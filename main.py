import threading
import asyncio
import traceback
import collections
import hashlib
import secrets
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import aiosqlite
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.api import AstrBotConfig
from astrbot.core.star.star_handler import star_handlers_registry, StarHandlerMetadata
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter

# 兼容不同版本的 AstrBot
try:
    from astrbot.core.star.star_tools import StarTools
    PLUGIN_DATA_DIR = StarTools.get_data_dir("permission_plugin")
except ImportError:
    from astrbot.core.utils.astrbot_path import get_astrbot_data_path
    PLUGIN_DATA_DIR = Path(get_astrbot_data_path()) / "plugin_data" / "permission_plugin"

PLUGIN_DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = PLUGIN_DATA_DIR / "permissions.db"

PLUGIN_DIR = Path(__file__).parent
TEMPLATES_DIR = PLUGIN_DIR / "templates"

PERMISSION_LEVELS = {
    "default": 0,
    "member": 1,
    "moderator": 2,
    "admin": 3,
    "super_admin": 4
}
LEVEL_TO_NAME = {v: k for k, v in PERMISSION_LEVELS.items()}
NAME_TO_LEVEL = PERMISSION_LEVELS

# 登录失败记录
LOGIN_FAILS = {}
FAIL_LOCK_TIME = 300  # 锁定时间5分钟
MAX_FAILS = 5  # 最大失败次数

app = FastAPI()
# 同源访问，无需 CORS，已移除中间件
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# 标志位，避免重复添加中间件
_middleware_added = False


def get_password_hash(password: str, salt: str = None) -> Tuple[str, str]:
    """使用 pbkdf2_sha256 哈希密码，返回 (salt, hash)"""
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt, key.hex()


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    """验证密码，使用防时序攻击比较"""
    _, hash_ = get_password_hash(password, salt)
    return secrets.compare_digest(hash_, password_hash)


def is_admin(sender_id: str, admin_list: List[str]) -> bool:
    """判断是否为管理员（super_admin）"""
    return sender_id in admin_list


async def init_database():
    """初始化数据库表（异步）"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # 启用 WAL 模式，提高并发性能
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        
        # 用户权限表
        async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='permissions'") as cursor:
            table_exists = await cursor.fetchone()
        
        if table_exists:
            async with db.execute("PRAGMA table_info(permissions)") as cursor:
                columns = [col[1] for col in await cursor.fetchall()]
            if 'user_id' not in columns:
                await db.execute("DROP TABLE permissions")
                logger.warning("检测到 permissions 表结构异常，已删除重建")
                await db.execute('''
                    CREATE TABLE permissions (
                        user_id TEXT PRIMARY KEY,
                        level INTEGER NOT NULL DEFAULT 0
                    )
                ''')
        else:
            await db.execute('''
                CREATE TABLE permissions (
                    user_id TEXT PRIMARY KEY,
                    level INTEGER NOT NULL DEFAULT 0
                )
            ''')

        # 群组权限表
        async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='group_permissions'") as cursor:
            group_table_exists = await cursor.fetchone()
        if not group_table_exists:
            await db.execute('''
                CREATE TABLE group_permissions (
                    group_id TEXT PRIMARY KEY,
                    level INTEGER NOT NULL DEFAULT 0
                )
            ''')
            logger.info("已创建群组权限表")

        # 指令权限表
        async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='command_permissions'") as cursor:
            cmd_table_exists = await cursor.fetchone()
        if not cmd_table_exists:
            await db.execute('''
                CREATE TABLE command_permissions (
                    plugin_name TEXT NOT NULL,
                    command_name TEXT NOT NULL,
                    min_permission_level INTEGER NOT NULL,
                    PRIMARY KEY (plugin_name, command_name)
                )
            ''')

        # web_auth 表
        async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='web_auth'") as cursor:
            auth_table_exists = await cursor.fetchone()
        if not auth_table_exists:
            await db.execute('''
                CREATE TABLE web_auth (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_changed INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

        # settings 表
        async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'") as cursor:
            settings_table_exists = await cursor.fetchone()
        if not settings_table_exists:
            await db.execute('''
                CREATE TABLE settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')

        await db.commit()
    logger.info("权限数据库初始化完成")


async def init_auth(config: AstrBotConfig):
    """初始化认证信息"""
    username = config.get("web_username", "admin")
    password = config.get("web_password", "admin")

    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        
        async with db.execute("SELECT COUNT(*) FROM web_auth") as cursor:
            count = (await cursor.fetchone())[0]
        
        if count == 0:
            salt, pwd_hash = get_password_hash(password)
            # 标记为默认密码（未修改）
            await db.execute(
                "INSERT INTO web_auth (username, salt, password_hash, password_changed) VALUES (?, ?, ?, ?)",
                (username, salt, pwd_hash, 0)
            )
            await db.commit()
            logger.warning("已创建初始 WebUI 登录账户，请立即修改密码！")
        else:
            # 检查是否有默认密码未修改
            async with db.execute("SELECT password_changed FROM web_auth WHERE username=?", (username,)) as cursor:
                row = await cursor.fetchone()
                if row and row[0] == 0:
                    logger.warning("检测到默认密码未修改，请及时修改密码！")


async def get_or_create_secret_key() -> str:
    """获取或创建会话密钥"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        
        async with db.execute("SELECT value FROM settings WHERE key='session_secret'") as cursor:
            row = await cursor.fetchone()
        
        if row:
            key = row[0]
        else:
            key = secrets.token_hex(32)
            await db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ('session_secret', key))
            await db.commit()
            logger.info("生成了新的会话密钥")
    return key


def add_session_middleware(secret_key: str):
    """添加会话中间件（单例模式）"""
    global _middleware_added
    if not _middleware_added:
        app.add_middleware(
            SessionMiddleware,
            secret_key=secret_key,
            max_age=3600,
            https_only=False,  # 生产环境应设为 True
            same_site="lax",
            session_cookie="permission_session"
        )
        _middleware_added = True
        logger.info("会话中间件已添加")


@register("astrbot_plugin_permission", "Your Name", "权限管理插件", "1.0.0", "repo_url")
class PermissionManager(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        
        self.config = config
        admin_qq_str = config.get("admin_qq", "")
        self.admin_qq_list = [qq.strip() for qq in admin_qq_str.split(",") if qq.strip()]
        logger.info(f"管理员QQ列表: {self.admin_qq_list}")
        
        # 获取 Web 监听配置
        self.web_host = config.get("web_host", "127.0.0.1")  # 默认仅本地监听
        self.web_port = config.get("web_port", 5555)

        self.cmd_permissions: Dict[Tuple[str, str], int] = {}
        self.plugin_commands: Dict[str, List[str]] = {}
        self._cmd_permissions_loaded = False
        self._plugin_commands_loaded = False

        self.server = None
        self.server_thread = None
        self._refresh_task = None

        # 将实例存储到 app.state 中，供路由使用
        app.state.plugin_instance = self

        # 启动异步初始化
        self._init_task = asyncio.create_task(self._async_init())

    async def _async_init(self):
        """异步初始化方法"""
        try:
            # 初始化数据库
            await init_database()
            
            # 初始化认证
            await init_auth(self.config)
            
            # 加载数据
            await self.load_command_permissions()
            await self.build_command_map_stable()
            
            # 获取会话密钥并添加中间件
            secret_key = await get_or_create_secret_key()
            add_session_middleware(secret_key)
            
            # 启动定时刷新任务（每5分钟刷新一次指令映射）
            self._refresh_task = asyncio.create_task(self._periodic_refresh())
            
            # 启动 Web 服务器
            self.start_web_server()
            
            logger.info("插件异步初始化完成")
        except Exception as e:
            logger.error(f"插件异步初始化失败: {traceback.format_exc()}")

    async def _periodic_refresh(self):
        """定时刷新指令映射"""
        while True:
            try:
                await asyncio.sleep(300)  # 每5分钟刷新一次
                await self.build_command_map_stable()
                logger.debug("指令映射已自动刷新")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"定时刷新指令映射失败: {e}")

    async def terminate(self):
        """插件卸载时清理资源"""
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except:
                pass
        
        if self.server:
            logger.info("正在关闭 WebUI 服务器...")
            self.server.should_exit = True
            if self.server_thread and self.server_thread.is_alive():
                await asyncio.to_thread(self.server_thread.join, timeout=5)
            logger.info("WebUI 服务器已关闭")

    def _debug_registered_handlers(self):
        try:
            for handler in star_handlers_registry:
                if handler.handler_module_path == __file__:
                    logger.debug(f"本插件已注册处理器: {handler.handler_name}")
        except Exception:
            pass

    async def load_command_permissions(self):
        """从数据库加载指令权限配置"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            async with db.execute("SELECT plugin_name, command_name, min_permission_level FROM command_permissions") as cursor:
                rows = await cursor.fetchall()
        
        self.cmd_permissions = {(row[0], row[1]): row[2] for row in rows}
        self._cmd_permissions_loaded = True
        logger.info(f"已加载 {len(self.cmd_permissions)} 条指令权限配置")
        return self.cmd_permissions

    async def save_command_permissions(self, new_perms: Dict[Tuple[str, str], int]):
        """保存指令权限配置到数据库"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            await db.execute("BEGIN IMMEDIATE")  # 立即加锁，避免并发冲突
            await db.execute("DELETE FROM command_permissions")
            for (plugin, cmd), level in new_perms.items():
                await db.execute(
                    "INSERT INTO command_permissions (plugin_name, command_name, min_permission_level) VALUES (?, ?, ?)",
                    (plugin, cmd, level)
                )
            await db.commit()
        
        self.cmd_permissions = new_perms
        logger.info(f"已保存 {len(new_perms)} 条指令权限配置")

    async def build_command_map_stable(self):
        """稳定构建插件指令映射，基于全局处理器注册表"""
        try:
            all_stars = self.context.get_all_stars()
            all_stars = [star for star in all_stars if getattr(star, 'activated', True)]
            plugin_map = {}
            for star in all_stars:
                plugin_name = getattr(star, 'name', '未知插件')
                module_path = getattr(star, 'module_path', None)
                if not module_path:
                    logger.debug(f"插件 {plugin_name} 缺少 module_path，跳过")
                    continue
                plugin_map[module_path] = plugin_name

            cmd_collector = collections.defaultdict(set)
            for handler in star_handlers_registry:
                if not isinstance(handler, StarHandlerMetadata):
                    continue
                module_path = handler.handler_module_path
                plugin_name = plugin_map.get(module_path)
                if not plugin_name:
                    continue
                if plugin_name == "astrbot_plugin_permission":
                    continue
                for filter_ in handler.event_filters:
                    cmd = None
                    if isinstance(filter_, CommandFilter):
                        cmd = filter_.command_name
                    elif isinstance(filter_, CommandGroupFilter):
                        cmd = filter_.group_name
                    if cmd and isinstance(cmd, str):
                        cmd_collector[plugin_name].add(cmd)
            self.plugin_commands = {k: sorted(v) for k, v in cmd_collector.items()}
            self._plugin_commands_loaded = True
            logger.info(f"指令映射构建完成，共收集到 {len(self.plugin_commands)} 个插件的指令")
        except Exception as e:
            logger.error(f"构建指令映射时发生异常: {traceback.format_exc()}")
            self.plugin_commands = {}

    async def _get_user_level_from_db(self, user_id: str) -> int:
        """从数据库获取用户等级"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            async with db.execute("SELECT level FROM permissions WHERE user_id = ?", (user_id,)) as cursor:
                row = await cursor.fetchone()
            
            if row:
                return row[0]
            else:
                # 插入默认用户等级
                await db.execute(
                    "INSERT INTO permissions (user_id, level) VALUES (?, ?)",
                    (user_id, PERMISSION_LEVELS["default"])
                )
                await db.commit()
                return PERMISSION_LEVELS["default"]

    async def _get_group_level_from_db(self, group_id: str) -> int:
        """从数据库获取群组等级"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            async with db.execute("SELECT level FROM group_permissions WHERE group_id = ?", (group_id,)) as cursor:
                row = await cursor.fetchone()
            
            if row:
                return row[0]
            return PERMISSION_LEVELS["default"]

    async def get_effective_level(self, user_id: str, group_id: Optional[str] = None) -> int:
        """
        获取用户的有效权限等级：
        - 如果用户是管理员（super_admin），直接返回 super_admin
        - 否则取用户等级和群组等级的最大值
        """
        if user_id in self.admin_qq_list:
            return PERMISSION_LEVELS["super_admin"]

        # 并发获取用户和群组等级
        user_level_task = self._get_user_level_from_db(user_id)
        group_level_task = self._get_group_level_from_db(group_id) if group_id else None
        
        user_level = await user_level_task
        group_level = await group_level_task if group_level_task else PERMISSION_LEVELS["default"]
        
        return max(user_level, group_level)

    # ---------- 刷新指令映射指令 ----------
    @filter.command("刷新权限映射")
    async def refresh_perm_map(self, event: AstrMessageEvent):
        """手动刷新指令权限映射"""
        sender_id = event.get_sender_id()
        if not is_admin(sender_id, self.admin_qq_list):
            yield event.plain_result("您没有权限执行此操作。")
            return
        
        await self.build_command_map_stable()
        yield event.plain_result(f"指令映射已刷新，共 {len(self.plugin_commands)} 个插件。")

    # ---------- 授权指令 ----------
    @filter.command("授权")
    async def set_permission(self, event: AstrMessageEvent, scope: str, target_id: str, level_str: str):
        """授权指令格式：/授权 [群组/私聊] [QQ号/群号] [等级名或数值]"""
        # 检查发送者是否为管理员
        sender_id = event.get_sender_id()
        if not is_admin(sender_id, self.admin_qq_list):
            yield event.plain_result("您没有权限使用授权指令。")
            return

        # 解析作用域
        scope = scope.strip()
        if scope not in ["群组", "私聊"]:
            yield event.plain_result("作用域必须是 '群组' 或 '私聊'。")
            return

        # 解析等级
        try:
            # 尝试直接解析为数值
            level = int(level_str)
            if level not in PERMISSION_LEVELS.values():
                yield event.plain_result(f"无效的等级数值，可用等级: {', '.join(PERMISSION_LEVELS.keys())}")
                return
        except ValueError:
            # 尝试按名称解析
            level_name = level_str.lower()
            if level_name not in NAME_TO_LEVEL:
                yield event.plain_result(f"无效的等级名称，可用等级: {', '.join(PERMISSION_LEVELS.keys())}")
                return
            level = NAME_TO_LEVEL[level_name]

        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            await db.execute("BEGIN IMMEDIATE")
            if scope == "私聊":
                # 设置用户等级
                await db.execute(
                    "INSERT OR REPLACE INTO permissions (user_id, level) VALUES (?, ?)",
                    (target_id, level)
                )
                await db.commit()
                yield event.plain_result(f"已为用户 {target_id} 设置权限等级为 {LEVEL_TO_NAME[level]} ({level})。")
            else:  # 群组
                # 设置群组等级
                await db.execute(
                    "INSERT OR REPLACE INTO group_permissions (group_id, level) VALUES (?, ?)",
                    (target_id, level)
                )
                await db.commit()
                yield event.plain_result(f"已为群组 {target_id} 设置权限等级为 {LEVEL_TO_NAME[level]} ({level})。")

    @filter.command("取消授权")
    async def remove_permission(self, event: AstrMessageEvent, scope: str, target_id: str):
        """取消授权指令格式：/取消授权 [群组/私聊] [QQ号/群号]"""
        sender_id = event.get_sender_id()
        if not is_admin(sender_id, self.admin_qq_list):
            yield event.plain_result("您没有权限使用取消授权指令。")
            return

        scope = scope.strip()
        if scope not in ["群组", "私聊"]:
            yield event.plain_result("作用域必须是 '群组' 或 '私聊'。")
            return

        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            await db.execute("BEGIN IMMEDIATE")
            if scope == "私聊":
                await db.execute("DELETE FROM permissions WHERE user_id = ?", (target_id,))
                await db.commit()
                affected = db.total_changes
                if affected:
                    yield event.plain_result(f"已取消用户 {target_id} 的权限设置，恢复为默认等级。")
                else:
                    yield event.plain_result(f"用户 {target_id} 没有权限设置。")
            else:  # 群组
                await db.execute("DELETE FROM group_permissions WHERE group_id = ?", (target_id,))
                await db.commit()
                affected = db.total_changes
                if affected:
                    yield event.plain_result(f"已取消群组 {target_id} 的权限设置，恢复为默认等级。")
                else:
                    yield event.plain_result(f"群组 {target_id} 没有权限设置。")

    @filter.command("权限帮助")
    async def perm_help(self, event: AstrMessageEvent):
        """查看权限管理指令帮助"""
        help_text = (
            "权限管理指令：\n"
            "/授权 [群组/私聊] [QQ号/群号] [等级名或数值] - 设置权限等级\n"
            "/取消授权 [群组/私聊] [QQ号/群号] - 取消权限设置\n"
            "/刷新权限映射 - 手动刷新指令映射\n"
            "可用等级: default(0), member(1), moderator(2), admin(3), super_admin(4)\n"
            "注：管理员自动拥有 super_admin 权限，无需设置。"
        )
        yield event.plain_result(help_text)

    @filter.command("权限列表")
    async def perm_list(self, event: AstrMessageEvent, target: Optional[str] = None):
        """查看权限列表，可选指定用户或群组"""
        sender_id = event.get_sender_id()
        if not is_admin(sender_id, self.admin_qq_list):
            yield event.plain_result("您没有权限查看权限列表。")
            return

        msg = ""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            if target is None:
                # 显示所有用户和群组
                async with db.execute("SELECT user_id, level FROM permissions") as cursor:
                    users = await cursor.fetchall()
                async with db.execute("SELECT group_id, level FROM group_permissions") as cursor:
                    groups = await cursor.fetchall()
                
                msg += "用户权限设置：\n"
                for uid, lvl in users:
                    msg += f"  {uid}: {LEVEL_TO_NAME[lvl]} ({lvl})\n"
                msg += "群组权限设置：\n"
                for gid, lvl in groups:
                    msg += f"  {gid}: {LEVEL_TO_NAME[lvl]} ({lvl})\n"
            else:
                # 尝试按用户或群组查询
                async with db.execute("SELECT level FROM permissions WHERE user_id = ?", (target,)) as cursor:
                    user_row = await cursor.fetchone()
                if user_row:
                    msg += f"用户 {target} 权限等级: {LEVEL_TO_NAME[user_row[0]]} ({user_row[0]})\n"
                
                async with db.execute("SELECT level FROM group_permissions WHERE group_id = ?", (target,)) as cursor:
                    group_row = await cursor.fetchone()
                if group_row:
                    msg += f"群组 {target} 权限等级: {LEVEL_TO_NAME[group_row[0]]} ({group_row[0]})\n"
                
                if not msg:
                    msg = f"未找到 {target} 的权限设置。"

        yield event.plain_result(msg if msg else "暂无权限设置。")

    # ---------- 权限检查拦截器（使用合并等级） ----------
    @filter.event_message_type(filter.EventMessageType.ALL, priority=999)
    async def permission_check(self, event: AstrMessageEvent):
        """权限检查拦截器"""
        try:
            if not self._plugin_commands_loaded or not self.plugin_commands:
                return

            sender_id = event.get_sender_id()
            if not sender_id:
                return

            # 获取群组ID（如果有）
            group_id = event.get_group_id() if hasattr(event, 'get_group_id') else None

            # 使用 event.get_command() 获取纯净指令词（不带前缀）
            command = event.get_command()
            if not command:
                return

            target_plugin = None
            for plugin, cmds in self.plugin_commands.items():
                if command in cmds:
                    target_plugin = plugin
                    break

            if not target_plugin:
                return

            required_level = self.cmd_permissions.get((target_plugin, command), PERMISSION_LEVELS["default"])
            
            # 异步获取有效等级
            effective_level = await self.get_effective_level(sender_id, group_id)
            
            logger.debug(f"权限检查：指令 /{command} 要求等级 {required_level}，用户 {sender_id} 有效等级 {effective_level}")

            if effective_level < required_level:
                level_name = LEVEL_TO_NAME.get(required_level, str(required_level))
                logger.info(f"权限不足：用户 {sender_id} 使用 /{command} 被拒绝")
                await event.send(event.plain_result(
                    f"您没有权限使用 {target_plugin} 插件的指令 /{command}，需要等级 {level_name}。"
                ))
                event.stop_event()
                return
        except Exception as e:
            logger.error(f"权限检查过程中发生异常: {traceback.format_exc()}")

    def start_web_server(self):
        """启动 Web 服务器"""
        config = uvicorn.Config(
            app,
            host=self.web_host,
            port=self.web_port,
            log_level="info",
            loop="asyncio"
        )
        self.server = uvicorn.Server(config)

        def run_server():
            asyncio.set_event_loop(asyncio.new_event_loop())
            self.server.run()

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        logger.info(f"权限管理 WebUI 已启动在 http://{self.web_host}:{self.web_port}")


# ---------- 登录防爆破 ----------
def check_login_fails(ip: str, username: str) -> bool:
    """检查登录失败次数，返回是否允许尝试"""
    key = f"{ip}:{username}"
    now = time.time()
    
    # 清理过期记录
    for k in list(LOGIN_FAILS.keys()):
        if now - LOGIN_FAILS[k]["first_fail"] > FAIL_LOCK_TIME:
            del LOGIN_FAILS[k]
    
    if key in LOGIN_FAILS:
        record = LOGIN_FAILS[key]
        if record["count"] >= MAX_FAILS:
            if now - record["first_fail"] < FAIL_LOCK_TIME:
                return False
            else:
                # 超过锁定时间，重置
                del LOGIN_FAILS[key]
                return True
    return True


def record_login_fail(ip: str, username: str):
    """记录登录失败"""
    key = f"{ip}:{username}"
    now = time.time()
    
    if key in LOGIN_FAILS:
        LOGIN_FAILS[key]["count"] += 1
    else:
        LOGIN_FAILS[key] = {"count": 1, "first_fail": now}


def clear_login_fails(ip: str, username: str):
    """清除登录失败记录"""
    key = f"{ip}:{username}"
    if key in LOGIN_FAILS:
        del LOGIN_FAILS[key]


# ---------- 登录依赖项 ----------
async def require_auth(request: Request):
    """依赖项：检查用户是否已登录"""
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return True


# ---------- FastAPI 路由 ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    """显示登录页面"""
    # 检查是否需要强制修改密码
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("PRAGMA busy_timeout=5000")
        async with db.execute("SELECT password_changed FROM web_auth WHERE username=?", 
                              (request.session.get("username", "admin"),)) as cursor:
            row = await cursor.fetchone()
            need_change = row and row[0] == 0
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "need_change": need_change
    })


@app.post("/login")
async def login(request: Request, 
                username: str = Form(...), 
                password: str = Form(...),
                new_password: str = Form(None),
                confirm_password: str = Form(None)):
    """处理登录表单"""
    client_ip = request.client.host
    
    # 检查登录失败次数
    if not check_login_fails(client_ip, username):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"登录失败次数过多，请{FAIL_LOCK_TIME//60}分钟后再试"
        }, status_code=400)

    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("PRAGMA busy_timeout=5000")
        async with db.execute(
            "SELECT username, salt, password_hash, password_changed FROM web_auth WHERE username=?", 
            (username,)
        ) as cursor:
            row = await cursor.fetchone()

    if not row or not verify_password(password, row[1], row[2]):
        record_login_fail(client_ip, username)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "用户名或密码错误"
        }, status_code=400)

    # 检查是否需要修改密码
    if row[3] == 0:
        # 默认密码，需要修改
        if not new_password or not confirm_password:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "请填写新密码和确认密码",
                "need_change": True,
                "username": username
            })
        
        if new_password != confirm_password:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "两次输入的密码不一致",
                "need_change": True,
                "username": username
            })
        
        if len(new_password) < 6:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "密码长度至少为6位",
                "need_change": True,
                "username": username
            })
        
        # 修改密码
        salt, pwd_hash = get_password_hash(new_password)
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            await db.execute(
                "UPDATE web_auth SET salt=?, password_hash=?, password_changed=1 WHERE username=?",
                (salt, pwd_hash, username)
            )
            await db.commit()
        logger.info(f"用户 {username} 已修改默认密码")

    # 登录成功
    clear_login_fails(client_ip, username)
    request.session["authenticated"] = True
    request.session["username"] = username
    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    """登出"""
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def home(request: Request):
    """显示权限配置主页（需要登录）"""
    try:
        plugin = app.state.plugin_instance
        if plugin is None:
            return HTMLResponse("<h1>500 Internal Server Error</h1><p>插件实例未初始化</p>", status_code=500)

        await plugin.load_command_permissions()

        plugin_data = []
        for plugin_name, commands in plugin.plugin_commands.items():
            cmd_list = []
            for cmd in commands:
                level = plugin.cmd_permissions.get((plugin_name, cmd), PERMISSION_LEVELS["default"])
                cmd_list.append({
                    "name": cmd,
                    "level": level
                })
            plugin_data.append({
                "name": plugin_name,
                "commands": cmd_list
            })

        return templates.TemplateResponse("index.html", {
            "request": request,
            "plugin_data": plugin_data,
            "PERMISSION_LEVELS": PERMISSION_LEVELS,
            "username": request.session.get("username")
        })
    except Exception as e:
        logger.error(f"处理 / 路由时发生异常: {traceback.format_exc()}")
        return HTMLResponse(f"<h1>500 Internal Server Error</h1><pre>{traceback.format_exc()}</pre>", status_code=500)


@app.post("/save_permissions", dependencies=[Depends(require_auth)])
async def save_permissions_post(request: Request):
    """保存权限配置（需要登录）"""
    logger.info("收到保存权限请求")
    try:
        plugin = app.state.plugin_instance
        if plugin is None:
            logger.error("插件实例为 None")
            return RedirectResponse(url="/", status_code=303)

        # 使用 JSON 格式提交，避免字符串解析问题
        data = await request.json()
        logger.debug(f"表单数据: {data}")
        
        new_perms = {}
        for item in data.get("permissions", []):
            plugin_name = item.get("plugin")
            command = item.get("command")
            level = item.get("level")
            
            if not plugin_name or not command or level is None:
                continue
            
            try:
                level = int(level)
                if level in PERMISSION_LEVELS.values():
                    new_perms[(plugin_name, command)] = level
                else:
                    logger.warning(f"无效权限等级 {level} 用于 {plugin_name}.{command}")
            except ValueError:
                logger.warning(f"无法解析权限等级: {level}")

        await plugin.save_command_permissions(new_perms)
        return JSONResponse({"status": "success"})
    except Exception as e:
        logger.error(f"保存权限时发生异常: {traceback.format_exc()}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.get("/save_permissions", dependencies=[Depends(require_auth)])
async def save_permissions_get():
    return PlainTextResponse("请使用 POST 方法提交表单", status_code=405)