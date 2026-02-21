import threading
import asyncio
import traceback
import collections
import hashlib
import secrets
import string
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
IP_LOGIN_FAILS = {}
FAIL_LOCK_TIME = 300  # 锁定时间5分钟
MAX_FAILS = 5  # 最大失败次数

app = FastAPI()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

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


def add_session_middleware(secret_key: str):
    """添加会话中间件（单例模式）"""
    global _middleware_added
    if not _middleware_added:
        app.add_middleware(
            SessionMiddleware,
            secret_key=secret_key,
            max_age=3600,
            https_only=False,  # 生产环境可设为 True
            same_site="lax",
            session_cookie="permission_session"
        )
        _middleware_added = True
        logger.info("会话中间件已添加")


async def verify_csrf(request: Request):
    """验证CSRF token"""
    if request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        session_token = request.session.get("csrf_token")
        if not token or not session_token or not secrets.compare_digest(token, session_token):
            raise HTTPException(status_code=403, detail="CSRF token invalid")
    return True


@register("astrbot_plugin_permission", "Your Name", "权限管理插件", "1.0.0", "repo_url")
class PermissionManager(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        
        self.config = config
        admin_qq_str = config.get("admin_qq", "")
        self.admin_qq_list = [qq.strip() for qq in admin_qq_str.split(",") if qq.strip()]
        logger.info(f"管理员QQ列表: {self.admin_qq_list}")
        
        self.web_host = config.get("web_host", "127.0.0.1")
        self.web_port = config.get("web_port", 5555)

        self.cmd_permissions: Dict[Tuple[str, str], int] = {}
        self.plugin_commands: Dict[str, List[str]] = {}
        self._cmd_permissions_loaded = False
        self._plugin_commands_loaded = False

        self.server = None
        self.server_thread = None
        self._refresh_task = None

        app.state.plugin_instance = self

        try:
            self._init_task = asyncio.create_task(self._async_init())
        except RuntimeError:
            logger.warning("无运行中事件循环，初始化任务将在首次权限检查时执行")
            self._init_task = None
            self._need_init = True
        else:
            self._need_init = False

    async def _async_init(self):
        """异步初始化方法"""
        try:
            await self._init_database()
            await self._init_auth()
            await self.load_command_permissions()
            await self.build_command_map_stable()
            
            secret_key = await self._get_or_create_secret_key()
            add_session_middleware(secret_key)
            
            self._refresh_task = asyncio.create_task(self._periodic_refresh())
            self.start_web_server()
            
            logger.info("插件异步初始化完成")
        except Exception as e:
            logger.error(f"插件异步初始化失败: {traceback.format_exc()}")

    async def _periodic_refresh(self):
        """定时刷新指令映射"""
        while True:
            try:
                await asyncio.sleep(300)
                await self.build_command_map_stable()
                logger.debug("指令映射已自动刷新")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"定时刷新指令映射失败: {e}")

    async def terminate(self):
        try:
            if self._refresh_task:
                self._refresh_task.cancel()
                try:
                    await self._refresh_task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.warning(f"取消定时任务时异常: {e}")
        except Exception as e:
            logger.warning(f"终止插件时异常: {e}")
        
        try:
            if self.server:
                logger.info("正在关闭 WebUI 服务器...")
                self.server.should_exit = True
                if self.server_thread and self.server_thread.is_alive():
                    await asyncio.to_thread(self.server_thread.join, timeout=5)
                logger.info("WebUI 服务器已关闭")
        except Exception as e:
            logger.warning(f"关闭服务器时异常: {e}")

    async def _init_database(self):
        """初始化数据库表（含结构更新）"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA busy_timeout=5000")
            
            # 用户权限表
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='permissions'") as cursor:
                table_exists = await cursor.fetchone()
            if not table_exists:
                await db.execute('''
                    CREATE TABLE permissions (
                        user_id TEXT PRIMARY KEY,
                        level INTEGER NOT NULL DEFAULT 0
                    )
                ''')
            else:
                async with db.execute("PRAGMA table_info(permissions)") as cursor:
                    columns = [col[1] for col in await cursor.fetchall()]
                if 'user_id' not in columns:
                    await db.execute("DROP TABLE permissions")
                    await db.execute('''
                        CREATE TABLE permissions (
                            user_id TEXT PRIMARY KEY,
                            level INTEGER NOT NULL DEFAULT 0
                        )
                    ''')

            # 群组权限表
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='group_permissions'") as cursor:
                if not await cursor.fetchone():
                    await db.execute('''
                        CREATE TABLE group_permissions (
                            group_id TEXT PRIMARY KEY,
                            level INTEGER NOT NULL DEFAULT 0
                        )
                    ''')

            # 指令权限表
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='command_permissions'") as cursor:
                if not await cursor.fetchone():
                    await db.execute('''
                        CREATE TABLE command_permissions (
                            plugin_name TEXT NOT NULL,
                            command_name TEXT NOT NULL,
                            min_permission_level INTEGER NOT NULL,
                            PRIMARY KEY (plugin_name, command_name)
                        )
                    ''')

            # web_auth 表（含列检查）
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='web_auth'") as cursor:
                table_exists = await cursor.fetchone()
            if not table_exists:
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
                logger.info("已创建 web_auth 表")
            else:
                # 检查是否有 password_changed 列
                async with db.execute("PRAGMA table_info(web_auth)") as cursor:
                    columns = [col[1] for col in await cursor.fetchall()]
                if 'password_changed' not in columns:
                    await db.execute("ALTER TABLE web_auth ADD COLUMN password_changed INTEGER NOT NULL DEFAULT 0")
                    logger.info("已添加 password_changed 列到 web_auth 表")

            # settings 表
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'") as cursor:
                if not await cursor.fetchone():
                    await db.execute('''
                        CREATE TABLE settings (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        )
                    ''')

            await db.commit()
        logger.info("权限数据库初始化完成")

    async def _init_auth(self):
        """初始化认证信息，并同步配置密码"""
        username = self.config.get("web_username", "admin")
        config_password = self.config.get("web_password", None)

        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            
            async with db.execute("SELECT COUNT(*) FROM web_auth") as cursor:
                count = (await cursor.fetchone())[0]
            
            if count == 0:
                # 首次启动，生成随机密码
                alphabet = string.ascii_letters + string.digits
                random_password = ''.join(secrets.choice(alphabet) for _ in range(16))
                salt, pwd_hash = get_password_hash(random_password)
                await db.execute(
                    "INSERT INTO web_auth (username, salt, password_hash, password_changed) VALUES (?, ?, ?, ?)",
                    (username, salt, pwd_hash, 0)
                )
                await db.commit()
                # 将随机密码写回配置，并保存
                self.config['web_password'] = random_password
                self.config.save_config()
                logger.warning(f"已创建初始 WebUI 登录账户，用户名：{username}，初始密码：{random_password}（请在插件配置中查看并修改）")
            else:
                # 已有用户，检查配置密码是否与数据库一致
                async with db.execute(
                    "SELECT salt, password_hash, password_changed FROM web_auth WHERE username=?",
                    (username,)
                ) as cursor:
                    row = await cursor.fetchone()
                if row:
                    salt, db_hash, changed = row
                    if config_password and not verify_password(config_password, salt, db_hash):
                        # 不匹配，说明用户修改了配置中的密码，更新数据库
                        logger.info("检测到配置密码变更，更新数据库密码哈希")
                        new_salt, new_hash = get_password_hash(config_password)
                        await db.execute(
                            "UPDATE web_auth SET salt=?, password_hash=?, password_changed=1 WHERE username=?",
                            (new_salt, new_hash, username)
                        )
                        await db.commit()
                    else:
                        if changed == 0 and config_password:
                            logger.warning("检测到默认密码未修改，请及时修改密码！")

    async def _get_or_create_secret_key(self) -> str:
        async with aiosqlite.connect(DATABASE_PATH) as db:
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

    async def load_command_permissions(self):
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            async with db.execute("SELECT plugin_name, command_name, min_permission_level FROM command_permissions") as cursor:
                rows = await cursor.fetchall()
        self.cmd_permissions = {(row[0], row[1]): row[2] for row in rows}
        self._cmd_permissions_loaded = True
        logger.info(f"已加载 {len(self.cmd_permissions)} 条指令权限配置")

    async def save_command_permissions(self, new_perms: Dict[Tuple[str, str], int]):
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            await db.execute("BEGIN IMMEDIATE")
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
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            async with db.execute("SELECT level FROM permissions WHERE user_id = ?", (user_id,)) as cursor:
                row = await cursor.fetchone()
            if row:
                return row[0]
            else:
                await db.execute("INSERT INTO permissions (user_id, level) VALUES (?, ?)", (user_id, PERMISSION_LEVELS["default"]))
                await db.commit()
                return PERMISSION_LEVELS["default"]

    async def _get_group_level_from_db(self, group_id: str) -> int:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            async with db.execute("SELECT level FROM group_permissions WHERE group_id = ?", (group_id,)) as cursor:
                row = await cursor.fetchone()
            return row[0] if row else PERMISSION_LEVELS["default"]

    async def get_effective_level(self, user_id: str, group_id: Optional[str] = None) -> int:
        if user_id in self.admin_qq_list:
            return PERMISSION_LEVELS["super_admin"]
        user_level_task = self._get_user_level_from_db(user_id)
        group_level_task = self._get_group_level_from_db(group_id) if group_id else None
        user_level = await user_level_task
        group_level = await group_level_task if group_level_task else PERMISSION_LEVELS["default"]
        return max(user_level, group_level)

    @filter.command("刷新权限映射")
    async def refresh_perm_map(self, event: AstrMessageEvent):
        sender_id = event.get_sender_id()
        if not is_admin(sender_id, self.admin_qq_list):
            yield event.plain_result("您没有权限执行此操作。")
            return
        await self.build_command_map_stable()
        yield event.plain_result(f"指令映射已刷新，共 {len(self.plugin_commands)} 个插件。")

    @filter.command("授权")
    async def set_permission(self, event: AstrMessageEvent, scope: str, target_id: str, level_str: str):
        sender_id = event.get_sender_id()
        if not is_admin(sender_id, self.admin_qq_list):
            yield event.plain_result("您没有权限使用授权指令。")
            return
        scope = scope.strip()
        if scope not in ["群组", "私聊"]:
            yield event.plain_result("作用域必须是 '群组' 或 '私聊'。")
            return
        try:
            level = int(level_str)
            if level not in PERMISSION_LEVELS.values():
                yield event.plain_result(f"无效的等级数值，可用等级: {', '.join(PERMISSION_LEVELS.keys())}")
                return
        except ValueError:
            level_name = level_str.lower()
            if level_name not in NAME_TO_LEVEL:
                yield event.plain_result(f"无效的等级名称，可用等级: {', '.join(PERMISSION_LEVELS.keys())}")
                return
            level = NAME_TO_LEVEL[level_name]
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            await db.execute("BEGIN IMMEDIATE")
            if scope == "私聊":
                await db.execute("INSERT OR REPLACE INTO permissions (user_id, level) VALUES (?, ?)", (target_id, level))
                await db.commit()
                yield event.plain_result(f"已为用户 {target_id} 设置权限等级为 {LEVEL_TO_NAME[level]} ({level})。")
            else:
                await db.execute("INSERT OR REPLACE INTO group_permissions (group_id, level) VALUES (?, ?)", (target_id, level))
                await db.commit()
                yield event.plain_result(f"已为群组 {target_id} 设置权限等级为 {LEVEL_TO_NAME[level]} ({level})。")

    @filter.command("取消授权")
    async def remove_permission(self, event: AstrMessageEvent, scope: str, target_id: str):
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
                yield event.plain_result(f"已取消用户 {target_id} 的权限设置" if affected else f"用户 {target_id} 没有权限设置")
            else:
                await db.execute("DELETE FROM group_permissions WHERE group_id = ?", (target_id,))
                await db.commit()
                affected = db.total_changes
                yield event.plain_result(f"已取消群组 {target_id} 的权限设置" if affected else f"群组 {target_id} 没有权限设置")

    @filter.command("权限帮助")
    async def perm_help(self, event: AstrMessageEvent):
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
        sender_id = event.get_sender_id()
        if not is_admin(sender_id, self.admin_qq_list):
            yield event.plain_result("您没有权限查看权限列表。")
            return
        msg = ""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            if target is None:
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

    @filter.event_message_type(filter.EventMessageType.ALL, priority=999)
    async def permission_check(self, event: AstrMessageEvent):
        if getattr(self, '_need_init', False):
            self._need_init = False
            asyncio.create_task(self._async_init())
            return
        try:
            if not self._plugin_commands_loaded or not self.plugin_commands:
                return

            sender_id = event.get_sender_id()
            if not sender_id:
                return

            # 获取群组ID（兼容不同版本）
            group_id = None
            if hasattr(event, 'get_group_id'):
                group_id = event.get_group_id()
            else:
                group_id = getattr(event.message_obj, 'group_id', None) if hasattr(event, 'message_obj') else None

            # 手动提取指令词（兼容所有版本）
            text = event.message_str.strip()
            if not text.startswith('/'):
                return
            parts = text.split()
            command = parts[0].lstrip('/')

            target_plugin = None
            for plugin, cmds in self.plugin_commands.items():
                if command in cmds:
                    target_plugin = plugin
                    break

            if not target_plugin:
                return

            required_level = self.cmd_permissions.get((target_plugin, command), PERMISSION_LEVELS["default"])
            effective_level = await self.get_effective_level(sender_id, group_id)
            logger.debug(f"权限检查：指令 /{command} 要求等级 {required_level}，用户 {sender_id} 有效等级 {effective_level}")

            if effective_level < required_level:
                level_name = LEVEL_TO_NAME.get(required_level, str(required_level))
                logger.info(f"权限不足：用户 {sender_id} 使用 /{command} 被拒绝")
                await event.send(event.plain_result(
                    f"您没有权限使用 {target_plugin} 插件的指令 /{command}，需要等级 {level_name}。"
                ))
                event.stop_event()
        except Exception as e:
            logger.error(f"权限检查过程中发生异常: {traceback.format_exc()}")

    def start_web_server(self):
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
    now = time.time()
    for records in [LOGIN_FAILS, IP_LOGIN_FAILS]:
        for k in list(records.keys()):
            if now - records[k]["first_fail"] > FAIL_LOCK_TIME:
                del records[k]
    user_key = f"{ip}:{username}"
    if user_key in LOGIN_FAILS and LOGIN_FAILS[user_key]["count"] >= MAX_FAILS:
        return False
    if ip in IP_LOGIN_FAILS and IP_LOGIN_FAILS[ip]["count"] >= MAX_FAILS * 2:
        return False
    return True


def record_login_fail(ip: str, username: str):
    user_key = f"{ip}:{username}"
    now = time.time()
    if user_key in LOGIN_FAILS:
        LOGIN_FAILS[user_key]["count"] += 1
    else:
        LOGIN_FAILS[user_key] = {"count": 1, "first_fail": now}
    if ip in IP_LOGIN_FAILS:
        IP_LOGIN_FAILS[ip]["count"] += 1
    else:
        IP_LOGIN_FAILS[ip] = {"count": 1, "first_fail": now}


def clear_login_fails(ip: str, username: str):
    user_key = f"{ip}:{username}"
    LOGIN_FAILS.pop(user_key, None)


async def require_auth(request: Request):
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return True


# ---------- FastAPI 路由 ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login(request: Request, 
                username: str = Form(...), 
                password: str = Form(...),
                new_password: str = Form(None),
                confirm_password: str = Form(None)):
    client_ip = request.client.host
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

    # 检查是否需要修改密码（默认密码且未修改过）
    if row[3] == 0:
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

    clear_login_fails(client_ip, username)
    request.session["authenticated"] = True
    request.session["username"] = username
    request.session["csrf_token"] = secrets.token_hex(16)
    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def home(request: Request):
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
            "username": request.session.get("username"),
            "csrf_token": request.session.get("csrf_token", "")
        })
    except Exception as e:
        logger.error(f"处理 / 路由时发生异常: {traceback.format_exc()}")
        return HTMLResponse("<h1>500 Internal Server Error</h1><p>服务器内部错误，请查看日志</p>", status_code=500)


@app.post("/save_permissions", dependencies=[Depends(require_auth), Depends(verify_csrf)])
async def save_permissions_post(request: Request):
    logger.info("收到保存权限请求")
    try:
        plugin = app.state.plugin_instance
        if plugin is None:
            return JSONResponse({"status": "error", "message": "插件未初始化"}, status_code=500)

        data = await request.json()
        new_perms = {}
        valid_commands = plugin.plugin_commands

        for item in data.get("permissions", []):
            plugin_name = item.get("plugin")
            command = item.get("command")
            level = item.get("level")
            if not plugin_name or not command or level is None:
                continue
            if plugin_name not in valid_commands:
                logger.warning(f"跳过不存在的插件 {plugin_name}")
                continue
            if command not in valid_commands[plugin_name]:
                logger.warning(f"插件 {plugin_name} 不存在指令 {command}")
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
        return JSONResponse({"status": "error", "message": "保存失败"}, status_code=500)


@app.get("/save_permissions", dependencies=[Depends(require_auth), Depends(verify_csrf)])
async def save_permissions_get():
    return PlainTextResponse("请使用 POST 方法提交表单", status_code=405)