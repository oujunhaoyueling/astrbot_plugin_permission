import os
import threading
import asyncio
import traceback
import collections
import hashlib
import secrets
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

import aiosqlite
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.api import AstrBotConfig
from astrbot.core.utils.astrbot_path import get_astrbot_data_path
from astrbot.core.star.star_handler import star_handlers_registry, StarHandlerMetadata
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter

PERMISSION_LEVELS = {
    "default": 0,
    "member": 1,
    "moderator": 2,
    "admin": 3,
    "super_admin": 4
}
LEVEL_TO_NAME = {v: k for k, v in PERMISSION_LEVELS.items()}
NAME_TO_LEVEL = PERMISSION_LEVELS

PLUGIN_DATA_DIR = Path(get_astrbot_data_path()) / "plugin_data" / "permission_plugin"
PLUGIN_DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = PLUGIN_DATA_DIR / "permissions.db"

PLUGIN_DIR = Path(__file__).parent
TEMPLATES_DIR = PLUGIN_DIR / "templates"

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


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


@register("astrbot_plugin_permission", "Your Name", "权限管理插件", "1.0.0", "repo_url")
class PermissionManager(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        
        # 将实例存储到 app.state 中，供路由使用
        app.state.plugin_instance = self
        
        self.config = config
        admin_qq_str = config.get("admin_qq", "")
        self.admin_qq_list = [qq.strip() for qq in admin_qq_str.split(",") if qq.strip()]
        logger.info(f"管理员QQ列表: {self.admin_qq_list}")

        self.cmd_permissions: Dict[Tuple[str, str], int] = {}
        self.plugin_commands: Dict[str, List[str]] = {}
        self._cmd_permissions_loaded = False
        self._plugin_commands_loaded = False

        self.server = None
        self.server_thread = None

        # 初始化事件循环
        self.loop = asyncio.get_event_loop()

        # 初始化数据库（同步，仅在启动时运行）
        self.loop.run_until_complete(self.init_database())
        self.loop.run_until_complete(self.init_auth())
        self.loop.run_until_complete(self.load_command_permissions())
        self.loop.run_until_complete(self.build_command_map_stable())

        # 设置 Session 密钥
        secret_key = self.loop.run_until_complete(self.get_or_create_secret_key())
        app.add_middleware(SessionMiddleware, secret_key=secret_key, max_age=3600)

        self.start_web_server()
        self._debug_registered_handlers()

    def _debug_registered_handlers(self):
        try:
            for handler in star_handlers_registry:
                if handler.handler_module_path == __file__:
                    logger.debug(f"本插件已注册处理器: {handler.handler_name}")
        except Exception:
            pass

    async def _execute_db(self, callback, *args, **kwargs):
        """在线程池中执行同步数据库操作（备用，主要使用 aiosqlite）"""
        # 注意：此方法保留用于兼容，新代码应直接使用 aiosqlite
        return await asyncio.to_thread(callback, *args, **kwargs)

    async def init_database(self):
        """初始化数据库表（异步）"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
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

    async def init_auth(self):
        """初始化认证信息"""
        username = self.config.get("web_username", "admin")
        password = self.config.get("web_password", "admin")

        async with aiosqlite.connect(DATABASE_PATH) as db:
            async with db.execute("SELECT COUNT(*) FROM web_auth") as cursor:
                count = (await cursor.fetchone())[0]
            
            if count == 0:
                salt, pwd_hash = get_password_hash(password)
                await db.execute(
                    "INSERT INTO web_auth (username, salt, password_hash) VALUES (?, ?, ?)",
                    (username, salt, pwd_hash)
                )
                await db.commit()
                logger.info("已创建初始 WebUI 登录账户")

    async def get_or_create_secret_key(self) -> str:
        """获取或创建会话密钥"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
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
        """从数据库加载指令权限配置"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
            async with db.execute("SELECT plugin_name, command_name, min_permission_level FROM command_permissions") as cursor:
                rows = await cursor.fetchall()
        
        self.cmd_permissions = {(row[0], row[1]): row[2] for row in rows}
        self._cmd_permissions_loaded = True
        logger.info(f"已加载 {len(self.cmd_permissions)} 条指令权限配置")
        return self.cmd_permissions

    async def save_command_permissions(self, new_perms: Dict[Tuple[str, str], int]):
        """保存指令权限配置到数据库"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
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
            for p, cmds in self.plugin_commands.items():
                logger.debug(f"插件 {p} 指令: {cmds}")
        except Exception as e:
            logger.error(f"构建指令映射时发生异常: {traceback.format_exc()}")
            self.plugin_commands = {}

    async def _get_user_level_from_db(self, user_id: str) -> int:
        """从数据库获取用户等级"""
        async with aiosqlite.connect(DATABASE_PATH) as db:
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
        logger.debug("权限检查函数被调用")
        try:
            if not self._plugin_commands_loaded or not self.plugin_commands:
                logger.debug("权限检查：plugin_commands 未加载或为空，放行")
                return

            sender_id = event.get_sender_id()
            if not sender_id:
                logger.debug("权限检查：无法获取发送者ID，放行")
                return

            # 获取群组ID（如果有）
            group_id = event.get_group_id() if hasattr(event, 'get_group_id') else None

            # 使用 event.get_command() 获取纯净指令词（不带前缀）
            command = event.get_command()
            if not command:
                logger.debug("权限检查：无法获取指令词，放行")
                return

            logger.debug(f"权限检查：提取指令 '{command}'")

            target_plugin = None
            for plugin, cmds in self.plugin_commands.items():
                if command in cmds:
                    target_plugin = plugin
                    logger.debug(f"权限检查：指令 '{command}' 属于插件 '{plugin}'")
                    break

            if not target_plugin:
                logger.debug(f"权限检查：未找到指令 '{command}' 所属插件，放行")
                return

            required_level = self.cmd_permissions.get((target_plugin, command), PERMISSION_LEVELS["default"])
            
            # 异步获取有效等级
            effective_level = await self.get_effective_level(sender_id, group_id)
            
            logger.info(f"权限检查：指令 /{command} 要求等级 {required_level}，用户 {sender_id} 群组 {group_id} 有效等级 {effective_level}")

            if effective_level < required_level:
                level_name = LEVEL_TO_NAME.get(required_level, str(required_level))
                logger.info(f"权限不足：用户 {sender_id} 使用 /{command} 被拒绝")
                await event.send(event.plain_result(
                    f"您没有权限使用 {target_plugin} 插件的指令 /{command}，需要等级 {level_name}。"
                ))
                event.stop_event()
                logger.info("权限检查：已调用 stop_event，事件传播停止")
                return
            else:
                logger.debug("权限检查通过")
        except Exception as e:
            logger.error(f"权限检查过程中发生异常: {traceback.format_exc()}")

    def start_web_server(self):
        """启动 Web 服务器"""
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=5555,
            log_level="info",
            loop="asyncio"
        )
        self.server = uvicorn.Server(config)

        def run_server():
            asyncio.set_event_loop(asyncio.new_event_loop())
            self.server.run()

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        logger.info("权限管理 WebUI 已启动在 http://localhost:5555")

    async def terminate(self):
        """插件卸载时关闭服务器"""
        if self.server:
            logger.info("正在关闭 WebUI 服务器...")
            self.server.should_exit = True
            if self.server_thread and self.server_thread.is_alive():
                await asyncio.to_thread(self.server_thread.join, timeout=5)
            logger.info("WebUI 服务器已关闭")


# ---------- 登录依赖项 ----------
async def require_auth(request: Request):
    """依赖项：检查用户是否已登录"""
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return True


# ---------- FastAPI 路由 ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """显示登录页面"""
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request):
    """处理登录表单"""
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute(
            "SELECT username, salt, password_hash FROM web_auth WHERE username=?", 
            (username,)
        ) as cursor:
            row = await cursor.fetchone()

    if row and verify_password(password, row[1], row[2]):
        request.session["authenticated"] = True
        request.session["username"] = username
        return RedirectResponse(url="/", status_code=303)
    else:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "用户名或密码错误"
        }, status_code=400)


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

        form = await request.form()
        logger.debug(f"表单数据: {dict(form)}")
        new_perms = {}
        for key, value in form.items():
            if not key.startswith("plugin_"):
                continue
            cmd_index = key.find("_cmd_")
            if cmd_index == -1:
                logger.warning(f"无效的表单字段名: {key}")
                continue
            plugin_name = key[7:cmd_index]
            command = key[cmd_index + 5:]
            try:
                level = int(value)
                if level in PERMISSION_LEVELS.values():
                    new_perms[(plugin_name, command)] = level
                else:
                    logger.warning(f"无效权限等级 {level} 用于 {plugin_name}.{command}")
            except ValueError:
                logger.warning(f"无法解析权限等级: {value}")

        await plugin.save_command_permissions(new_perms)
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        logger.error(f"保存权限时发生异常: {traceback.format_exc()}")
        return PlainTextResponse(f"保存失败: {str(e)}", status_code=500)


@app.get("/save_permissions", dependencies=[Depends(require_auth)])
async def save_permissions_get():
    return PlainTextResponse("请使用 POST 方法提交表单", status_code=405)