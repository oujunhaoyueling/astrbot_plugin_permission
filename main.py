import os
import threading
import asyncio
import sqlite3
import traceback
import collections
import hashlib
import secrets
from pathlib import Path
from typing import Dict, List, Tuple, Optional

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
DATABASE_FILE = str(PLUGIN_DATA_DIR / "permissions.db")

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

_plugin_instance = None


def get_password_hash(password: str, salt: str = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt, key.hex()


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    _, hash_ = get_password_hash(password, salt)
    return hash_ == password_hash


def is_admin(sender_id: str, admin_list: List[str]) -> bool:
    """判断是否为管理员（super_admin）"""
    return sender_id in admin_list


@register("astrbot_plugin_permission", "Your Name", "权限管理插件", "1.0.0", "repo_url")
class PermissionManager(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        global _plugin_instance
        _plugin_instance = self

        self.config = config
        admin_qq_str = config.get("admin_qq", "")
        self.admin_qq_list = [qq.strip() for qq in admin_qq_str.split(",") if qq.strip()]
        logger.info(f"管理员QQ列表: {self.admin_qq_list}")

        self.cmd_permissions: Dict[Tuple[str, str], int] = {}
        self.plugin_commands: Dict[str, List[str]] = {}

        self.server = None
        self.server_thread = None

        self.init_database()
        self.init_auth()
        self.load_command_permissions()
        self.build_command_map_stable()

        secret_key = self.get_or_create_secret_key()
        app.add_middleware(SessionMiddleware, secret_key=secret_key, max_age=3600)

        self.start_web_server()
        self._debug_registered_handlers()

    def _debug_registered_handlers(self):
        try:
            for handler in star_handlers_registry:
                if handler.handler_module_path == __file__:
                    logger.debug(f"本插件已注册处理器: {handler.handler_name}")
        except:
            pass

    def init_database(self):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # 用户权限表
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='permissions'")
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(permissions)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'user_id' not in columns:
                cursor.execute("DROP TABLE permissions")
                logger.warning("检测到 permissions 表结构异常，已删除重建")
                cursor.execute('''
                    CREATE TABLE permissions (
                        user_id TEXT PRIMARY KEY,
                        level INTEGER NOT NULL DEFAULT 0
                    )
                ''')
        else:
            cursor.execute('''
                CREATE TABLE permissions (
                    user_id TEXT PRIMARY KEY,
                    level INTEGER NOT NULL DEFAULT 0
                )
            ''')

        # 群组权限表（新增）
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='group_permissions'")
        if not cursor.fetchone():
            cursor.execute('''
                CREATE TABLE group_permissions (
                    group_id TEXT PRIMARY KEY,
                    level INTEGER NOT NULL DEFAULT 0
                )
            ''')
            logger.info("已创建群组权限表")

        # 指令权限表
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='command_permissions'")
        if not cursor.fetchone():
            cursor.execute('''
                CREATE TABLE command_permissions (
                    plugin_name TEXT NOT NULL,
                    command_name TEXT NOT NULL,
                    min_permission_level INTEGER NOT NULL,
                    PRIMARY KEY (plugin_name, command_name)
                )
            ''')

        # web_auth 表
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='web_auth'")
        if not cursor.fetchone():
            cursor.execute('''
                CREATE TABLE web_auth (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

        # settings 表
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
        if not cursor.fetchone():
            cursor.execute('''
                CREATE TABLE settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')

        conn.commit()
        conn.close()
        logger.info("权限数据库初始化完成")

    def init_auth(self):
        username = self.config.get("web_username", "admin")
        password = self.config.get("web_password", "admin")

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM web_auth")
        count = cursor.fetchone()[0]
        if count == 0:
            salt, pwd_hash = get_password_hash(password)
            cursor.execute(
                "INSERT INTO web_auth (username, salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, pwd_hash)
            )
            conn.commit()
            logger.info("已创建初始 WebUI 登录账户")
        conn.close()

    def get_or_create_secret_key(self) -> str:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key='session_secret'")
        row = cursor.fetchone()
        if row:
            key = row[0]
        else:
            key = secrets.token_hex(32)
            cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ('session_secret', key))
            conn.commit()
            logger.info("生成了新的会话密钥")
        conn.close()
        return key

    def load_command_permissions(self):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT plugin_name, command_name, min_permission_level FROM command_permissions")
        rows = cursor.fetchall()
        self.cmd_permissions = {(row[0], row[1]): row[2] for row in rows}
        conn.close()
        logger.info(f"已加载 {len(self.cmd_permissions)} 条指令权限配置")

    def save_command_permissions(self, new_perms: Dict[Tuple[str, str], int]):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM command_permissions")
        for (plugin, cmd), level in new_perms.items():
            cursor.execute(
                "INSERT INTO command_permissions (plugin_name, command_name, min_permission_level) VALUES (?, ?, ?)",
                (plugin, cmd, level)
            )
        conn.commit()
        conn.close()
        self.cmd_permissions = new_perms
        logger.info(f"已保存 {len(new_perms)} 条指令权限配置")

    def build_command_map_stable(self):
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
            logger.info(f"指令映射构建完成，共收集到 {len(self.plugin_commands)} 个插件的指令")
            for p, cmds in self.plugin_commands.items():
                logger.debug(f"插件 {p} 指令: {cmds}")
        except Exception as e:
            logger.error(f"构建指令映射时发生异常: {traceback.format_exc()}")
            self.plugin_commands = {}

    # ---------- 权限查询函数（合并用户和群组等级） ----------
    def get_effective_level(self, user_id: str, group_id: Optional[str] = None) -> int:
        """
        获取用户的有效权限等级：
        - 如果用户是管理员（super_admin），直接返回 super_admin
        - 否则取用户等级和群组等级的最大值
        """
        if user_id in self.admin_qq_list:
            return PERMISSION_LEVELS["super_admin"]

        user_level = PERMISSION_LEVELS["default"]
        group_level = PERMISSION_LEVELS["default"]

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # 查询用户等级
        cursor.execute("SELECT level FROM permissions WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            user_level = row[0]
        else:
            # 插入默认用户等级
            cursor.execute("INSERT INTO permissions (user_id, level) VALUES (?, ?)", (user_id, PERMISSION_LEVELS["default"]))
            conn.commit()

        # 如果有群组，查询群组等级
        if group_id:
            cursor.execute("SELECT level FROM group_permissions WHERE group_id = ?", (group_id,))
            row = cursor.fetchone()
            if row:
                group_level = row[0]
            # 没有记录则保持 default

        conn.close()
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

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        if scope == "私聊":
            # 设置用户等级
            cursor.execute("INSERT OR REPLACE INTO permissions (user_id, level) VALUES (?, ?)", (target_id, level))
            conn.commit()
            conn.close()
            yield event.plain_result(f"已为用户 {target_id} 设置权限等级为 {LEVEL_TO_NAME[level]} ({level})。")
        else:  # 群组
            # 设置群组等级
            cursor.execute("INSERT OR REPLACE INTO group_permissions (group_id, level) VALUES (?, ?)", (target_id, level))
            conn.commit()
            conn.close()
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

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        if scope == "私聊":
            cursor.execute("DELETE FROM permissions WHERE user_id = ?", (target_id,))
            conn.commit()
            affected = cursor.rowcount
            conn.close()
            if affected:
                yield event.plain_result(f"已取消用户 {target_id} 的权限设置，恢复为默认等级。")
            else:
                yield event.plain_result(f"用户 {target_id} 没有权限设置。")
        else:  # 群组
            cursor.execute("DELETE FROM group_permissions WHERE group_id = ?", (target_id,))
            conn.commit()
            affected = cursor.rowcount
            conn.close()
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

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        msg = ""

        if target is None:
            # 显示所有用户和群组
            cursor.execute("SELECT user_id, level FROM permissions")
            users = cursor.fetchall()
            cursor.execute("SELECT group_id, level FROM group_permissions")
            groups = cursor.fetchall()
            msg += "用户权限设置：\n"
            for uid, lvl in users:
                msg += f"  {uid}: {LEVEL_TO_NAME[lvl]} ({lvl})\n"
            msg += "群组权限设置：\n"
            for gid, lvl in groups:
                msg += f"  {gid}: {LEVEL_TO_NAME[lvl]} ({lvl})\n"
        else:
            # 尝试按用户或群组查询
            cursor.execute("SELECT level FROM permissions WHERE user_id = ?", (target,))
            row = cursor.fetchone()
            if row:
                msg += f"用户 {target} 权限等级: {LEVEL_TO_NAME[row[0]]} ({row[0]})\n"
            cursor.execute("SELECT level FROM group_permissions WHERE group_id = ?", (target,))
            row = cursor.fetchone()
            if row:
                msg += f"群组 {target} 权限等级: {LEVEL_TO_NAME[row[0]]} ({row[0]})\n"
            if not msg:
                msg = f"未找到 {target} 的权限设置。"

        conn.close()
        yield event.plain_result(msg if msg else "暂无权限设置。")

    # ---------- 权限检查拦截器（使用合并等级） ----------
    @filter.event_message_type(filter.EventMessageType.ALL, priority=999)
    async def permission_check(self, event: AstrMessageEvent):
        logger.debug("权限检查函数被调用")
        try:
            if not self.plugin_commands:
                logger.debug("权限检查：plugin_commands 为空，放行")
                return

            sender_id = event.get_sender_id()
            if not sender_id:
                logger.debug("权限检查：无法获取发送者ID，放行")
                return

            # 获取群组ID（如果有）
            group_id = event.get_group_id() if hasattr(event, 'get_group_id') else None

            text = event.message_str.strip()
            logger.debug(f"权限检查：收到消息 '{text}'")
            if not text:
                logger.debug("权限检查：空消息，放行")
                return

            parts = text.split()
            command = parts[0]
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
            effective_level = self.get_effective_level(sender_id, group_id)
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
        if self.server:
            logger.info("正在关闭 WebUI 服务器...")
            self.server.should_exit = True
            if self.server_thread and self.server_thread.is_alive():
                await asyncio.to_thread(self.server_thread.join, timeout=5)
            logger.info("WebUI 服务器已关闭")


# ---------- 登录依赖项 ----------
async def require_auth(request: Request):
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return True


# ---------- FastAPI 路由 ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, salt, password_hash FROM web_auth WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

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
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def home(request: Request):
    try:
        global _plugin_instance
        plugin = _plugin_instance
        if plugin is None:
            return HTMLResponse("<h1>500 Internal Server Error</h1><p>插件实例未初始化</p>", status_code=500)

        plugin.load_command_permissions()

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
    logger.info("收到保存权限请求")
    try:
        global _plugin_instance
        plugin = _plugin_instance
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

        plugin.save_command_permissions(new_perms)
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        logger.error(f"保存权限时发生异常: {traceback.format_exc()}")
        return PlainTextResponse(f"保存失败: {str(e)}", status_code=500)


@app.get("/save_permissions", dependencies=[Depends(require_auth)])
async def save_permissions_get():
    return PlainTextResponse("请使用 POST 方法提交表单", status_code=405)