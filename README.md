# AstrBot Permission Plugin / AstrBot 权限管理插件

## Introduction / 简介
This plugin provides **command-level permission control** for AstrBot, and can **completely replace** the framework's built-in permission management. You can configure the minimum required permission level for each command of each plugin in an independent WebUI.  
本插件为 AstrBot 提供**指令级权限控制**功能，可以**完全取代**框架自身权限管理。你可以在独立的 WebUI 中为每个插件的每条指令配置所需的最低权限等级。

## Features / 特性
- 🔒 **Command-level permissions**：Set independent permission levels for each command of each plugin (you can also set for the entire plugin)  
  **指令级权限**：为每个插件的每条指令独立设置权限等级（当然你也可以为整个插件设置）
- 🧑‍🤝‍🧑 **User/Group permission management**：Support setting permission levels for individual users (QQ) or groups, admins automatically get the highest level  
  **用户/群组权限管理**：支持为每个用户（QQ号）或群组单独设置权限等级，管理员自动获得最高权限
- 🌐 **Independent WebUI**：Built-in FastAPI server provides a beautiful permission configuration page with login protection  
  **独立 WebUI**：内置 FastAPI 服务器，提供美观的权限配置页面，支持登录保护
- 🔍 **Real-time search**：WebUI supports searching by plugin name or command name to quickly locate configuration items  
  **实时搜索**：WebUI 支持按插件名或指令名搜索，快速定位配置项
- 🛡️ **High priority interception**：The permission checker runs with the highest priority to ensure validation before all other plugins  
  **高优先级拦截**：权限检查器以最高优先级运行，确保在所有插件执行前完成校验
- 📦 **Zero intrusion**：No need to modify other plugin code, permission control is achieved through event interception  
  **零侵入**：无需修改其他插件代码，通过事件拦截机制实现权限控制

## Installation / 安装

### Via AstrBot Plugin Market / 通过 AstrBot 插件市场
1. Open the "Plugin Market" in AstrBot WebUI.  
   在 AstrBot WebUI 中打开「插件市场」。
2. Search for `astrbot_plugin_permission` and click install.  
   搜索 `astrbot_plugin_permission` 并点击安装。
3. Restart AstrBot or reload the plugin.  
   重启 AstrBot 或重载插件。

### Manual Installation / 手动安装
1. Clone this repository to the `data/plugins/` directory:  
   将本插件仓库克隆至 `data/plugins/` 目录：
   ```bash
   cd data/plugins
   git clone https://github.com/oujunhaoyueling/astrbot_plugin_permission.git
   ```
2. Restart AstrBot or reload the plugin.  
   重启 AstrBot 或重载插件。

## Configuration / 配置

| Config Item / 配置项 | Type / 类型 | Description / 描述 | Default / 默认值 |
|--------|------|------|--------|
| `admin_qq` | string | Admin QQ numbers, separated by commas (e.g., `123456,789012`) / 管理员QQ号，多个用英文逗号分隔 | Empty / 空 |
| `web_username` | string | WebUI login username / WebUI 登录用户名 | `admin` |
| `web_password` | string | WebUI login password (a random password is generated on first startup) / WebUI 登录密码（首次启动自动生成随机密码） | Random / 随机 |

## Usage / 使用方法

### 1. Access WebUI to configure plugin permissions / 访问 WebUI 配置插件所需权限
After the plugin starts, it will launch a web server at `localhost:5555`. Open your browser and visit `http://your-ip:5555` (remember to open the firewall), and log in with the configured username and password.  
插件启动后会在 `localhost:5555` 启动 Web 服务器。打开浏览器访问 `http://你的IP:5555`（记得开防火墙），使用配置的用户名密码登录。

### 2. Configure command permissions / 配置指令权限
After logging in, the page will list all loaded plugins and their commands. Each command has a dropdown menu to select the permission level:  
登录后页面将列出所有已加载插件的指令。每个指令旁有一个下拉菜单，可选择权限等级：
- `default` (0)
- `member` (1)
- `moderator` (2)
- `admin` (3)
- `super_admin` (4)

After selection, click the blue **Save** button in the top-left corner to apply changes.  
选择后点击左上角蓝色「保存」按钮即可生效。

### 3. Configure permissions in chat (use "/权限帮助" to view plugin commands) / 在聊天中配置权限（使用“/权限帮助”查看插件命令）
The plugin currently supports the following chat commands (all commands must start with `/`):  
插件目前支持以下聊天命令（所有命令均需以 `/` 开头）：

| Command / 命令 | Parameters / 参数 | Description / 说明 | Available Users / 可用用户 |
|------|------|------|----------|
| `/授权` | `[group/private] [QQ/group ID] [level name or value]` | Set permission level for a user or group / 设置指定用户或群组的权限等级 | Admin only / 仅管理员 |
| `/取消授权` | `[group/private] [QQ/group ID]` | Remove permission settings for a user or group, restore default level / 删除指定用户或群组的权限设置，恢复默认等级 | Admin only / 仅管理员 |
| `/权限列表` | `[optional: user QQ/group ID]` | View all or specified permission settings / 查看所有或指定目标的权限设置 | Admin only / 仅管理员 |
| `/权限帮助` | None / 无 | Show help information for permission commands / 显示权限管理指令的帮助信息 | Everyone / 所有人 |
| `/perm_debug` | None / 无 | Debug: output current command mapping and permission configuration (for development) / 调试：输出当前指令映射和权限配置（用于开发） | Admin recommended / 建议仅管理员 |

**Note / 注**：
- Admins are defined by the `admin_qq` configuration item (multiple separated by commas).  
  管理员由插件配置项 `admin_qq` 定义（多个用逗号分隔）。
- Level names and values correspond: `default(0)`, `member(1)`, `moderator(2)`, `admin(3)`, `super_admin(4)`.  
  等级名称与数值对应：`default(0)`、`member(1)`、`moderator(2)`、`admin(3)`、`super_admin(4)`。
- When authorizing, if the message comes from a group chat, the effective permission level is the maximum of the user's level and the group's level.  
  授权时，若消息来自群聊，最终有效权限等级取用户等级和群组等级的最大值。

### 4. Permission check / 权限检查
When a user sends a command starting with `/`, the plugin automatically executes the following logic:  
当用户发送以 `/` 开头的指令时，插件会自动执行以下逻辑：
- Get the sender's QQ number. If it is in the `admin_qq` list, allow directly (treated as `super_admin`).  
  获取发送者 QQ 号，若在 `admin_qq` 列表中则直接放行（视为 `super_admin`）。
- Otherwise, query the user's permission level from the database (default is `default`).  
  否则从数据库中查询该用户的权限等级（默认为 `default`）。
- Find the plugin the command belongs to and its configured minimum level. If the user's level < required level, reply:  
  查找指令所属插件及配置的最低等级，若用户等级 < 要求等级，则回复：
  ```
  You do not have permission to use the /[command] command of the [plugin] plugin. Required level: [level name].
  您没有权限使用 [插件名] 插件的指令 /[指令]，需要等级 [等级名]。
  ```
  And stop event propagation, subsequent plugins will not execute.  
  并阻止事件传播，后续插件不会执行。

## 5. Permission level description / 权限等级说明
| Level Name / 等级名称 | Value / 数值 | Description / 说明 |
|----------|------|------|
| `default` | 0 | Default user level / 默认用户等级 |
| `member`  | 1 | Regular member / 普通成员 |
| `moderator` | 2 | Moderator / 协管员 |
| `admin` | 3 | Administrator / 管理员 |
| `super_admin` | 4 | Super administrator (automatically granted to admin QQ) / 超级管理员（自动授予管理员QQ） |

## 6. Command description / 指令说明
This plugin provides a debug command (only available during development):  
本插件提供一个调试指令（仅在开发时可用）：
- `/perm_debug`: View current command mapping and permission configuration (admin only)  
  查看当前指令映射和权限配置（仅限管理员）

## 7. Dependencies / 依赖
- **Python 3.8+**
- **AstrBot 4.17+**
- aiosqlite>=0.19.0
- fastapi>=0.104.0
- uvicorn>=0.24.0
- jinja2>=3.1.0

## 8. Notes / 注意事项
- After configuring admin QQ in `admin_qq`, these users automatically get `super_admin` permission, no need to set them separately in the `permissions` table.  
  管理员QQ在 `admin_qq` 中配置后，这些用户自动获得 `super_admin` 权限，无需在 `permissions` 表中额外设置。
- The plugin needs to be **reloaded** to apply configuration changes.  
  插件需要**重载**才能应用配置更改。

## 9. Feedback & Contributions / 反馈与贡献
If you have any questions or suggestions, feel free to submit an [Issue](https://github.com/oujunhaoyueling/astrbot_plugin_permission/issues) or Pull Request.  
如有问题或建议，欢迎提交 [Issue](https://github.com/oujunhaoyueling/astrbot_plugin_permission/issues) 或 Pull Request。

---

**If you like it, please give a star! (｡•̀ᴗ-)✧**  
**如果觉得好用就给个 star 叭～**