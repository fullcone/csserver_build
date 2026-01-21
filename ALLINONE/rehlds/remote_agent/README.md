# Remote Agent for ReHLDS

远程终端 Agent，允许通过 Web 界面远程管理 ReHLDS 游戏服务器。

## 架构

```
┌─────────────────┐     WebSocket      ┌─────────────────┐     WebSocket      ┌─────────────────┐
│   Web Browser   │ ◄─────────────────► │   Rust Server   │ ◄─────────────────► │  Remote Agent   │
│  (xterm.js UI)  │   /agent-terminal  │  (中控服务器)    │      /agent        │  (.so in hlds)  │
└─────────────────┘                     └─────────────────┘                     └─────────────────┘
                                                                                        │
                                                                                        │ PTY
                                                                                        ▼
                                                                                ┌─────────────────┐
                                                                                │   bash shell    │
                                                                                └─────────────────┘
```

## 组件

### 1. Remote Agent (.so 动态库)

- 编译为 `remote_agent.so`，由 `hlds_linux` 在启动时通过 `dlopen()` 加载
- 运行在独立线程中，不阻塞游戏服务器主线程
- 主动连接到中控 Rust Server
- 管理 PTY 终端会话

### 2. Rust Server (中控服务器)

- 接收 Agent 连接 (`/agent` WebSocket 端点)
- 接收 Web 客户端连接 (`/agent-terminal` WebSocket 端点)
- 路由终端数据在 Agent 和 Web 客户端之间

### 3. Web UI

- 基于 xterm.js 的终端界面
- 显示在线服务器列表
- 支持选择服务器并连接终端

## 编译

### 编译 Remote Agent

```bash
cd github/patches/remote_agent

# 安装 32 位目标（hlds_linux 是 32 位程序）
rustup target add i686-unknown-linux-gnu

# 编译
cargo build --release --target i686-unknown-linux-gnu

# 输出文件
ls target/i686-unknown-linux-gnu/release/libremote_agent.so
```

### 应用补丁到 ReHLDS

```bash
cd github/patches
./apply_remote_agent.sh /path/to/rehlds
```

## 部署

### 1. 部署 Agent

将编译好的 `libremote_agent.so` 复制到 hlds 目录：

```bash
cp target/i686-unknown-linux-gnu/release/libremote_agent.so /path/to/hlds/remote_agent.so
```

### 2. 启动 hlds_linux

Agent 永远启用，所有配置硬编码，无需任何参数：
- 服务器地址: `ws://agent.cs16.cspt.fullcone.cn/agent`
- 认证密钥: `5x890rBpKKmdMCCsxEYdtzROiJce8Rxk`
- 主机名: 自动生成 `系统hostname:端口` 格式（如 `myserver:27015`）

```bash
# Agent 自动启用，无需任何参数
./hlds_linux -game cstrike +map de_dust2

# 指定端口时，hostname 会自动包含端口号
./hlds_linux -game cstrike +map de_dust2 -port 27016
# hostname 会是: myserver:27016
```

### 3. 启动 Rust Server

认证密钥已硬编码，无需任何参数：

```bash
./rustserver
```

或指定监听地址：

```bash
./rustserver --listen 0.0.0.0:8080
```

### 4. 访问 Web UI

打开浏览器访问：`http://your-server.com:8080/static/agent-terminal.html`

## 命令行参数

### hlds_linux

Agent 完全硬编码，无需任何参数。只要 `remote_agent.so` 文件存在，Agent 就会自动启用。

注：`-port` 参数会被读取用于生成 hostname（如 `myserver:27016`），这是 HLDS 原有参数。

### Rust Server

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l, --listen` | 监听地址 | `0.0.0.0:8080` |
| `-c, --cs-server` | CS 服务器地址 | `127.0.0.1:27015` |
| `--log-level` | 日志级别 | `info` |
| `--static-dir` | 静态文件目录 | `static` |

注：Agent 认证密钥已硬编码为 `5x890rBpKKmdMCCsxEYdtzROiJce8Rxk`

## 安全警告

⚠️ **此功能提供完整的 shell 访问权限，必须配合严格的安全措施使用！**

1. **使用强密钥**：认证密钥应该是随机生成的长字符串
2. **使用 HTTPS/WSS**：生产环境必须使用 TLS 加密
3. **限制访问**：通过防火墙限制对 Rust Server 的访问
4. **审计日志**：记录所有终端操作

## 协议

### Agent -> Server

```json
{"type": "auth", "key": "...", "hostname": "...", "version": "1.0.0"}
{"type": "heartbeat", "active_sessions": 0, "uptime_secs": 3600}
{"type": "terminal_output", "session_id": "...", "data": "base64..."}
{"type": "terminal_closed", "session_id": "...", "reason": "...", "exit_code": 0}
{"type": "terminal_created", "session_id": "..."}
{"type": "error", "session_id": "...", "code": "...", "message": "..."}
```

### Server -> Agent

```json
{"type": "auth_result", "success": true, "message": "...", "agent_id": "..."}
{"type": "heartbeat_ack"}
{"type": "create_terminal", "session_id": "...", "cols": 80, "rows": 24, "shell": "/bin/bash"}
{"type": "terminal_input", "session_id": "...", "data": "base64..."}
{"type": "terminal_resize", "session_id": "...", "cols": 120, "rows": 40}
{"type": "close_terminal", "session_id": "..."}
{"type": "shutdown", "reason": "..."}
```
