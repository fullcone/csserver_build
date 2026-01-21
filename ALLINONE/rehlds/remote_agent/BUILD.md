# Remote Agent 编译说明

## 目录位置

```
ALLINONE/rehlds/remote_agent/
```

## 编译步骤

### 1. 安装 Rust 工具链

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. 添加 32 位目标

```bash
rustup target add i686-unknown-linux-gnu
```

### 3. 安装 32 位交叉编译工具

```bash
# Debian/Ubuntu
sudo apt-get install gcc-multilib g++-multilib gcc-i686-linux-gnu

# 或者
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install gcc-i686-linux-gnu
```

### 4. 编译

```bash
cd ALLINONE/rehlds/remote_agent

# 设置交叉编译器
export CC_i686_unknown_linux_gnu=i686-linux-gnu-gcc
export CXX_i686_unknown_linux_gnu=i686-linux-gnu-g++
export AR_i686_unknown_linux_gnu=i686-linux-gnu-ar
export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=i686-linux-gnu-gcc

# 编译
cargo build --release --target i686-unknown-linux-gnu
```

### 5. 输出文件

```
target/i686-unknown-linux-gnu/release/libremote_agent.so
```

## 部署

将编译好的 `.so` 文件复制到 hlds 目录：

```bash
cp target/i686-unknown-linux-gnu/release/libremote_agent.so /path/to/hlds/remote_agent.so
```

或者放在 addons 目录：

```bash
mkdir -p /path/to/hlds/addons
cp target/i686-unknown-linux-gnu/release/libremote_agent.so /path/to/hlds/addons/remote_agent.so
```

## 自动加载

hlds_linux 启动时会自动搜索并加载 remote_agent.so：

1. `./remote_agent.so` (当前目录)
2. `./addons/remote_agent.so` (addons 目录)
3. `../remote_agent.so` (上级目录)

如果找到文件，Agent 会自动启用，无需任何命令行参数。

## 配置

所有配置都已硬编码在源码中：

- **服务器地址**: `ws://agent.cs16.cspt.fullcone.cn/agent`
- **认证密钥**: `5x890rBpKKmdMCCsxEYdtzROiJce8Rxk`
- **主机名**: 自动生成 `系统hostname:端口` 格式

如需修改，请编辑 `src/config.rs` 后重新编译。

## 验证

启动 hlds_linux 后，查看日志：

```
[RemoteAgent] Loaded from: ./remote_agent.so
[RemoteAgent] Connecting to ws://agent.cs16.cspt.fullcone.cn/agent
[RemoteAgent] Connected successfully
```

如果看到这些日志，说明 Agent 已成功加载并运行。
