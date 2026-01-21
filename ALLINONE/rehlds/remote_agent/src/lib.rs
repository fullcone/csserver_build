//! Remote Terminal Agent for ReHLDS
//!
//! 作为 .so 动态库被 hlds_linux 加载，提供远程终端功能。
//! 连接到中控 Rust Server，允许通过 Web 界面远程管理服务器。
//!
//! # 安全警告
//! 此模块提供完整的 shell 访问权限，必须配合认证机制使用！
//!
//! # 平台支持
//! 此模块仅支持 Linux 平台（hlds_linux 是 Linux 程序）

// 仅在 Linux 上编译主要功能
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

mod config;
mod protocol;

#[cfg(target_os = "linux")]
mod pty_session;
#[cfg(target_os = "linux")]
mod websocket;

use std::ffi::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tracing::{error, info};

use crate::config::AgentConfig;

/// 全局运行状态
static AGENT_RUNNING: AtomicBool = AtomicBool::new(false);

/// 全局配置（初始化后不变）
static AGENT_CONFIG: OnceCell<AgentConfig> = OnceCell::new();

/// Agent 线程句柄
static AGENT_THREAD: OnceCell<Mutex<Option<std::thread::JoinHandle<()>>>> = OnceCell::new();


// ============================================================================
// Linux 平台实现
// ============================================================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::ffi::CStr;
    use std::thread;

    /// C 导出函数：初始化 Agent
    ///
    /// 由 hlds_linux 在 main() 中调用，必须快速返回（< 1ms）
    /// 
    /// Agent 永远启用，使用硬编码的服务器地址和认证密钥
    /// hostname 自动生成为 "系统hostname:端口" 格式
    ///
    /// # Safety
    /// - argc 和 argv 必须是有效的命令行参数
    /// - 此函数只能调用一次
    #[no_mangle]
    pub unsafe extern "C" fn RemoteAgent_Init(argc: c_int, argv: *const *const c_char) {
        // 防止重复初始化
        if AGENT_RUNNING.swap(true, Ordering::SeqCst) {
            eprintln!("[RemoteAgent] Already initialized, skipping");
            return;
        }

        // 初始化日志
        init_logging();

        // 解析命令行参数获取配置
        let config = parse_args(argc, argv);

        info!(
            "[RemoteAgent] Initializing - server: {}, hostname: {}",
            config.server_url, config.hostname
        );

        // 保存配置
        let _ = AGENT_CONFIG.set(config.clone());

        // 初始化线程句柄存储
        let _ = AGENT_THREAD.set(Mutex::new(None));

        // 启动 Agent 线程（非阻塞）
        let handle = thread::Builder::new()
            .name("remote-agent".to_string())
            .spawn(move || {
                agent_thread_main(config);
            });

        match handle {
            Ok(h) => {
                if let Some(thread_holder) = AGENT_THREAD.get() {
                    *thread_holder.lock() = Some(h);
                }
                info!("[RemoteAgent] Thread started successfully");
            }
            Err(e) => {
                error!("[RemoteAgent] Failed to start thread: {}", e);
                AGENT_RUNNING.store(false, Ordering::SeqCst);
            }
        }

        // 立即返回，不阻塞主线程
    }

    /// C 导出函数：关闭 Agent
    #[no_mangle]
    pub extern "C" fn RemoteAgent_Shutdown() {
        if !AGENT_RUNNING.load(Ordering::SeqCst) {
            return;
        }

        info!("[RemoteAgent] Shutting down...");
        AGENT_RUNNING.store(false, Ordering::SeqCst);

        // 等待线程结束（最多 5 秒）
        if let Some(thread_holder) = AGENT_THREAD.get() {
            if let Some(handle) = thread_holder.lock().take() {
                let _ = handle.join();
            }
        }

        info!("[RemoteAgent] Shutdown complete");
    }

    /// C 导出函数：检查 Agent 是否运行中
    #[no_mangle]
    pub extern "C" fn RemoteAgent_IsRunning() -> c_int {
        if AGENT_RUNNING.load(Ordering::SeqCst) {
            1
        } else {
            0
        }
    }

    /// 初始化日志系统
    fn init_logging() {
        use tracing_subscriber::{fmt, EnvFilter};

        // 默认完全禁用日志，设置 RUST_LOG=info 可以启用
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));

        let _ = fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .try_init();
    }

    // ========== 硬编码配置 ==========
    const DEFAULT_SERVER_URL: &str = "ws://agent.cs16.cspt.fullcone.cn/agent";
    const DEFAULT_AUTH_KEY: &str = "5x890rBpKKmdMCCsxEYdtzROiJce8Rxk";

    /// 解析命令行参数
    /// 
    /// 使用硬编码的服务器地址和认证密钥，无需任何配置参数
    /// hostname 自动生成为 "系统hostname:端口" 格式
    /// Agent 永远启用
    unsafe fn parse_args(argc: c_int, argv: *const *const c_char) -> AgentConfig {
        let mut port: Option<u16> = None;

        let args: Vec<String> = (0..argc as usize)
            .filter_map(|i| {
                let ptr = *argv.add(i);
                if ptr.is_null() {
                    None
                } else {
                    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string())
                }
            })
            .collect();

        let mut i = 0;
        while i < args.len() {
            // 支持 -port 27016 和 +port 27016
            if args[i] == "-port" || args[i] == "+port" {
                if i + 1 < args.len() {
                    if let Ok(p) = args[i + 1].parse::<u16>() {
                        port = Some(p);
                    }
                    i += 1;
                }
            }
            i += 1;
        }

        // 生成 hostname: 系统hostname:端口
        let sys_hostname = get_system_hostname();
        let hostname = match port {
            Some(p) => format!("{}:{}", sys_hostname, p),
            None => {
                // 没有指定端口，生成随机标识
                let random_id: u32 = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| (d.as_nanos() % 100000) as u32)
                    .unwrap_or(0);
                format!("{}:{}", sys_hostname, random_id)
            }
        };

        AgentConfig {
            server_url: DEFAULT_SERVER_URL.to_string(),
            auth_key: DEFAULT_AUTH_KEY.to_string(),
            hostname,
            reconnect_interval_secs: 5,
            heartbeat_interval_secs: 30,
        }
    }

    /// 获取系统 hostname
    fn get_system_hostname() -> String {
        nix::unistd::gethostname()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Agent 主线程入口
    fn agent_thread_main(config: AgentConfig) {
        info!(
            "[RemoteAgent] Thread started, connecting to {}",
            config.server_url
        );

        // 创建 tokio 运行时
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agent-tokio")
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                error!("[RemoteAgent] Failed to create tokio runtime: {}", e);
                return;
            }
        };

        // 运行异步主循环
        runtime.block_on(async {
            crate::websocket::run_agent_loop(&config, &AGENT_RUNNING).await;
        });

        info!("[RemoteAgent] Thread exiting");
    }
}

// ============================================================================
// 非 Linux 平台的空实现（用于编译检查）
// ============================================================================

#[cfg(not(target_os = "linux"))]
mod stub_impl {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn RemoteAgent_Init(_argc: c_int, _argv: *const *const c_char) {
        eprintln!("[RemoteAgent] ERROR: This module only works on Linux!");
    }

    #[no_mangle]
    pub extern "C" fn RemoteAgent_Shutdown() {}

    #[no_mangle]
    pub extern "C" fn RemoteAgent_IsRunning() -> c_int {
        0
    }
}
