//! PTY 会话管理模块
//!
//! 管理多个 PTY 终端会话，每个会话对应一个 bash shell 进程
//!
//! 仅在 Linux 平台可用

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, execvp, fork, setsid, ForkResult, Pid};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// PTY 窗口大小结构（与 libc::winsize 兼容）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Winsize {
    pub ws_row: libc::c_ushort,
    pub ws_col: libc::c_ushort,
    pub ws_xpixel: libc::c_ushort,
    pub ws_ypixel: libc::c_ushort,
}

/// 打开 PTY 伪终端
///
/// 返回 (master_fd, slave_fd)
fn openpty(winsize: &Winsize) -> Result<(RawFd, RawFd), String> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            winsize as *const Winsize as *const libc::winsize,
        )
    };

    if ret == -1 {
        return Err(format!(
            "openpty failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok((master, slave))
}

/// PTY 会话
pub struct PtySession {
    /// 会话 ID
    #[allow(dead_code)]
    pub session_id: String,
    /// 子进程 PID
    pub child_pid: i32,
    /// PTY master 文件描述符
    pub master_fd: RawFd,
    /// 输入发送通道
    pub input_tx: mpsc::Sender<Vec<u8>>,
    /// 是否已关闭
    #[allow(dead_code)]
    pub closed: bool,
}

/// PTY 会话管理器
pub struct PtySessionManager {
    /// 活跃的会话
    sessions: Arc<Mutex<HashMap<String, PtySession>>>,
}

impl PtySessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 创建新的 PTY 会话
    pub async fn create_session(
        &self,
        session_id: String,
        cols: u16,
        rows: u16,
        shell: Option<String>,
        output_callback: impl Fn(String, Vec<u8>) + Send + 'static,
        close_callback: impl FnOnce(String, String, Option<i32>) + Send + 'static,
    ) -> Result<(), String> {
        let shell_path = shell.unwrap_or_else(|| "/bin/bash".to_string());

        // 检查会话是否已存在
        {
            let sessions = self.sessions.lock();
            if sessions.contains_key(&session_id) {
                return Err(format!("Session {} already exists", session_id));
            }
        }

        // 创建 PTY
        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let (master, slave) = openpty(&winsize)?;

        // Fork 子进程
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // 父进程：关闭 slave 端
                let _ = close(slave);

                let child_pid = child.as_raw() as i32;
                info!(
                    "[PTY] Session {} created, PID={}, shell={}",
                    session_id, child_pid, shell_path
                );

                // 创建输入通道
                let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(256);

                // 保存会话
                {
                    let mut sessions = self.sessions.lock();
                    sessions.insert(
                        session_id.clone(),
                        PtySession {
                            session_id: session_id.clone(),
                            child_pid,
                            master_fd: master,
                            input_tx: input_tx.clone(),
                            closed: false,
                        },
                    );
                }

                // 启动 I/O 任务
                let sessions_clone = self.sessions.clone();
                let session_id_clone = session_id.clone();

                tokio::spawn(async move {
                    Self::run_session_io(
                        session_id_clone,
                        master,
                        child_pid,
                        input_rx,
                        output_callback,
                        close_callback,
                        sessions_clone,
                    )
                    .await;
                });

                Ok(())
            }
            Ok(ForkResult::Child) => {
                // 子进程：设置为新会话，执行 shell
                let _ = close(master);

                // 创建新会话
                let _ = setsid();

                // 设置控制终端
                unsafe {
                    libc::ioctl(slave, libc::TIOCSCTTY, 0);
                }

                // 重定向标准输入输出到 slave（使用 libc::dup2）
                unsafe {
                    libc::dup2(slave, 0);
                    libc::dup2(slave, 1);
                    libc::dup2(slave, 2);
                }

                if slave > 2 {
                    let _ = close(slave);
                }

                // 设置环境变量
                std::env::set_var("TERM", "xterm-256color");
                std::env::set_var("COLORTERM", "truecolor");
                std::env::set_var("LANG", "en_US.UTF-8");

                // 执行 shell
                let shell_cstr = std::ffi::CString::new(shell_path.as_str())
                    .unwrap_or_else(|_| std::ffi::CString::new("/bin/bash").unwrap());
                let args = [shell_cstr.clone()];

                let _ = execvp(&shell_cstr, &args);

                // 如果 execvp 失败，退出
                std::process::exit(1);
            }
            Err(e) => {
                let _ = close(master);
                let _ = close(slave);
                Err(format!("Fork failed: {}", e))
            }
        }
    }

    /// 运行会话 I/O 循环
    async fn run_session_io(
        session_id: String,
        master_fd: RawFd,
        child_pid: i32,
        mut input_rx: mpsc::Receiver<Vec<u8>>,
        output_callback: impl Fn(String, Vec<u8>) + Send + 'static,
        close_callback: impl FnOnce(String, String, Option<i32>) + Send + 'static,
        sessions: Arc<Mutex<HashMap<String, PtySession>>>,
    ) {
        // 复制 fd 用于读取，原始 fd 用于写入
        // 这样避免 double-close 问题
        let read_fd = unsafe { libc::dup(master_fd) };
        if read_fd == -1 {
            error!("[PTY] Failed to dup master_fd for reading");
            close_callback(session_id, "Failed to setup PTY".to_string(), None);
            return;
        }

        // 创建异步文件句柄
        let mut master_read = unsafe {
            let std_file = std::fs::File::from_raw_fd(read_fd);
            tokio::fs::File::from_std(std_file)
        };

        let mut master_write = unsafe {
            let std_file = std::fs::File::from_raw_fd(master_fd);
            tokio::fs::File::from_std(std_file)
        };

        let mut read_buf = vec![0u8; 4096];
        let mut exit_code: Option<i32> = None;
        #[allow(unused_assignments)]
        let mut close_reason = String::new();

        loop {
            tokio::select! {
                // 读取 PTY 输出
                result = master_read.read(&mut read_buf) => {
                    match result {
                        Ok(0) => {
                            debug!("[PTY] Session {} EOF", session_id);
                            close_reason = "Shell exited".to_string();
                            break;
                        }
                        Ok(n) => {
                            output_callback(session_id.clone(), read_buf[..n].to_vec());
                        }
                        Err(e) => {
                            error!("[PTY] Session {} read error: {}", session_id, e);
                            close_reason = format!("Read error: {}", e);
                            break;
                        }
                    }
                }

                // 处理输入
                Some(data) = input_rx.recv() => {
                    if let Err(e) = master_write.write_all(&data).await {
                        error!("[PTY] Session {} write error: {}", session_id, e);
                        close_reason = format!("Write error: {}", e);
                        break;
                    }
                }

                // 输入通道关闭
                else => {
                    debug!("[PTY] Session {} input channel closed", session_id);
                    close_reason = "Input channel closed".to_string();
                    break;
                }
            }
        }

        // 清理
        info!("[PTY] Session {} closing: {}", session_id, close_reason);

        // 终止子进程
        let pid = Pid::from_raw(child_pid);
        let _ = kill(pid, Signal::SIGTERM);

        // 等待子进程退出
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                exit_code = Some(code);
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                exit_code = Some(128 + sig as i32);
            }
            _ => {
                // 强制杀死
                let _ = kill(pid, Signal::SIGKILL);
                let _ = waitpid(pid, Some(WaitPidFlag::WNOHANG));
            }
        }

        // 从会话列表移除
        {
            let mut sessions_guard = sessions.lock();
            sessions_guard.remove(&session_id);
        }

        // 调用关闭回调
        close_callback(session_id, close_reason, exit_code);
    }

    /// 向会话发送输入
    pub async fn send_input(&self, session_id: &str, data: Vec<u8>) -> Result<(), String> {
        let input_tx = {
            let sessions = self.sessions.lock();
            sessions
                .get(session_id)
                .map(|s| s.input_tx.clone())
                .ok_or_else(|| format!("Session {} not found", session_id))?
        };

        input_tx
            .send(data)
            .await
            .map_err(|_| format!("Failed to send input to session {}", session_id))
    }

    /// 调整会话终端大小
    pub fn resize_session(&self, session_id: &str, cols: u16, rows: u16) -> Result<(), String> {
        let master_fd = {
            let sessions = self.sessions.lock();
            sessions
                .get(session_id)
                .map(|s| s.master_fd)
                .ok_or_else(|| format!("Session {} not found", session_id))?
        };

        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        unsafe {
            if libc::ioctl(master_fd, libc::TIOCSWINSZ, &winsize) == -1 {
                return Err(format!("Failed to resize session {}", session_id));
            }
        }

        debug!("[PTY] Session {} resized to {}x{}", session_id, cols, rows);
        Ok(())
    }

    /// 关闭会话
    pub fn close_session(&self, session_id: &str) -> Result<(), String> {
        let session = {
            let mut sessions = self.sessions.lock();
            sessions.remove(session_id)
        };

        if let Some(session) = session {
            // 终止子进程
            let pid = Pid::from_raw(session.child_pid);
            let _ = kill(pid, Signal::SIGTERM);

            // 注意：master_fd 的所有权已经转移给 tokio::fs::File
            // 当 I/O 任务结束时会自动关闭
            // 这里不需要手动 close

            info!("[PTY] Session {} closed by request", session_id);
            Ok(())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// 获取活跃会话数
    pub fn active_session_count(&self) -> u32 {
        self.sessions.lock().len() as u32
    }

    /// 关闭所有会话
    pub fn close_all_sessions(&self) {
        let sessions: Vec<_> = {
            let mut guard = self.sessions.lock();
            guard.drain().collect()
        };

        for (session_id, session) in sessions {
            let pid = Pid::from_raw(session.child_pid);
            let _ = kill(pid, Signal::SIGTERM);
            // 注意：master_fd 的所有权已经转移给 tokio::fs::File
            // 当 I/O 任务结束时会自动关闭
            info!("[PTY] Session {} closed (shutdown)", session_id);
        }
    }
}

impl Drop for PtySessionManager {
    fn drop(&mut self) {
        self.close_all_sessions();
    }
}
