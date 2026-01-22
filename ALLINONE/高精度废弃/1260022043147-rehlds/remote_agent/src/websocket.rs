//! WebSocket 客户端模块
//!
//! 负责连接到中控服务器，处理消息收发，自动重连
//!
//! 仅在 Linux 平台可用

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

use crate::config::AgentConfig;
use crate::protocol::{AgentMessage, ServerMessage, AGENT_VERSION};
use crate::pty_session::PtySessionManager;

/// 运行 Agent 主循环
///
/// 持续连接到服务器，断线自动重连
pub async fn run_agent_loop(config: &AgentConfig, running: &AtomicBool) {
    let start_time = Instant::now();
    let mut retry_count = 0u32;
    let max_retry_delay = 60u64; // 最大重连延迟 60 秒

    while running.load(Ordering::SeqCst) {
        info!(
            "[Agent] Connecting to {} (attempt {})",
            config.server_url,
            retry_count + 1
        );

        match run_connection(config, running, start_time).await {
            Ok(()) => {
                info!("[Agent] Connection closed normally");
                retry_count = 0; // 正常关闭，重置重试计数
            }
            Err(e) => {
                error!("[Agent] Connection error: {}", e);
                retry_count += 1;
            }
        }

        // 检查是否应该退出
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // 计算重连延迟（指数退避，最大 60 秒）
        let delay_secs = std::cmp::min(
            config.reconnect_interval_secs * (1 << std::cmp::min(retry_count, 6)),
            max_retry_delay,
        );

        info!("[Agent] Reconnecting in {} seconds...", delay_secs);

        // 等待重连，但可以被中断
        let delay = tokio::time::sleep(std::time::Duration::from_secs(delay_secs));
        tokio::pin!(delay);

        loop {
            tokio::select! {
                _ = &mut delay => break,
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    if !running.load(Ordering::SeqCst) {
                        return;
                    }
                }
            }
        }
    }

    info!("[Agent] Main loop exiting");
}

/// 运行单次连接
async fn run_connection(
    config: &AgentConfig,
    running: &AtomicBool,
    start_time: Instant,
) -> Result<(), String> {
    // 连接到服务器
    let (ws_stream, _response) = connect_async(&config.server_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    info!("[Agent] Connected to {}", config.server_url);

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // 发送认证消息
    let auth_msg = AgentMessage::Auth {
        key: config.auth_key.clone(),
        hostname: config.hostname.clone(),
        version: AGENT_VERSION.to_string(),
    };

    let auth_json = auth_msg
        .to_json()
        .map_err(|e| format!("Failed to serialize auth message: {}", e))?;

    ws_sender
        .send(Message::Text(auth_json.into()))
        .await
        .map_err(|e| format!("Failed to send auth message: {}", e))?;

    // 等待认证结果
    let auth_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        wait_for_auth(&mut ws_receiver),
    )
    .await
    .map_err(|_| "Authentication timeout".to_string())?
    .map_err(|e| format!("Authentication failed: {}", e))?;

    info!("[Agent] Authenticated, agent_id={:?}", auth_result);

    // 创建 PTY 会话管理器
    let session_manager = Arc::new(PtySessionManager::new());

    // 创建消息发送通道
    let (msg_tx, mut msg_rx) = mpsc::channel::<AgentMessage>(256);

    // 心跳定时器
    let heartbeat_interval = config.heartbeat_interval();

    // 主循环
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    heartbeat_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // 处理服务器消息
            msg_result = ws_receiver.next() => {
                match msg_result {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = handle_server_message(
                            &text,
                            &session_manager,
                            &msg_tx,
                        ).await {
                            warn!("[Agent] Failed to handle message: {}", e);
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if let Err(e) = ws_sender.send(Message::Pong(data)).await {
                            error!("[Agent] Failed to send pong: {}", e);
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("[Agent] Server closed connection");
                        break;
                    }
                    Some(Err(e)) => {
                        error!("[Agent] WebSocket error: {}", e);
                        break;
                    }
                    None => {
                        info!("[Agent] WebSocket stream ended");
                        break;
                    }
                    _ => {}
                }
            }

            // 发送待发消息
            Some(msg) = msg_rx.recv() => {
                match msg.to_json() {
                    Ok(json) => {
                        if let Err(e) = ws_sender.send(Message::Text(json.into())).await {
                            error!("[Agent] Failed to send message: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("[Agent] Failed to serialize message: {}", e);
                    }
                }
            }

            // 心跳
            _ = heartbeat_timer.tick() => {
                let uptime = start_time.elapsed().as_secs();
                let active_sessions = session_manager.active_session_count();

                let heartbeat = AgentMessage::Heartbeat {
                    active_sessions,
                    uptime_secs: uptime,
                };

                match heartbeat.to_json() {
                    Ok(json) => {
                        if let Err(e) = ws_sender.send(Message::Text(json.into())).await {
                            error!("[Agent] Failed to send heartbeat: {}", e);
                            break;
                        }
                        debug!("[Agent] Heartbeat sent (sessions={}, uptime={}s)", active_sessions, uptime);
                    }
                    Err(e) => {
                        error!("[Agent] Failed to serialize heartbeat: {}", e);
                    }
                }
            }

            // 检查运行状态
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                if !running.load(Ordering::SeqCst) {
                    info!("[Agent] Shutdown requested");
                    // 发送关闭消息
                    let _ = ws_sender.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }

    // 清理所有会话
    session_manager.close_all_sessions();

    Ok(())
}

/// 等待认证结果
async fn wait_for_auth(
    receiver: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Result<Option<String>, String> {
    while let Some(msg_result) = receiver.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                let server_msg = ServerMessage::from_json(&text)
                    .map_err(|e| format!("Invalid message format: {}", e))?;

                match server_msg {
                    ServerMessage::AuthResult {
                        success,
                        message,
                        agent_id,
                    } => {
                        if success {
                            return Ok(agent_id);
                        } else {
                            return Err(message);
                        }
                    }
                    _ => {
                        return Err("Expected auth_result message".to_string());
                    }
                }
            }
            Ok(Message::Close(_)) => {
                return Err("Connection closed during auth".to_string());
            }
            Err(e) => {
                return Err(format!("WebSocket error: {}", e));
            }
            _ => continue,
        }
    }
    Err("No auth response received".to_string())
}

/// 处理服务器消息
async fn handle_server_message(
    text: &str,
    session_manager: &Arc<PtySessionManager>,
    msg_tx: &mpsc::Sender<AgentMessage>,
) -> Result<(), String> {
    let server_msg =
        ServerMessage::from_json(text).map_err(|e| format!("Invalid message: {}", e))?;

    match server_msg {
        ServerMessage::HeartbeatAck => {
            debug!("[Agent] Heartbeat acknowledged");
        }

        ServerMessage::CreateTerminal {
            session_id,
            cols,
            rows,
            shell,
        } => {
            info!(
                "[Agent] Creating terminal session: {} ({}x{})",
                session_id, cols, rows
            );

            let msg_tx_clone = msg_tx.clone();
            let session_id_clone = session_id.clone();

            // 输出回调
            let output_callback = {
                let msg_tx = msg_tx.clone();
                let session_id = session_id.clone();
                move |_sid: String, data: Vec<u8>| {
                    let encoded = BASE64.encode(&data);
                    let msg = AgentMessage::TerminalOutput {
                        session_id: session_id.clone(),
                        data: encoded,
                    };
                    // 非阻塞发送
                    let _ = msg_tx.try_send(msg);
                }
            };

            // 关闭回调
            let close_callback = {
                let msg_tx = msg_tx_clone;
                let session_id = session_id_clone;
                move |_sid: String, reason: String, exit_code: Option<i32>| {
                    let msg = AgentMessage::TerminalClosed {
                        session_id,
                        reason,
                        exit_code,
                    };
                    let _ = msg_tx.try_send(msg);
                }
            };

            match session_manager
                .create_session(
                    session_id.clone(),
                    cols,
                    rows,
                    shell,
                    output_callback,
                    close_callback,
                )
                .await
            {
                Ok(()) => {
                    let msg = AgentMessage::TerminalCreated {
                        session_id: session_id.clone(),
                    };
                    let _ = msg_tx.send(msg).await;
                }
                Err(e) => {
                    error!("[Agent] Failed to create terminal: {}", e);
                    let msg = AgentMessage::Error {
                        session_id: Some(session_id),
                        code: "CREATE_FAILED".to_string(),
                        message: e,
                    };
                    let _ = msg_tx.send(msg).await;
                }
            }
        }

        ServerMessage::TerminalInput { session_id, data } => {
            // 解码 base64 数据
            match BASE64.decode(&data) {
                Ok(decoded) => {
                    if let Err(e) = session_manager.send_input(&session_id, decoded).await {
                        warn!("[Agent] Failed to send input to {}: {}", session_id, e);
                    }
                }
                Err(e) => {
                    warn!("[Agent] Invalid base64 input data: {}", e);
                }
            }
        }

        ServerMessage::TerminalResize {
            session_id,
            cols,
            rows,
        } => {
            if let Err(e) = session_manager.resize_session(&session_id, cols, rows) {
                warn!("[Agent] Failed to resize {}: {}", session_id, e);
            }
        }

        ServerMessage::CloseTerminal { session_id } => {
            info!("[Agent] Closing terminal session: {}", session_id);
            if let Err(e) = session_manager.close_session(&session_id) {
                warn!("[Agent] Failed to close {}: {}", session_id, e);
            }
        }

        ServerMessage::AuthResult { .. } => {
            // 认证结果在 wait_for_auth 中处理，这里忽略
        }
    }

    Ok(())
}
