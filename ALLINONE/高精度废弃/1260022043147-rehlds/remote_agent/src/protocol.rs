//! WebSocket 消息协议定义
//!
//! Agent <-> Server 之间的通信协议

use serde::{Deserialize, Serialize};

/// Agent -> Server 消息
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentMessage {
    /// 认证请求（连接后首先发送）
    #[serde(rename = "auth")]
    Auth {
        /// 认证密钥
        key: String,
        /// 服务器显示名称
        hostname: String,
        /// Agent 版本
        version: String,
    },
    
    /// 心跳
    #[serde(rename = "heartbeat")]
    Heartbeat {
        /// 当前活跃的终端会话数
        active_sessions: u32,
        /// Agent 运行时间（秒）
        uptime_secs: u64,
    },
    
    /// 终端输出数据
    #[serde(rename = "terminal_output")]
    TerminalOutput {
        /// 会话 ID
        session_id: String,
        /// 输出数据（base64 编码，支持二进制）
        data: String,
    },
    
    /// 终端会话已关闭
    #[serde(rename = "terminal_closed")]
    TerminalClosed {
        /// 会话 ID
        session_id: String,
        /// 关闭原因
        reason: String,
        /// 退出码（如果有）
        exit_code: Option<i32>,
    },
    
    /// 终端会话创建成功
    #[serde(rename = "terminal_created")]
    TerminalCreated {
        /// 会话 ID
        session_id: String,
    },
    
    /// 错误消息
    #[serde(rename = "error")]
    Error {
        /// 相关会话 ID（如果有）
        session_id: Option<String>,
        /// 错误码
        code: String,
        /// 错误描述
        message: String,
    },
}

/// Server -> Agent 消息
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// 认证结果
    #[serde(rename = "auth_result")]
    AuthResult {
        /// 是否成功
        success: bool,
        /// 消息
        message: String,
        /// 分配的 Agent ID（成功时）
        agent_id: Option<String>,
    },
    
    /// 心跳响应
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck,
    
    /// 创建终端会话请求
    #[serde(rename = "create_terminal")]
    CreateTerminal {
        /// 会话 ID（由 Server 分配）
        session_id: String,
        /// 终端列数
        cols: u16,
        /// 终端行数
        rows: u16,
        /// 要执行的 shell（可选，默认 /bin/bash）
        shell: Option<String>,
    },
    
    /// 终端输入数据
    #[serde(rename = "terminal_input")]
    TerminalInput {
        /// 会话 ID
        session_id: String,
        /// 输入数据（base64 编码）
        data: String,
    },
    
    /// 调整终端大小
    #[serde(rename = "terminal_resize")]
    TerminalResize {
        /// 会话 ID
        session_id: String,
        /// 新的列数
        cols: u16,
        /// 新的行数
        rows: u16,
    },
    
    /// 关闭终端会话
    #[serde(rename = "close_terminal")]
    CloseTerminal {
        /// 会话 ID
        session_id: String,
    },
}

impl AgentMessage {
    /// 序列化为 JSON 字符串
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl ServerMessage {
    /// 从 JSON 字符串解析
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Agent 版本号
pub const AGENT_VERSION: &str = "1.0.0";
