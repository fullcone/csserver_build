//! Agent 配置模块

/// Agent 配置
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// 中控服务器 WebSocket URL (例如: wss://server.example.com/agent)
    pub server_url: String,
    
    /// 认证密钥
    pub auth_key: String,
    
    /// 服务器显示名称（用于在 Web 界面显示）
    pub hostname: String,
    
    /// 重连间隔（秒）
    pub reconnect_interval_secs: u64,
    
    /// 心跳间隔（秒）
    pub heartbeat_interval_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            auth_key: String::new(),
            hostname: "Unknown Server".to_string(),
            reconnect_interval_secs: 5,
            heartbeat_interval_secs: 30,
        }
    }
}

impl AgentConfig {
    /// 验证配置是否有效
    pub fn is_valid(&self) -> bool {
        !self.server_url.is_empty() && !self.auth_key.is_empty()
    }
    
    /// 获取重连间隔 Duration
    pub fn reconnect_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.reconnect_interval_secs)
    }
    
    /// 获取心跳间隔 Duration
    pub fn heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.heartbeat_interval_secs)
    }
}
