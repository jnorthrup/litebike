//! LiteBike - Self-standing light proxy foundation
//!
//! litebike owns:
//! - Port-8888 dynamic protocol sharing (special8888)
//! - KnoxProxyConfig (proxy_config)
//! - POSIX socket utilities (posix_sockets)
//! - Gate-based protocol routing (gates)
//! - Channel management (channel)
//! - Integrated proxy server (integrated_proxy)

pub mod proxy_config;
pub mod agent_8888;
pub mod posix_sockets;
pub mod channel;
pub mod gates;
pub mod integrated_proxy;

pub use proxy_config::KnoxProxyConfig;
pub use agent_8888::{Special8888Listener, ProtocolDetection, DEFAULT_PORT};
pub use integrated_proxy::{IntegratedProxyServer, IntegratedProxyConfig, IntegratedProxyStats};
pub use channel::{ChannelManager, ChannelType};
pub use gates::{LitebikeGateController, GateInfo};

/// LiteBike integrated proxy facade for simple usage
pub struct LiteBike {
    proxy_server: IntegratedProxyServer,
}

impl LiteBike {
    /// Create new LiteBike instance with default configuration
    pub fn new() -> Self {
        let config = IntegratedProxyConfig::default();
        Self {
            proxy_server: IntegratedProxyServer::new(config),
        }
    }

    /// Create new LiteBike instance with custom configuration
    pub fn with_config(config: IntegratedProxyConfig) -> Self {
        Self {
            proxy_server: IntegratedProxyServer::new(config),
        }
    }

    /// Start the LiteBike proxy server
    pub async fn start(self) -> Result<(), integrated_proxy::IntegratedProxyError> {
        self.proxy_server.start().await
    }

    /// Get proxy server statistics
    pub async fn stats(&self) -> IntegratedProxyStats {
        self.proxy_server.get_stats().await
    }
}

impl Default for LiteBike {
    fn default() -> Self {
        Self::new()
    }
}
