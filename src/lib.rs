//! LiteBike - Embodied agent gateway with intelligent routing
//!
//! Built on literbike (betanet productive codebase rehomed) with:
//! - QUIC/h3 single UDP port
//! - Gate-based protocol routing
//! - CC-Cache integration for AI API spoofing
//! - Radio-aware egress

// Re-export core from literbike (DRY)
pub use literbike::{
    quic,
    rbcursive,
    syscall_net,
    gates as core_gates,
    radios,
    channel,
    config,
    types,
};

// LiteBike-specific extensions
pub mod gates;
pub mod integrated_proxy;

// Re-export key integrated components for easy access
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
