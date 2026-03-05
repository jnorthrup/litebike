//! LiteBike - Self-standing light proxy foundation
//!
//! litebike owns:
//! - Port-8888 dynamic protocol sharing (special8888)
//! - KnoxProxyConfig (proxy_config)
//! - POSIX socket utilities (posix_sockets)
//! - Gate-based protocol routing (gates)
//! - Channel management (channel)
//! - Integrated proxy server (integrated_proxy)

pub mod agents;
pub mod gates;
pub mod integrated_proxy;
pub mod keymux;
pub mod knox_proxy;
pub mod syscall_net;
pub mod tethering_bypass;

// Re-export from agents
pub use agents::model_hierarchy::{ModelHierarchy, ModelNode, ProviderConfig};
pub use agents::web_tools::{WebSearchRequest, WebSearchResult, WebTools};
pub use keymux::{ModelInfo, WebModelCard, ModelId, ModelCardStore, ModelFacade, ModelMapping};
pub use keymux::dsel::{QuotaContainer, ProviderPotential, DSELBuilder, RuleEngine, ProviderSelectionRule};

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

    #[test]
    fn test_litebike_system() {
        // Test basic model hierarchy
        let hierarchy = ModelHierarchy::new();
        assert!(hierarchy.roots.len() > 0);

        // Test DSEL functionality
        let dsel = DSELBuilder::new()
            .with_quota("test_quota", 1000)
            .with_provider("openai", 500, 1, 20.0, false)
            .with_provider("anthropic", 300, 2, 30.0, false);

        assert!(dsel.build().is_ok());
    }
}
