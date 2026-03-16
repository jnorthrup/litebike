//! LiteBike - Self-standing light proxy foundation
//!
//! litebike owns:
//! - Port-8888 dynamic protocol sharing (special8888)
//! - KnoxProxyConfig (proxy_config)
//! - POSIX socket utilities (posix_sockets)
//! - Gate-based protocol routing (gates)
//! - Channel management (channel)
//! - Integrated proxy server (integrated_proxy)
//! - agent_8888 listener (gated combinator precompiled)
//! - I/O substrate for Linux I/O emulation (io_substrate)

pub mod agent_8888;
pub mod agents;
pub mod channel;
pub mod dsel;
pub mod gates;
pub mod integrated_proxy;
pub mod io_substrate;
pub mod knox_proxy;
pub mod proxy_config;
pub mod syscall_net;
pub mod tethering_bypass;

// Re-export from agents
pub use agents::model_hierarchy::{ModelHierarchy, ModelNode, ProviderConfig};
pub use agents::web_tools::{WebSearchRequest, WebSearchResult, WebTools};

// Local dsel functions (key discovery, provider status)
pub use dsel::{key, has_key, available, status, provider_quota_status};

// Re-export keymux and modelmux from literbike
pub use literbike::keymux::{ModelInfo, WebModelCard, ModelId, ModelCardStore, ModelFacade, ModelMapping};
pub use literbike::keymux::dsel::{DSELBuilder, route, all_provider_quotas, track_tokens};
pub use literbike::modelmux::{
    CachedModel, GatewayControlAction, GatewayControlState, GatewayRuntimeControl, ModelCache,
    ModelProxy, ModelRegistry, ProxyConfig, ToolbarAction, ToolbarState,
};



#[cfg(test)]
mod tests {
    use super::*;
    use crate::keymux::DSELBuilder;

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
