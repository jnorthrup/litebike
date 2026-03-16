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
//! - Protocol detection and SIMD combinators (protocol_detector, rbcursive)
//! - Samsung Note 20 5G platform features (note20_features)

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

// Protocol detection and routing
pub mod protocol_detector;
pub mod patricia_detector_simd;
#[cfg(target_arch = "aarch64")]
pub mod patricia_detector_simd_arm64;
pub mod combinator_dsl;
#[cfg(feature = "static-generation")]
pub mod static_generation;
#[cfg(feature = "static-generation")]
pub mod jump_table_generation;
pub mod n_dimensional_inference;
pub mod fixed_range_constraints;
pub mod autovec_optimization;
pub mod pac;
pub mod bonjour;
pub mod upnp;
pub mod auto_discovery;
pub mod types;
pub mod note20_features;
pub mod unified_handler;
pub mod universal_listener;
pub mod protocol_registry;
pub mod protocol_handlers;
pub mod simple_routing;
pub mod unified_protocol_manager;
pub mod posix_sockets;
// RBCursive - Network parser combinators with SIMD acceleration
pub mod rbcursive;
// Testing and mock modules
pub mod protocol_mocks;
pub mod simple_torture_test;
pub mod abstractions;
pub mod stubs;

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
        let hierarchy = ModelHierarchy::new();
        assert!(hierarchy.roots.len() > 0);

        let dsel = DSELBuilder::new()
            .with_quota("test_quota", 1000)
            .with_provider("openai", 500, 1, 20.0, false)
            .with_provider("anthropic", 300, 2, 30.0, false);

        assert!(dsel.build().is_ok());
    }
}
