// LiteBike Agent System
// Claude bot with web search and JSON capabilities

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

#[cfg(test)]
mod tests {
    use super::*;

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
