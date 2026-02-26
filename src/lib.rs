// LiteBike Agent System
// Claude bot with web search and JSON capabilities

pub mod model_hierarchy;
pub mod mod;  // mod.rs
pub mod web_tools;

pub use model_hierarchy::{ModelHierarchy, ModelNode, ProviderConfig};
pub use mod::{AgentConfig, AgentModelConfig, AgentRuntime, GatewayConfig, SecurityConfig, ProviderConfigs, WebToolConfig, WebSearchProvider};
pub use web_tools::{WebSearchRequest, WebSearchResult, JsonToolConfig, WebSearchProvider as WebToolProvider, WebTools};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_agent_system() {
        use std::env;

        // Set test environment variables
        env::set_var("NVIDIA_API_KEY", "test-nvidia-key");
        env::set_var("GROQ_API_KEY", "test-groq-key");
        env::set_var("OPENROUTER_API_KEY", "test-openrouter-key");
        env::set_var("BRAVE_SEARCH_API_KEY", "test-brave-key");

        let hierarchy = ModelHierarchy::new();
        let runtime = AgentRuntime::new_with_defaults("a2f43b129fff1fce1c8a243a4869518c09823b1e73bfa66b");

        // Test model selection
        let coding_model = hierarchy.select_model("coding");
        assert!(coding_model.is_some());

        // Test agent config generation
        let config = runtime.to_openclaw_config();
        assert!(config["agents"].is_object());
        assert!(config["gateway"].is_object());
        assert!(config["webTools"].is_object());

        // Test web tools
        let web_tools = WebTools::new();
        assert!(!web_tools.providers.is_empty());

        // Verify token matches
        assert_eq!(config["gateway"]["token"], "a2f43b129fff1fce1c8a243a4869518c09823b1e73bfa66b");
    }
}
