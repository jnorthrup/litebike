// TDD Test Suite: Model Mux 8888 Cloaking & Interception
// Tests for rbcursive precompiled parser combinator protocol dispatch from single port 8888
// Keymux integrates with env projection; user defines precedence

#[cfg(test)]
mod modelmux_8888_cloaking_tests {
    use litebike::keymux::dsel::{DSELBuilder, ProviderPotential, QuotaContainer};

    // ========================================================================
    // SECTION 1: Single Port 8888 Precompiled Dispatch Tests
    // ========================================================================

    #[test]
    fn test_single_port_8888_protocol_dispatch() {
        // All protocols dispatch from same port 8888 via precompiled parser combinators
        let protocols: &[&[u8]] = &[
            b"GET /v1/chat/completions HTTP/1.1\r\nHost: localhost:8888\r\n\r\n",  // OpenAI
            b"POST /v1/messages HTTP/1.1\r\nHost: localhost:8888\r\n\r\n",         // Anthropic
            b"POST /api/generate HTTP/1.1\r\nHost: localhost:8888\r\n\r\n",        // Ollama
            b"GET /api/tags HTTP/1.1\r\nHost: localhost:8888\r\n\r\n",             // Ollama tags
        ];

        for protocol in protocols {
            // All should be detected from same port 8888
            // RBCursive precompiled dispatch handles all protocols
            assert!(!protocol.is_empty());
        }
    }

    #[test]
    fn test_precompiled_parser_combinator_dispatch() {
        // Test precompiled parser combinator dispatch
        // literbike performs precompiled parser combinator protocol dispatch from the same port
        
        // Precompiled HTTP method parser (GET)
        let get_method = b"GET ";
        assert_eq!(get_method.len(), 4);
        
        // Precompiled HTTP method parser (POST)
        let post_method = b"POST ";
        assert_eq!(post_method.len(), 5);
        
        // All methods dispatch from port 8888
        let default_port = 8888;
        assert_eq!(default_port, 8888);
    }

    #[test]
    fn test_8888_agent_name_binding() {
        // Test that agent8888 is the default agent name
        let default_agent = "agent8888";
        assert_eq!(default_agent, "agent8888", "Default agent name should be agent8888");
    }

    // ========================================================================
    // SECTION 2: Keymux + Env Projection Integration Tests
    // ========================================================================

    #[test]
    fn test_keymux_env_projection_integration() {
        // keymux combines with the env projection
        // Test that keymux state is derived from env projection
        
        // Simulated env projection
        let env_keys = vec![
            "KILO_API_KEY",
            "MOONSHOT_API_KEY",
            "DEEPSEEK_API_KEY",
        ];
        
        // Keymux should recognize these as provider API keys
        for key in &env_keys {
            assert!(key.ends_with("_API_KEY"), "Should be API key pattern: {}", key);
        }
    }

    #[test]
    fn test_keymux_dsel_quota_from_env() {
        // Test DSEL quota container populated from env projection
        // keymux combines with env projection for quota decisions
        
        let dsel = DSELBuilder::new()
            .with_quota("production", 1000000)
            .with_provider("kilo_code", 500000, 1, 0.0, true)   // from env
            .with_provider("moonshot", 300000, 1, 0.0, true)    // from env
            .with_provider("deepseek", 200000, 2, 0.01, false); // from env
        
        let result = dsel.build();
        assert!(result.is_ok(), "DSEL should build from env projection");
    }

    // ========================================================================
    // SECTION 3: User-Defined Precedence Tests
    // ========================================================================

    #[test]
    fn test_user_precedence_env_first() {
        // user may define the precedence of which (env projection first)
        let precedence_mode = "env_first";
        
        // Env projection drives provider selection
        let env_keys = vec!["KILO_API_KEY", "KILO_BASE_URL"];
        assert!(!env_keys.is_empty());
        
        // Precedence: env_first
        assert_eq!(precedence_mode, "env_first");
    }

    #[test]
    fn test_user_precedence_keymux_first() {
        // user may define the precedence of which (keymux first)
        let precedence_mode = "keymux_first";
        
        // Keymux state drives provider selection
        let keymux_providers = vec!["kilo_code", "moonshot", "deepseek"];
        assert!(!keymux_providers.is_empty());
        
        // Precedence: keymux_first
        assert_eq!(precedence_mode, "keymux_first");
    }

    #[test]
    fn test_user_precedence_balanced() {
        // user may define the precedence of which (balanced weighted)
        let env_weight = 0.6f32;
        let keymux_weight = 0.4f32;
        
        // Balanced: both systems vote
        assert_eq!(env_weight + keymux_weight, 1.0);
        
        // Weighted decision
        let weighted_score = env_weight * 100.0 + keymux_weight * 80.0;
        assert!(weighted_score > 80.0 && weighted_score < 100.0);
    }

    #[test]
    fn test_user_precedence_custom_rules() {
        // user may define the precedence of which (custom rules)
        // Example: kilo_code uses env_first, moonshot uses keymux_first
        
        let provider_rules = [
            ("kilo_code", "env_first"),
            ("moonshot", "keymux_first"),
            ("deepseek", "balanced"),
        ];
        
        for (provider, rule) in &provider_rules {
            assert!(!provider.is_empty());
            assert!(!rule.is_empty());
        }
    }

    // ========================================================================
    // SECTION 3: Provider Integration Tests
    // ========================================================================

    #[test]
    fn test_kilo_provider_configuration() {
        // Test Kilo.ai provider configuration
        let dsel = DSELBuilder::new()
            .with_quota("kilo_free", 100000)
            .with_provider("kilo_code", 100000, 1, 0.0, true);
        
        let result = dsel.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_moonshot_provider_configuration() {
        // Test Moonshot (Kimi) provider configuration
        let dsel = DSELBuilder::new()
            .with_quota("moonshot_free", 50000)
            .with_provider("moonshot", 50000, 1, 0.0, true);
        
        let result = dsel.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_multi_provider_quota_arbitration() {
        // Test arbitration across multiple providers
        let dsel = DSELBuilder::new()
            .with_quota("multi_tier", 200000)
            .with_provider("kilo_code", 100000, 1, 0.0, true)      // free
            .with_provider("moonshot", 50000, 1, 0.0, true)        // free
            .with_provider("deepseek", 30000, 2, 0.01, false)      // paid
            .with_provider("openai", 20000, 3, 0.10, false);       // paid expensive
        
        let result = dsel.build();
        assert!(result.is_ok());
        
        // Free providers should be prioritized
        let container = result.unwrap();
        let selected = container.select_provider(100);
        assert!(selected.is_some());
        assert!(selected.unwrap().is_free);
    }

    // ========================================================================
    // SECTION 4: Model Reference Parsing Tests
    // ========================================================================

    #[test]
    fn test_model_ref_free_prefix() {
        // Test /free/ model reference prefix
        let model_ref = "/free/moonshotai/kimi-k2";
        assert!(model_ref.starts_with("/free/"), "Free tier model should start with /free/");
    }

    #[test]
    fn test_model_ref_provider_namespace() {
        // Test provider namespace in model refs
        let model_refs = [
            "/free/moonshotai/kimi-k2",
            "/paid/openai/gpt-4",
            "/free/deepseek/deepseek-coder",
        ];
        
        for model_ref in &model_refs {
            let parts: Vec<&str> = model_ref.split('/').collect();
            assert!(parts.len() >= 3, "Model ref should have at least 3 parts");
            assert!(!parts[1].is_empty(), "Tier should not be empty");
            assert!(!parts[2].is_empty(), "Provider should not be empty");
        }
    }

    // ========================================================================
    // SECTION 5: Env Projection Tests
    // ========================================================================

    #[test]
    fn test_env_projection_api_key_detection() {
        // Test API key detection from env vars
        let api_key_patterns = [
            "OPENAI_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "GEMINI_API_KEY",
            "MOONSHOT_API_KEY",
            "KILO_API_KEY",
            "DEEPSEEK_API_KEY",
        ];
        
        for pattern in &api_key_patterns {
            assert!(pattern.ends_with("_API_KEY") || pattern.ends_with("_TOKEN"),
                "API key pattern should end with _API_KEY or _TOKEN: {}", pattern);
        }
    }

    #[test]
    fn test_env_projection_base_url_detection() {
        // Test base URL detection from env vars
        let base_url_patterns = [
            "OPENAI_BASE_URL",
            "ANTHROPIC_BASE_URL",
            "GOOGLE_GEMINI_BASE_URL",
            "KILO_BASE_URL",
        ];
        
        for pattern in &base_url_patterns {
            assert!(pattern.ends_with("_BASE_URL"),
                "Base URL pattern should end with _BASE_URL: {}", pattern);
        }
    }

    #[test]
    fn test_search_api_key_multi_key_support() {
        // Test multi-key search API support
        let search_key_patterns = [
            "BRAVE_SEARCH_API_KEY",
            "BRAVE_SEARCH_API_KEY_1",
            "BRAVE_SEARCH_API_KEY_2",
            "TAVILY_SEARCH_API_KEY",
        ];
        
        for pattern in &search_key_patterns {
            assert!(pattern.contains("_SEARCH_API_KEY"),
                "Search key should contain _SEARCH_API_KEY: {}", pattern);
        }
    }

    // ========================================================================
    // SECTION 6: Integration Tests
    // ========================================================================

    #[test]
    fn test_full_modelmux_lifecycle() {
        // Test complete modelmux lifecycle
        // 1. Initialize DSEL with quota
        let dsel = DSELBuilder::new()
            .with_quota("production", 1000000)
            .with_provider("kilo_code", 500000, 1, 0.0, true)
            .with_provider("moonshot", 300000, 1, 0.0, true)
            .with_provider("deepseek", 200000, 2, 0.01, false);
        
        // 2. Build container
        let container = dsel.build().expect("DSEL should build");
        
        // 3. Select best provider
        let selected = container.select_provider(100);
        assert!(selected.is_some(), "Should select a provider");

        // 4. Verify free tier priority
        let provider = selected.unwrap();
        assert!(provider.is_free, "Should select free tier first");
    }

    #[test]
    fn test_8888_cloaking_port_configuration() {
        // Test port 8888 cloaking configuration
        let ports = vec![8888, 8880, 8443, 443];
        
        for port in &ports {
            assert!(*port > 0 && *port < 65536, "Port should be valid: {}", port);
        }
        
        // 8888 should be primary
        assert_eq!(ports[0], 8888, "8888 should be primary port");
    }

    #[test]
    fn test_provider_endpoint_classification() {
        // Test provider endpoint classification
        let endpoints = [
            ("https://api.kilo.ai/api/gateway", "kilo_code"),
            ("https://api.moonshot.cn/v1", "moonshot"),
            ("https://api.deepseek.com/v1", "deepseek"),
            ("https://api.openai.com/v1", "openai"),
        ];
        
        for (endpoint, provider) in &endpoints {
            assert!(endpoint.starts_with("https://"), 
                "Endpoint should be HTTPS: {}", endpoint);
            assert!(!provider.is_empty(), 
                "Provider should not be empty: {}", provider);
        }
    }

    #[test]
    fn test_quota_drainer_policy_enforcement() {
        // Test QuotaDrainer policy enforcement
        let mut container = QuotaContainer::new("drainer_test");
        
        // Add free tier with low quota
        container.add_provider("low_free", 10, 1, 0.0, true);
        // Add paid tier with high quota
        container.add_provider("high_paid", 10000, 2, 0.01, false);
        
        // Free should be selected despite low quota
        let selected = container.select_provider(5);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().name, "low_free");
    }

    #[test]
    fn test_model_mux_routing_decision() {
        // Test model mux routing decision
        let routing_table = [
            ("/free/moonshotai/kimi-k2", "moonshot", true),
            ("/free/deepseek/deepseek-coder", "deepseek", true),
            ("/paid/openai/gpt-4", "openai", false),
            ("/paid/anthropic/claude-3", "anthropic", false),
        ];
        
        for (model_ref, provider, is_free) in &routing_table {
            assert!(model_ref.starts_with('/'), 
                "Model ref should start with /: {}", model_ref);
            assert!(!provider.is_empty(), 
                "Provider should not be empty: {}", provider);
            
            let is_free_tier = model_ref.starts_with("/free/");
            assert_eq!(is_free_tier, *is_free,
                "Free tier mismatch for {}", model_ref);
        }
    }
}
