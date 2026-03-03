//! Tests for hierarchical prefix handling in DSEL
//! These tests validate prefix transformation and hierarchical model ID processing.

use litebike::keymux::dsel::{
    DSELBuilder, HierarchicalModelProcessor, HierarchicalModelSelector, PrefixTransformation,
    QuotaContainer, ProviderPotential,
};

#[test]
fn test_dsel_builder_with_rule_engine_integration() {
    // Test the integration of prefix handling with DSEL quota management
    let rule_engine = DSELBuilder::new()
        .with_quota("test-quota", 5000)
        .with_provider("litellm", 2000, 1, 20.0, false)
        .with_provider("openai", 1500, 2, 30.0, false)
        .with_provider("anthropic", 1500, 3, 40.0, false)
        .with_prefix_transformation("/litellm/litellm/litellm/", "/litellm/")
        .with_prefix_transformation("/openai/openai/openai/", "/openai/")
        .build_with_rule_engine()
        .expect("Failed to build rule engine");

    // Verify token ledger is enabled
    // Note: We can't directly check private fields, but we can test the functionality

    // Create providers for testing
    let providers = vec![
        ProviderPotential::new("litellm", 2000, 1, 20.0, false),
        ProviderPotential::new("openai", 1500, 2, 30.0, false),
        ProviderPotential::new("anthropic", 1500, 3, 40.0, false),
    ];

    // Test provider selection with hierarchical model ID transformation
    // This validates that prefix handling is integrated with quota management
    let selected = rule_engine.select_provider(
        &providers,
        100,
        Some("/litellm/litellm/litellm/gpt-4"),
    );

    assert!(selected.is_some(), "Should find a provider for the hierarchical model ID");
    // The transformed model ID should match litellm provider
    assert_eq!(selected.unwrap().name, "litellm");
}

#[test]
fn test_dsel_builder_with_hierarchical_selector() {
    // Test building with hierarchical selector directly
    let (container, selector) = DSELBuilder::new()
        .with_quota("test-quota", 3000)
        .with_provider("litellm", 1000, 1, 20.0, false)
        .with_provider("openai", 1000, 2, 30.0, false)
        .with_provider("anthropic", 1000, 3, 40.0, false)
        .with_prefix_transformation("/litellm/litellm/litellm/", "/litellm/")
        .build_with_hierarchical_selector()
        .expect("Failed to build with hierarchical selector");

    // Verify container has providers
    assert_eq!(container.providers.len(), 3);

    // Verify selector can transform model IDs
    let mut selector = selector;
    let transformed = selector.transform_model_id("/litellm/litellm/litellm/gpt-4");
    assert_eq!(transformed, "/litellm/gpt-4");
}

#[test]
fn test_prefix_transformation_with_quota_aware_selection() {
    // Test that prefix transformations work correctly with quota-aware selection
    let rule_engine = DSELBuilder::new()
        .with_quota("high-priority", 500)
        .with_provider("litellm", 200, 1, 20.0, false)
        .with_provider("openai", 300, 2, 30.0, false)
        .with_prefix_transformation("/litellm/litellm/litellm/", "/litellm/")
        .build_with_rule_engine()
        .expect("Failed to build rule engine");

    let providers = vec![
        ProviderPotential::new("litellm", 200, 1, 20.0, false),
        ProviderPotential::new("openai", 300, 2, 30.0, false),
    ];

    // Test selecting provider with transformed hierarchical ID
    let selected = rule_engine.select_provider(
        &providers,
        50,
        Some("/litellm/litellm/litellm/gpt-4"),
    );

    assert!(selected.is_some());
    // litellm should be selected (higher priority)
    assert_eq!(selected.unwrap().name, "litellm");

    // Track token usage
    let mut rule_engine = rule_engine;
    rule_engine.track_token_usage("litellm", 50).unwrap();

    // Verify quota tracking works
    let has_quota = rule_engine.has_sufficient_quota("litellm", 100);
    assert!(has_quota, "Should have sufficient quota after tracking");
}

#[test]
fn test_simple_prefix_transformation() {
    let mut processor = HierarchicalModelProcessor::new();

    // Add transformation rules
    processor.add_transformation(r"^/litellm/litellm/litellm/(.+)$", "/litellm/$1");
    processor.add_transformation(r"^/ccswitch/ccswitch/ccswitch/(.+)$", "/ccswitch/$1");

    // Test transformations
    let (provider, model) = processor.process_model_id("/litellm/litellm/litellm/gpt-4");
    assert_eq!(provider, "litellm");
    assert_eq!(model, "gpt-4");

    let (provider, model) = processor.process_model_id("/ccswitch/ccswitch/ccswitch/claude-3-opus");
    assert_eq!(provider, "ccswitch");
    assert_eq!(model, "claude-3-opus");
}

#[test]
fn test_nested_prefix_transformation() {
    let mut processor = HierarchicalModelProcessor::new();

    // Add specific transformation rules (more reliable than generic patterns)
    processor.add_transformation(r"^/openai/openai/openai/(.+)$", "/openai/$1");
    processor.add_transformation(r"^/anthropic/anthropic/anthropic/(.+)$", "/anthropic/$1");
    processor.add_transformation(r"^/(.+)/\1/\1/(.+)$", "/$1/$2");

    // Test nested transformations
    let (provider, model) = processor.process_model_id("/openai/openai/openai/gpt-4");
    assert_eq!(provider, "openai");
    assert_eq!(model, "gpt-4");

    let (provider, model) =
        processor.process_model_id("/anthropic/anthropic/anthropic/claude-3-opus");
    assert_eq!(provider, "anthropic");
    assert_eq!(model, "claude-3-opus");
}

#[test]
fn test_provider_alias_mapping() {
    let mut processor = HierarchicalModelProcessor::new();

    // Add provider mappings with aliases
    processor.add_provider_mapping("openai", vec!["openai", "oa", "gpt"]);
    processor.add_provider_mapping("anthropic", vec!["anthropic", "claude", "ant"]);

    // Test alias resolution
    let (provider, model) = processor.process_model_id("/oa/gpt-4");
    assert_eq!(provider, "openai");
    assert_eq!(model, "gpt-4");

    let (provider, model) = processor.process_model_id("/claude/claude-3-opus");
    assert_eq!(provider, "anthropic");
    assert_eq!(model, "claude-3-opus");
}

#[test]
fn test_best_provider_approximation() {
    let mut processor = HierarchicalModelProcessor::new();

    // Setup transformations
    processor.add_transformation(r"^/litellm/litellm/litellm/(.+)$", "/litellm/$1");
    processor.add_provider_mapping("openai", vec!["openai", "gpt"]);

    let available_providers = vec!["openai", "litellm", "anthropic"];

    // Test finding best approximation
    let best = processor
        .find_best_provider_approximation("/litellm/litellm/litellm/gpt-4", &available_providers);
    assert_eq!(best, Some("litellm".to_string()));

    let best = processor.find_best_provider_approximation("/gpt/gpt-4", &available_providers);
    assert_eq!(best, Some("openai".to_string()));
}

#[test]
fn test_hierarchical_model_selector() {
    use litebike::keymux::dsel::{ProviderPotential, QuotaContainer};

    let mut container = QuotaContainer::new("test");
    container.add_provider("litellm", 1000, 1, 20.0, false);
    container.add_provider("openai", 800, 2, 30.0, false);
    container.add_provider("anthropic", 600, 3, 40.0, false);

    let mut selector = HierarchicalModelSelector::new(container);

    // Add transformation rules
    selector.add_transformation_rule("/litellm/litellm/litellm/", "/litellm/", 100);
    selector.add_transformation_rule("/ccswitch/ccswitch/ccswitch/", "/ccswitch/", 90);
    selector.add_transformation_rule("/openai/openai/openai/", "/openai/", 80);

    // Test prefix transformation
    let transformed = selector.transform_model_id("/litellm/litellm/litellm/gpt-4");
    assert_eq!(transformed, "/litellm/gpt-4");

    // Test best approximation selection
    let provider = selector.select_best_approximation("/litellm/litellm/litellm/gpt-4");
    assert!(provider.is_some());
    assert_eq!(provider.unwrap().name, "litellm");
}

#[test]
fn test_complex_hierarchical_transformations() {
    let selector = HierarchicalModelSelector::new(QuotaContainer::new("test"));

    // Test complex transformations
    let transformations = selector.handle_complex_transformations("/litellm/litellm/litellm/gpt-4");
    assert!(transformations.contains(&"/litellm/gpt-4".to_string()));

    let transformations =
        selector.handle_complex_transformations("/ccswitch/ccswitch/ccswitch/claude-3-opus");
    assert!(transformations.contains(&"/ccswitch/claude-3-opus".to_string()));

    let transformations = selector.handle_complex_transformations("/openai/openai/openai/gpt-4");
    assert!(transformations.contains(&"/openai/gpt-4".to_string()));
}

#[test]
fn test_prefix_cache() {
    let mut container = QuotaContainer::new("test");
    container.add_provider("litellm", 1000, 1, 20.0, false);

    let mut selector = HierarchicalModelSelector::new(container);
    selector.add_transformation_rule("/litellm/litellm/litellm/", "/litellm/", 100);

    // First transformation should be computed
    let first = selector.transform_model_id("/litellm/litellm/litellm/gpt-4");
    assert_eq!(first, "/litellm/gpt-4");

    // Second transformation should use cache
    let second = selector.transform_model_id("/litellm/litellm/litellm/gpt-4");
    assert_eq!(second, "/litellm/gpt-4");

    // They should be the same
    assert_eq!(first, second);
}

#[test]
fn test_rule_engine_with_hierarchical_selector() {
    use litebike::keymux::dsel::{ProviderPotential, QuotaContainer};
    use litebike::keymux::dsel::{ProviderSelectionRule, RuleEngine};

    let mut container = QuotaContainer::new("test");
    container.add_provider("litellm", 1000, 1, 20.0, false);
    container.add_provider("openai", 800, 2, 30.0, false);

    let mut selector = HierarchicalModelSelector::new(container);
    selector.add_transformation_rule("/litellm/litellm/litellm/", "/litellm/", 100);

    let mut rule_engine = RuleEngine::new();
    rule_engine.set_hierarchical_selector(selector);

    // Create providers list
    let providers = vec![
        ProviderPotential::new("litellm", 1000, 1, 20.0, false),
        ProviderPotential::new("openai", 800, 2, 30.0, false),
    ];

    // Test hierarchical model ID selection
    let selected =
        rule_engine.select_provider_enhanced(&providers, "/litellm/litellm/litellm/gpt-4", 100);

    assert!(selected.is_some());
    assert_eq!(selected.unwrap().name, "litellm");
}

#[test]
fn test_malformed_hierarchical_ids() {
    let processor = HierarchicalModelProcessor::new();

    // Test malformed IDs
    let (provider, model) = processor.process_model_id("just-gpt-4");
    assert_eq!(provider, "unknown");
    assert_eq!(model, "just-gpt-4");

    let (provider, model) = processor.process_model_id("/single/provider");
    assert_eq!(provider, "single");
    assert_eq!(model, "provider");

    let (provider, model) = processor.process_model_id("//double//slash//model");
    assert_eq!(provider, "double");
    assert_eq!(model, "slash/model");
}

#[test]
fn test_prefix_transformation_priority() {
    let mut container = QuotaContainer::new("test");
    container.add_provider("litellm", 1000, 1, 20.0, false);

    let mut selector = HierarchicalModelSelector::new(container);

    // Add rules with different priorities
    selector.add_transformation_rule("/litellm/litellm/litellm/", "/litellm/", 100); // Higher priority
    selector.add_transformation_rule("/litellm/", "/litellm/", 50); // Lower priority

    // Should use higher priority rule
    let transformed = selector.transform_model_id("/litellm/litellm/litellm/gpt-4");
    assert_eq!(transformed, "/litellm/gpt-4");

    // Should not double-transform
    let transformed = selector.transform_model_id("/litellm/gpt-4");
    assert_eq!(transformed, "/litellm/gpt-4");
}

#[test]
fn test_real_world_examples() {
    let mut processor = HierarchicalModelProcessor::new();

    // Add real-world transformations
    processor.add_transformation(r"^/litellm/litellm/litellm/(.+)$", "/litellm/$1");
    processor.add_transformation(r"^/ccswitch/ccswitch/ccswitch/(.+)$", "/ccswitch/$1");
    processor.add_transformation(r"^/openai/openai/openai/(.+)$", "/openai/$1");
    processor.add_transformation(r"^/anthropic/anthropic/anthropic/(.+)$", "/anthropic/$1");

    // Test real-world examples
    let examples = vec![
        ("/litellm/litellm/litellm/gpt-4", ("litellm", "gpt-4")),
        (
            "/ccswitch/ccswitch/ccswitch/claude-3-opus",
            ("ccswitch", "claude-3-opus"),
        ),
        (
            "/openai/openai/openai/gpt-4-turbo",
            ("openai", "gpt-4-turbo"),
        ),
        (
            "/anthropic/anthropic/anthropic/claude-3-haiku",
            ("anthropic", "claude-3-haiku"),
        ),
        ("/litellm/gpt-4", ("litellm", "gpt-4")),
        ("/gpt-4", ("unknown", "gpt-4")),
    ];

    for (input, expected) in examples {
        let (provider, model) = processor.process_model_id(input);
        assert_eq!(
            (provider.as_str(), model.as_str()),
            expected,
            "Failed for input: {}",
            input
        );
    }
}
