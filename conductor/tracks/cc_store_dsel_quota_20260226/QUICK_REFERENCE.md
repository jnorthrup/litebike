# CC-Store DSEL Quick Reference Guide

**Track:** `cc_store_dsel_quota_20260226`  
**Module:** `litebike::keymux::dsel`

---

## Quick Start

### 1. Basic Quota Container

```rust
use litebike::keymux::dsel::{QuotaContainer, ProviderPotential};

let mut container = QuotaContainer::new("production");

// Add providers
container.add_provider("openai", 1_000_000, 1, 20.0, false);
container.add_provider("anthropic", 500_000, 2, 30.0, false);

// Select provider for request
if let Some(provider) = container.select_provider(100_000) {
    println!("Selected: {} (priority: {})", provider.name, provider.priority);
}
```

### 2. DSEL Builder Pattern (Recommended)

```rust
use litebike::keymux::dsel::DSELBuilder;

// Simple container
let container = DSELBuilder::new()
    .with_quota("production", 2_000_000)
    .with_provider("openai", 1_000_000, 1, 20.0, false)
    .with_provider("anthropic", 500_000, 2, 30.0, false)
    .with_free_provider("kilo_code", 100_000, 3, 100_000, 3_000_000, 0)
    .build()?;

// Or build with full rule engine
let rule_engine = DSELBuilder::new()
    .with_quota("production", 2_000_000)
    .with_provider("litellm", 1_000_000, 1, 20.0, false)
    .with_prefix_transformation("/litellm/litellm/litellm/", "/litellm/")
    .build_with_rule_engine()?;
```

### 3. Hierarchical Prefix Handling

```rust
let (container, selector) = DSELBuilder::new()
    .with_quota("test", 1_000_000)
    .with_provider("litellm", 500_000, 1, 20.0, false)
    .with_provider("openai", 500_000, 2, 30.0, false)
    .with_prefix_transformation("/litellm/litellm/litellm/", "/litellm/")
    .build_with_hierarchical_selector()?;

// Transform malformed model ID
let mut selector = selector;
let transformed = selector.transform_model_id("/litellm/litellm/litellm/gpt-4");
// Result: "/litellm/gpt-4"

// Select provider for hierarchical ID
if let Some(provider) = selector.select_best_approximation("/litellm/litellm/litellm/gpt-4") {
    println!("Best match: {}", provider.name);
}
```

### 4. Token Usage Tracking

```rust
let mut rule_engine = DSELBuilder::new()
    .with_quota("production", 1_000_000)
    .with_provider("openai", 500_000, 1, 20.0, false)
    .build_with_rule_engine()?;

// Enable token ledger
rule_engine.enable_token_ledger();

// Track usage
rule_engine.track_token_usage("openai", 50_000)?;

// Check quota
if rule_engine.has_sufficient_quota("openai", 100_000) {
    println!("Has sufficient quota");
}

// Get quota status
if let Some((used_today, remaining, confidence)) = rule_engine.get_quota_status("openai") {
    println!("Used: {}, Remaining: {}, Confidence: {}", used_today, remaining, confidence);
}

// Reset usage (call hourly/daily)
rule_engine.reset_hourly_usage();
rule_engine.reset_daily_usage();
```

### 5. Provider Selection Rules

```rust
use litebike::keymux::dsel::{RuleEngine, ProviderSelectionRule};

let mut rule_engine = RuleEngine::new();

// Add selection rules
rule_engine.add_rule(
    ProviderSelectionRule::new("budget", 1)
        .with_max_tokens(500_000)
        .with_cost_threshold(10.0)
);

rule_engine.add_rule(
    ProviderSelectionRule::new("free_only", 2)
        .with_free_only()
);

// Select with rules
let providers = vec![/* ... */];
let selected = rule_engine.select_provider(&providers, 100_000, None);
```

### 6. Model Facade Integration

```rust
use litebike::keymux::facade::ModelFacade;
use litebike::keymux::cards::ModelCardStore;
use std::sync::Arc;

let card_store = Arc::new(ModelCardStore::new());
let mut facade = ModelFacade::new(card_store);

let active_providers = vec![
    "openai".to_string(),
    "anthropic".to_string(),
    "kilo_code".to_string(),
];

// Get quota-aware model list
let models = facade.handle_models(active_providers);

for model in models {
    println!("Model: {} (owned by: {})", model.id, model.owned_by);
}
```

---

## API Reference

### ProviderPotential

```rust
pub struct ProviderPotential {
    pub name: String,
    pub available_tokens: usize,
    pub priority: u8,          // Lower = higher priority
    pub cost_per_million: f64, // USD per million tokens
    pub is_free: bool,
    pub free_quota: Option<FreeQuotaConfig>,
    pub quota_timeframe: Option<QuotaTimeframe>,
    pub rate_limit: Option<RateLimitConfig>,
}
```

**Methods:**
- `calculate_cost(tokens: usize) -> f64` - Calculate cost for token count
- `can_handle(tokens: usize) -> bool` - Check if provider can handle request
- `get_priority_score() -> u8` - Get effective priority (free providers get bonus)
- `is_rate_limited(current_requests: u64, timeframe: &str) -> bool` - Check rate limits

### QuotaContainer

```rust
pub struct QuotaContainer {
    pub name: String,
    pub providers: HashMap<String, ProviderPotential>,
    pub total_quota: usize,
    pub used_quota: usize,
}
```

**Methods:**
- `new(name: &str) -> Self` - Create new container
- `add_provider(name, tokens, priority, cost, is_free)` - Add provider
- `add_free_provider(name, tokens, priority, daily, monthly, reset_hour)` - Add free provider
- `can_allocate(tokens: usize) -> bool` - Check if allocation possible
- `allocate(tokens: usize) -> Option<&ProviderPotential>` - Allocate tokens
- `select_provider(tokens: usize) -> Option<&ProviderPotential>` - Select without allocating
- `get_provider(name: &str) -> Option<&ProviderPotential>` - Get by name
- `get_providers_by_priority() -> Vec<&ProviderPotential>` - Get sorted by priority

### DSELBuilder

```rust
pub struct DSELBuilder;
```

**Builder Methods:**
- `new() -> Self` - Create new builder
- `with_quota(name: &str, total: usize) -> Self` - Set container name and quota
- `with_provider(name, tokens, priority, cost, is_free) -> Self` - Add provider
- `with_free_provider(name, tokens, priority, daily, monthly, reset_hour) -> Self` - Add free provider
- `with_timeframe_provider(name, tokens, priority, cost, timeframe, limit, reset) -> Self` - Add timeframe quota
- `with_rate_limited_provider(name, tokens, priority, cost, rpm, rph, rpd, burst) -> Self` - Add rate-limited provider
- `with_prefix_transformation(from: &str, to: &str) -> Self` - Add prefix transformation
- `build() -> Result<QuotaContainer, String>` - Build container
- `build_with_rule_engine() -> Result<RuleEngine, String>` - Build with full rule engine
- `build_with_hierarchical_selector() -> Result<(QuotaContainer, HierarchicalModelSelector), String>` - Build with selector

### HierarchicalModelSelector

```rust
pub struct HierarchicalModelSelector {
    // Handles prefix transformations for malformed model IDs
}
```

**Methods:**
- `new(base_selector: QuotaContainer) -> Self` - Create new selector
- `add_transformation_rule(pattern, replacement, priority)` - Add transformation rule
- `transform_model_id(model_id: &str) -> String` - Transform hierarchical ID
- `select_best_approximation(hierarchical_model_id: &str) -> Option<&ProviderPotential>` - Select provider
- `handle_complex_transformations(model_id: &str) -> Vec<String>` - Get all possible transformations

### RuleEngine

```rust
pub struct RuleEngine {
    // Integrates rules, hierarchical selection, and token tracking
}
```

**Methods:**
- `new() -> Self` - Create new engine
- `enable_token_ledger()` - Enable token usage tracking
- `add_rule(rule: ProviderSelectionRule)` - Add selection rule
- `set_hierarchical_selector(selector)` - Set hierarchical selector
- `track_token_usage(provider: &str, tokens: u64) -> Result<(), String>` - Track usage
- `has_sufficient_quota(provider: &str, tokens: u64) -> bool` - Check quota
- `get_quota_status(provider: &str) -> Option<(u64, u64, f64)>` - Get status
- `reset_hourly_usage()` - Reset hourly counters
- `reset_daily_usage()` - Reset daily counters
- `select_provider(providers, tokens, model_id) -> Option<&ProviderPotential>` - Select with hierarchy
- `select_provider_enhanced(providers, model_id, tokens) -> Option<&ProviderPotential>` - Enhanced selection

---

## Common Patterns

### Pattern 1: Free-First Routing

```rust
let container = DSELBuilder::new()
    .with_quota("production", 1_000_000)
    .with_free_provider("kilo_code", 100_000, 1, 100_000, 3_000_000, 0)
    .with_free_provider("moonshot", 50_000, 1, 50_000, 1_500_000, 0)
    .with_provider("openai", 500_000, 3, 20.0, false)  // Lower priority (higher number)
    .build()?;

// Free providers will be selected first
let selected = container.select_provider(50_000);
```

### Pattern 2: Fallback Chain

```rust
let container = DSELBuilder::new()
    .with_quota("fallback_chain", 1_000_000)
    .with_provider("primary", 500_000, 1, 10.0, false)
    .with_provider("secondary", 300_000, 2, 15.0, false)
    .with_provider("tertiary", 200_000, 3, 20.0, false)
    .build()?;

// Try primary first
if let Some(provider) = container.select_provider(100_000) {
    // Use provider
} else {
    // Handle no available provider
}
```

### Pattern 3: Hierarchical ID Cleanup

```rust
let rule_engine = DSELBuilder::new()
    .with_quota("clean_ids", 1_000_000)
    .with_provider("litellm", 500_000, 1, 20.0, false)
    .with_provider("openai", 500_000, 2, 30.0, false)
    .with_prefix_transformation("/litellm/litellm/litellm/", "/litellm/")
    .with_prefix_transformation("/openai/openai/openai/", "/openai/")
    .build_with_rule_engine()?;

// Handles malformed IDs automatically
let selected = rule_engine.select_provider(
    &providers,
    50_000,
    Some("/litellm/litellm/litellm/gpt-4"),
);
```

### Pattern 4: Cost-Aware Selection

```rust
let container = DSELBuilder::new()
    .with_quota("cost_optimized", 1_000_000)
    .with_provider("cheap", 500_000, 1, 2.0, false)   // $2/million
    .with_provider("expensive", 500_000, 2, 20.0, false)  // $20/million
    .build()?;

// Lower cost provider selected first (if priority is same)
let cost = container.get_provider("cheap").unwrap().calculate_cost(100_000);
// cost = $0.20
```

### Pattern 5: Rate-Limited Providers

```rust
let container = DSELBuilder::new()
    .with_quota("rate_limited", 1_000_000)
    .with_rate_limited_provider(
        "api_provider",
        500_000,
        1,
        10.0,
        60,   // requests per minute
        1000, // requests per hour
        10000, // requests per day
        10,   // burst limit
    )
    .build()?;

let provider = container.get_provider("api_provider").unwrap();
if provider.is_rate_limited(100, "minute") {
    println!("Rate limited!");
}
```

---

## Error Handling

```rust
use litebike::keymux::dsel::DSELBuilder;

match DSELBuilder::new()
    .with_quota("test", 0)  // Error: quota must be > 0
    .build()
{
    Ok(container) => {
        // Use container
    }
    Err(e) => {
        eprintln!("Failed to build DSEL: {}", e);
        // Handle error
    }
}

// Or with ? operator
let container = DSELBuilder::new()
    .with_quota("test", 1_000_000)
    .build()?;  // Propagates error
```

**Common Errors:**
- `"No providers defined"` - Must add at least one provider
- `"Total quota must be greater than zero"` - Quota must be > 0
- `"Insufficient quota"` - Request exceeds available quota

---

## Best Practices

1. **Use Builder Pattern** - Prefer `DSELBuilder` over manual construction
2. **Enable Token Ledger** - Call `enable_token_ledger()` for quota tracking
3. **Add Prefix Transformations** - Handle malformed agent IDs proactively
4. **Set Appropriate Priorities** - Lower numbers = higher priority
5. **Monitor Quota Status** - Use `get_quota_status()` for observability
6. **Reset Usage Periodically** - Call `reset_hourly_usage()` and `reset_daily_usage()`
7. **Use Free Providers First** - Set free providers with priority 1-3
8. **Cache Transformations** - `HierarchicalModelSelector` caches automatically

---

## Testing

```rust
#[cfg(test)]
mod tests {
    use litebike::keymux::dsel::{DSELBuilder, QuotaContainer};

    #[test]
    fn test_quota_container() {
        let container = DSELBuilder::new()
            .with_quota("test", 1_000)
            .with_provider("test_provider", 500, 1, 10.0, false)
            .build()
            .unwrap();

        assert_eq!(container.providers.len(), 1);
    }

    #[test]
    fn test_provider_selection() {
        let mut container = QuotaContainer::new("test");
        container.add_provider("provider_a", 500, 1, 10.0, false);
        container.add_provider("provider_b", 300, 2, 15.0, false);

        let selected = container.select_provider(100);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().name, "provider_a");
    }
}
```

---

## See Also

- **Full Implementation:** `src/keymux/dsel.rs`
- **Test Suite:** `tests/keymux/test_dsel.rs`, `tests/keymux/test_hierarchical_prefix.rs`
- **Implementation Summary:** `conductor/tracks/cc_store_dsel_quota_20260226/IMPLEMENTATION_SUMMARY.md`
- **Specification:** `conductor/tracks/cc_store_dsel_quota_20260226/spec.md`
