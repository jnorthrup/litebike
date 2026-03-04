# Course Correction: Model Mux Architecture

**Date:** 2026-03-04  
**Type:** Architecture Correction  
**Track:** ollama-emulator-copilot-20260304

---

## Corrected Architecture

### 1. Single Port Protocol Dispatch

**Previous Understanding:** Multiple ports for different protocols

**Corrected:** **literbike performs precompiled parser combinator protocol dispatch from the same port (8888)**

```
                    ┌─────────────────────────────────────┐
                    │     Port 8888 (Single Entry)        │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │  RBCursive Precompiled Dispatch     │
                    │  - Parser Combinators               │
                    │  - SIMD-accelerated detection       │
                    │  - Zero-allocation streaming        │
                    └─────────────────┬───────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐            ┌───────────────┐            ┌───────────────┐
│   OpenAI      │            │   Anthropic   │            │    Gemini     │
│   /v1/*       │            │   /messages   │            │ /generateContent │
│   Protocol    │            │   Protocol    │            │    Protocol   │
└───────────────┘            └───────────────┘            └───────────────┘
        │                             │                             │
        └─────────────────────────────┴─────────────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │     Ollama Emulator Surface         │
                    │     /api/generate, /api/chat, ...   │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │     Modelmux Lifecycle + Quota      │
                    │     (Keymux + Env Projection)       │
                    └─────────────────────────────────────┘
```

### 2. Keymux + Env Projection Integration

**Previous Understanding:** Separate systems

**Corrected:** **keymux combines with the env projection**

```rust
// Integrated flow:
// 1. Env projection normalizes environment variables
let env_profile = normalize_env_pairs(env_pairs);

// 2. Keymux uses projected env for provider selection
let keymux_state = KeymuxState::from_env_projection(&env_profile);

// 3. Combined state drives quota arbitration
let quota_decision = arbitrate_quota(&keymux_state, &quota_inventory);
```

### 3. User-Defined Precedence

**New Feature:** **Users may define the precedence of which system takes priority**

```rust
// User configuration options:
pub enum PrecedenceMode {
    /// Env projection first, then keymux refinement
    EnvFirst,
    
    /// Keymux first, then env projection fallback
    KeymuxFirst,
    
    /// Balanced: both systems vote, weighted decision
    Balanced { env_weight: f32, keymux_weight: f32 },
    
    /// Custom user-defined precedence rules
    Custom(Vec<PrecedenceRule>),
}

// Example configuration:
let config = ModelmuxConfig {
    port: 8888,
    precedence: PrecedenceMode::EnvFirst,
    quota_policy: QuotaPolicy::FreeFirst,
    // ...
};
```

---

## Updated TDD Tests

### Precompiled Parser Combinator Tests

```rust
#[test]
fn test_precompiled_dispatch_single_port_8888() {
    // All protocols dispatch from same port
    let protocols = [
        b"GET /v1/chat/completions HTTP/1.1\r\n...",  // OpenAI
        b"POST /v1/messages HTTP/1.1\r\n...",         // Anthropic
        b"POST /api/generate HTTP/1.1\r\n...",        // Ollama
    ];
    
    let rbcursive = RBCursive::new();
    
    for protocol in &protocols {
        // All should be detected from same port
        let detection = rbcursive.detect_protocol(protocol);
        assert!(matches!(detection, ProtocolDetection::Http(_)));
    }
}

#[test]
fn test_precompiled_parser_combinator_dispatch() {
    // Test precompiled parser combinator dispatch
    use crate::rbcursive::combinators::*;
    
    // Precompiled HTTP method parser
    let method_parser = TagParser::new(b"GET ");
    
    // Precompiled path parser
    let path_parser = TakeUntilParser::new(b' ', scanner);
    
    // Precompiled sequence for full request line
    let request_line = SequenceParser::new(method_parser, path_parser);
    
    let input = b"GET /api/chat HTTP/1.1\r\n\r\n";
    let result = request_line.parse(input);
    
    assert!(result.is_complete());
}

#[test]
fn test_simd_accelerated_protocol_detection() {
    // Test SIMD-accelerated detection
    let rbcursive = RBCursive::new();
    let scanner = rbcursive.scanner();
    
    // SIMD should quickly detect protocol markers
    let data = b"POST /api/chat HTTP/1.1\r\n\r\n";
    let structural = scanner.scan_structural(data);
    
    // Structural analysis should identify HTTP patterns
    assert!(structural > 0);
}
```

### Keymux + Env Projection Integration Tests

```rust
#[test]
fn test_keymux_env_projection_integration() {
    // Test keymux combining with env projection
    let env_pairs = vec![
        ("KILO_API_KEY".to_string(), "sk-kilo".to_string()),
        ("KILO_BASE_URL".to_string(), "https://api.kilo.ai".to_string()),
        ("MOONSHOT_API_KEY".to_string(), "sk-moonshot".to_string()),
    ];
    
    // 1. Env projection
    let env_profile = normalize_env_pairs(env_pairs);
    
    // 2. Keymux integration
    let keymux_state = KeymuxState::from_env_projection(&env_profile);
    
    // 3. Verify combined state
    assert_eq!(keymux_state.providers.len(), 2);
    assert!(keymux_state.providers.iter().any(|p| p.id == "kilo_code"));
    assert!(keymux_state.providers.iter().any(|p| p.id == "moonshot"));
}

#[test]
fn test_keymux_dsel_quota_from_env() {
    // Test DSEL quota container populated from env projection
    let env_pairs = vec![
        ("KILO_API_KEY".to_string(), "sk-kilo".to_string()),
        ("MOONSHOT_API_KEY".to_string(), "sk-moonshot".to_string()),
    ];
    
    let env_profile = normalize_env_pairs(env_pairs);
    let keymux_state = KeymuxState::from_env_projection(&env_profile);
    
    // Build DSEL from keymux state
    let mut dsel = DSELBuilder::new()
        .with_quota("production", 1000000);
    
    for provider in &keymux_state.providers {
        dsel = dsel.with_provider(
            &provider.id,
            provider.remaining_requests,
            provider.priority,
            provider.cost_per_1k,
            provider.is_free,
        );
    }
    
    let container = dsel.build().expect("DSEL should build");
    
    // Free providers should be prioritized
    let selected = container.select_best();
    assert!(selected.is_some());
    assert!(selected.unwrap().is_free());
}
```

### User-Defined Precedence Tests

```rust
#[test]
fn test_precedence_mode_env_first() {
    // Test EnvFirst precedence mode
    let config = ModelmuxConfig {
        port: 8888,
        precedence: PrecedenceMode::EnvFirst,
        ..Default::default()
    };
    
    let env_pairs = vec![
        ("KILO_API_KEY".to_string(), "sk-kilo".to_string()),
    ];
    
    let env_profile = normalize_env_pairs(env_pairs);
    let decision = make_routing_decision(&config, &env_profile, &keymux_state);
    
    // Env projection should drive decision
    assert_eq!(decision.source, DecisionSource::EnvProjection);
}

#[test]
fn test_precedence_mode_keymux_first() {
    // Test KeymuxFirst precedence mode
    let config = ModelmuxConfig {
        port: 8888,
        precedence: PrecedenceMode::KeymuxFirst,
        ..Default::default()
    };
    
    let decision = make_routing_decision(&config, &env_profile, &keymux_state);
    
    // Keymux should drive decision
    assert_eq!(decision.source, DecisionSource::Keymux);
}

#[test]
fn test_precedence_mode_balanced() {
    // Test Balanced precedence mode
    let config = ModelmuxConfig {
        port: 8888,
        precedence: PrecedenceMode::Balanced {
            env_weight: 0.6,
            keymux_weight: 0.4,
        },
        ..Default::default()
    };
    
    let decision = make_routing_decision(&config, &env_profile, &keymux_state);
    
    // Decision should be weighted combination
    assert_eq!(decision.source, DecisionSource::Balanced);
    assert!(decision.confidence >= 0.0 && decision.confidence <= 1.0);
}

#[test]
fn test_user_defined_precedence_rules() {
    // Test custom user-defined precedence rules
    let rules = vec![
        PrecedenceRule::IfProvider("kilo_code", Precedence::EnvFirst),
        PrecedenceRule::IfProvider("moonshot", Precedence::KeymuxFirst),
        PrecedenceRule::Default(Precedence::Balanced { weight: 0.5 }),
    ];
    
    let config = ModelmuxConfig {
        port: 8888,
        precedence: PrecedenceMode::Custom(rules),
        ..Default::default()
    };
    
    // Kilo should use EnvFirst
    let kilo_decision = make_routing_decision(&config, &kilo_env, &kilo_keymux);
    assert_eq!(kilo_decision.source, DecisionSource::EnvProjection);
    
    // Moonshot should use KeymuxFirst
    let moonshot_decision = make_routing_decision(&config, &moonshot_env, &moonshot_keymux);
    assert_eq!(moonshot_decision.source, DecisionSource::Keymux);
}
```

---

## Updated Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Port 8888 (Single Entry Point)                       │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RBCursive Precompiled Parser Dispatch                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Precompiled Parser Combinators (SIMD-accelerated)                   │   │
│  │  - TagParser: HTTP methods (GET, POST, PUT, DELETE)                 │   │
│  │  - TakeUntilParser: Path extraction                                  │   │
│  │  - SequenceParser: Full request line parsing                         │   │
│  │  - AlternativeParser: Protocol fallback                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              │                                               │
              ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│    Env Projection       │                     │      Keymux State       │
│  - normalize_env_pairs  │                     │  - Provider potentials  │
│  - API key recognition  │                     │  - Quota containers     │
│  - Hostname detection   │                     │  - DSEL builders        │
│  - Search key grouping  │                     │  - Token ledgers        │
└───────────┬─────────────┘                     └───────────┬─────────────┘
            │                                               │
            └───────────────────────┬───────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │   User-Defined Precedence     │
                    │  ┌─────────────────────────┐  │
                    │  │ EnvFirst                │  │
                    │  │ KeymuxFirst             │  │
                    │  │ Balanced (weighted)     │  │
                    │  │ Custom (rule-based)     │  │
                    │  └─────────────────────────┘  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   Quota Arbitration Engine    │
                    │   - Free-first policy         │
                    │   - Minima thresholds         │
                    │   - Provider scoring          │
                    │   - Fallback logic            │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   Ollama Emulator Backend     │
                    │   - /api/generate             │
                    │   - /api/chat                 │
                    │   - /api/tags                 │
                    │   - /api/show                 │
                    │   - /health, /metrics         │
                    └───────────────────────────────┘
```

---

## Files to Update

| File | Change Needed |
|------|---------------|
| `literbike/src/rbcursive/mod.rs` | Add precompiled dispatch documentation |
| `literbike/src/keymux/dsel.rs` | Add env projection integration |
| `litebike/src/keymux/facade.rs` | Add precedence mode configuration |
| `tests/modelmux/test_8888_cloaking.rs` | Add precompile dispatch tests |
| `conductor/tracks/.../spec.md` | Update architecture section |
| `conductor/tracks/.../plan.md` | Update implementation plan |

---

## Implementation Priority

1. **High:** Add precompiled parser combinator dispatch tests
2. **High:** Add keymux + env projection integration tests
3. **Medium:** Add user-defined precedence tests
4. **Medium:** Update documentation with corrected architecture
5. **Low:** Add balanced precedence mode implementation

---

## Key Insights

1. **Single Port:** All protocol dispatch happens from port 8888 via precompiled parser combinators
2. **Integration:** Keymux and env projection are combined, not separate
3. **Flexibility:** Users can define precedence rules for different providers
4. **Performance:** Precompiled parsers + SIMD = zero-allocation streaming
