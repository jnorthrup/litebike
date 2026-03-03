# Spec: CC-Store DSEL & Quota Potential

## Overview
This specification defines a Domain-Specific Embedded Language (DSEL) for CC-Store. The DSEL replaces "stove-pipe" GUI-based routing with a declarative, programmable system for managing consumer-provider quota containers. It enables the "Generative Model Plasma" by allowing agents to discover and utilize reasoning capacity based on dynamic quota potentials.

## Requirements
- **DSEL Grammar:** Define a Rust-embedded DSEL (or a simple parser) for defining quota containers, provider pairings, and priority hierarchies.
- **Quota Potentials:** Implement logic to calculate "potentials" (available reasoning capacity) across distributed keys and providers.
- **Metadata Specialization:** Use "Web Model Cards" to allow the DSEL to filter or prioritize models based on specialized agent needs (e.g., `if model.is_code_native() { use high_priority_quota }`).
- **Separation of Concerns:** Zero dependency on legacy `cc-switch` UI or Tauri. The DSEL must be a pure logic layer in `litebike`.

## The DSEL Concept (Example)
```rust
quota_container "high-res-thinking" {
    provider "anthropic" {
        priority 1
        model_match "claude-3-5-sonnet"
        potential 1000000 // tokens
    }
    provider "openai" {
        priority 2
        model_match "gpt-4o"
        potential 500000
    }
}
```

## Verification Criteria
- DSEL scripts can be parsed and correctly instantiate the `QuotaManager` state.
- The `keymux` ranker successfully uses DSEL-derived potentials to route requests.
- Unit tests confirm that quota drainage and refill logic (simulated) follow DSEL rules.
