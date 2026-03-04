# DRY + YAGNI Architecture

**Date:** 2026-03-04  
**Principle:** Don't Repeat Yourself + You Ain't Gonna Need It

---

## Architecture Separation

### literbike (Heavyweight Library)
**Location:** `/Users/jim/work/literbike/`

**Responsibilities:**
- Protocol parsing (RBCursive)
- Model mux logic
- Keymux precedence
- Env projection
- Quota arbitration
- Provider taxonomy
- All core logic

**Modules:**
```
literbike/src/
├── model_mux.rs          ← Unified mux (single source of truth)
├── env_facade_parity.rs  ← Env projection
├── model_serving_taxonomy.rs ← Provider taxonomy
├── provider_facade_models.rs ← Provider facades
├── rbcursive/            ← Parser combinators
└── lib.rs                ← Exports model_mux
```

### litebike (Lightweight Proxy)
**Location:** `/Users/jim/work/litebike/`

**Responsibilities:**
- HTTP/S proxy
- SOCKS5 proxy
- Port binding (8888)
- Request routing
- Uses literbike as dependency (NO duplication)

**Modules:**
```
litebike/src/
├── keymux/mod.rs         ← Re-exports from literbike
├── agents/               ← Agent logic
├── gates/                ← Proxy gates
├── ollama_emulator.rs    ← Ollama API surface (binary)
└── lib.rs                ← litebike specific logic
```

---

## Single Source of Truth

### Precedence Logic
**Location:** `literbike/src/model_mux.rs` ✅

```rust
// literbike/src/model_mux.rs (ONLY copy)
pub enum PrecedenceMode {
    EnvFirst,
    KeymuxFirst,
    Balanced { env_weight, keymux_weight },
    Custom(Vec<PrecedenceRule>),
}
```

**litebike uses via re-export:**
```rust
// litebike/src/keymux/mod.rs
pub use literbike::model_mux::{
    UnifiedMuxState, PrecedenceMode, PrecedenceRule,
    ProviderPrecedence, DecisionSource, RoutingDecision
};
```

### Env Projection
**Location:** `literbike/src/env_facade_parity.rs` ✅

```rust
// literbike (single source)
pub fn normalize_env_pairs(...) -> NormalizedEnvProfile { ... }
```

**litebike imports:**
```rust
use literbike::env_facade_parity::normalize_env_pairs;
```

### Quota Arbitration
**Location:** `literbike/src/env_facade_parity.rs` ✅

```rust
// literbike (single source)
pub fn evaluate_modelmux_mvp_quota_inventory(...) { ... }
pub fn run_modelmux_quota_drainer_dry_run(...) { ... }
```

---

## Dependency Flow

```
litebike (proxy runtime)
    │
    │ depends on
    ▼
literbike (core library)
    │
    │ contains
    ▼
├── model_mux.rs      ← Precedence logic
├── env_facade_parity.rs ← Env projection
├── rbcursive/        ← Parser combinators
└── ...               ← All core logic
```

---

## Code Location Guide

| Feature | Location | File |
|---------|----------|------|
| PrecedenceMode | literbike | `src/model_mux.rs` |
| UnifiedMuxState | literbike | `src/model_mux.rs` |
| RoutingDecision | literbike | `src/model_mux.rs` |
| Env Projection | literbike | `src/env_facade_parity.rs` |
| Quota Arbitration | literbike | `src/env_facade_parity.rs` |
| Provider Taxonomy | literbike | `src/model_serving_taxonomy.rs` |
| Ollama Emulator | litebike | `src/bin/ollama_emulator.rs` |
| Proxy Gates | litebike | `src/gates/` |
| DSEL Builder | litebike | `src/keymux/dsel.rs` |

---

## DRY Violations Fixed

### Before (WRONG ❌)
```
litebike/src/keymux/precedence.rs  ← Duplicate
literbike/src/model_mux.rs         ← Duplicate
```

### After (CORRECT ✅)
```
literbike/src/model_mux.rs         ← Single source
litebike/src/keymux/mod.rs         ← Re-export only
```

---

## YAGNI Applied

**Removed:**
- `litebike/src/keymux/precedence.rs` (deleted - duplicated literbike)
- Duplicate `PrecedenceMode` in litebike
- Duplicate `RoutingDecision` in litebike
- Duplicate `UnifiedMuxState` in litebike

**Kept in litebike:**
- `ollama_emulator.rs` (binary - litebike specific)
- `gates/` (proxy logic - litebike specific)
- `agents/` (agent logic - litebike specific)

---

## Usage Examples

### In litebike (using literbike)

```rust
// litebike/src/bin/ollama_emulator.rs
use literbike::model_mux::{UnifiedMuxState, PrecedenceMode};
use literbike::env_facade_parity::normalize_env_pairs;

fn main() {
    // Use literbike's unified mux
    let state = UnifiedMuxState::from_env_pairs(env_pairs)
        .with_precedence(PrecedenceMode::EnvFirst);
    
    let decision = state.make_decision();
    // ...
}
```

### In literbike (core logic)

```rust
// literbike/src/model_mux.rs
pub struct UnifiedMuxState {
    // Core implementation
}

impl UnifiedMuxState {
    pub fn make_decision(&self) -> Option<RoutingDecision> {
        // Core logic
    }
}
```

---

## Build Order

1. **literbike** builds first (library)
2. **litebike** builds second (depends on literbike)

```bash
# Build literbike first
cd /Users/jim/work/literbike
cargo build

# Build litebike (uses literbike)
cd /Users/jim/work/litebike
cargo build
```

---

## Testing

### literbike Tests
```bash
cd /Users/jim/work/literbike
cargo test model_mux  # Tests core mux logic
```

### litebike Tests
```bash
cd /Users/jim/work/litebike
cargo test modelmux_8888  # Tests integration with literbike
```

---

## Benefits

1. **DRY:** Single source of truth for precedence/mux logic
2. **YAGNI:** No duplicate code in litebike
3. **Maintainability:** Fix bug in literbike → fixed everywhere
4. **Clear Separation:** literbike = library, litebike = runtime
5. **Dependency Direction:** litebike → literbike (one way)

---

## Files Modified

| File | Action | Reason |
|------|--------|--------|
| `litebike/src/keymux/precedence.rs` | ❌ Deleted | Duplicate of literbike |
| `litebike/src/keymux/mod.rs` | ✅ Updated | Re-export from literbike |
| `literbike/src/model_mux.rs` | ✅ Created | Single source of truth |
| `literbike/src/lib.rs` | ✅ Updated | Export model_mux |

---

## Summary

✅ **literbike** = Heavyweight library (all core logic)  
✅ **litebike** = Lightweight proxy (uses literbike, no duplication)  
✅ **Single Source** = `literbike/src/model_mux.rs`  
✅ **Re-export** = `litebike/src/keymux/mod.rs`  
✅ **DRY** = No duplicate precedence/mux code  
✅ **YAGNI** = Removed unnecessary duplication  

**Architecture is now clean and maintainable.**
