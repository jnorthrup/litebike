# Plan: Universal Model Facade

## Phase 1: Standardized `v1/models` Facade
- [x] Implement robust `handle_models` in `keymux` to return aggregate model lists.
- [x] Implement the "Web Model Cards" metadata cache for specialized agent context.
- [x] Add support for multiple model protocols (OpenAI, Anthropic, Google) in the facade.

## Implementation Notes
- Migration from `cc-switch` museum logic complete.
- Core types and translation protocols landed in `litebike/src/keymux/protocols`.
- Phase 2 (DSEL) broken out into track `cc_store_dsel_quota_20260226`.
