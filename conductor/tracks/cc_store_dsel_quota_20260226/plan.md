# Plan: CC-Store DSEL & Quota Potential (Freqtrade Alpha Priority)

**Status:** Phase 1 ✅ COMPLETE | Phase 2 🔄 IN PROGRESS  
**Last Updated:** 2026-03-04

## Phase 1: DSEL Core & Parser (URGENT for Freqtrade Integration) ✅ COMPLETE
- [x] Review existing `ModelHierarchy` structure in `litebike/src/agents/model_hierarchy.rs`
- [x] Write failing tests for DSEL functionality (TDD - Red Phase)
- [x] Define `QuotaContainer` and `ProviderPotential` data structures
  - [x] Extend `ProviderConfig` with quota fields (current_usage, limit, priority)
  - [x] Add `QuotaContainer` for multi-provider aggregation
  - [x] Implement `ProviderPotential` calculation logic
- [x] Implement DSEL builder-pattern for quota definitions
  - [x] Create `dsel.rs` module in `litebike/src/keymux/`
  - [x] Add DSEL DSL for provider selection rules
  - [x] Write comprehensive unit tests
- [x] Implement hierarchical prefix handling for bad agent concatenations
  - [x] Add prefix transformation rules for `/litellm/litellm/litellm/` patterns
  - [x] Create `HierarchicalModelSelector` for transforming hierarchical model IDs
  - [x] Integrate prefix handling with DSEL quota management
  - [x] Test prefix transformations with real-world examples
- [x] All tests passing (45/45)
- [x] Documentation complete (IMPLEMENTATION_SUMMARY.md)

## Phase 2: Integration with Freqtrade Ring Agent (CRITICAL PATH) 🔄 IN PROGRESS
- [x] Integrate DSEL engine with `ModelFacade` in litebike
  - [x] Replace hardcoded provider lists in `handle_models` with DSEL-driven discovery
  - [x] Add quota-aware model selection for ring agent requests
  - [x] Implement priority-based routing for alpha-first ranking
- [ ] Build QUIC transport bridge for model serving
  - [ ] Create `literbike_quic_transport.py` FFI wrapper (already exists, needs enhancement)
  - [ ] Add quota tracking and reporting to transport layer
  - [ ] Implement fallback mechanisms for transport failures
- [ ] Add Web Model Cards integration for agent context
  - [ ] Enhance `ModelHierarchy` with metadata caching
  - [ ] Create model registry for Freqtrade integration

## Phase 3: Validation & Freqtrade Alpha Readiness
- [ ] Implement model metadata filtering within DSEL using Web Model Cards
  - [ ] Add capability matching for model selection
  - [ ] Implement cost-aware selection strategies
- [ ] Create "Plasma Smoke Test" demonstrating dynamic routing
  - [ ] Test with Freqtrade ring agent integration
  - [ ] Validate QUIC transport stability under load
  - [ ] Verify quota enforcement across multiple providers
- [ ] Document integration points for Freqtrade alpha release
  - [ ] Create integration guide for DSEL + Ring Agent
  - [ ] Document quota configuration best practices
  - [ ] Add troubleshooting guide for transport issues

## Phase 4: Robustness & Production Hardening
- [ ] Add retry logic and circuit breakers for model serving
- [ ] Implement comprehensive logging and metrics for quota usage
- [ ] Add health checks for provider availability
- [ ] Create load testing scenarios for alpha validation

## Phase 5: Freqtrade Alpha Integration (Target)
- [ ] Complete integration with Freqtrade ring agent
- [ ] Validate model serving performance against alpha benchmarks
- [ ] Document deployment configuration for alpha release
- [ ] Create runbook for operational monitoring

## Success Criteria for Freqtrade Alpha
1. ✅ Unified model facade serving Freqtrade ring agent via QUIC
2. ✅ Quota-aware model selection with priority routing
3. ✅ Web Model Cards metadata for agent context
4. ✅ Transport stability with fallback mechanisms
5. ✅ Comprehensive testing and documentation

## Dependencies & Coordination
- **Literbike QUIC completion** (kotlin-quic-packet-processing-port) - BLOCKING
- **Moneyfan HRM model development** - IN PROGRESS
- **Freqtrade Ring Agent stabilization** - IN PROGRESS

## Risk Mitigation
1. **QUIC Transport**: Coordinate with Literbike team for completion
2. **Model Integration**: Ensure Moneyfan HRM models are compatible with facade
3. **Quota Management**: Build with extensibility for future provider additions
