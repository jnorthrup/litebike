# Litebike Modelmux Superpath Consolidation

## Overview

Consolidate model-serving, proxy-routing, and app-level behavior previously split across `cc-switch`, betanet-era flows, and local `litebike` gate logic into a shared `literbike` modelmux taxonomy/facade layer plus `litebike` runtime integration.

This track establishes a DSEL-first proxy superpath intended to subsume the `cc-switch` application as a single Rust DSEL-driven system.

For this track, `cc-switch` replacement parity is defined primarily around the `.env`-driven execution facade (configuration/env-to-execution behavior), which is the key user-facing capability to preserve.

`cccache` and `cc-switch` are distinct entities in this track:

- `cccache` refers to the cache/proxy gate surface (e.g., `cccache_gate`) and its route detection/forwarding behavior.
- `cc-switch` refers to the separate `.env`-driven execution facade whose parity is the migration target.

Near-term implementation priority is a template-first, self-improving agent FSM in Rust DSEL. Live external API calls (provider/exchange/capability probes) are optional adapters and should not be on the critical path for the first useful slice.

This track also includes an agent guidance addendum for OpenClaw or other local agents, centered on a free-tier-first "QuotaDrainer" worker profile that is implemented as DSEL/FSM policy over local stores and mockable adapters.

The resulting system can support:

- OpenAI-style `v1` model APIs and compatible surfaces
- Pragmatic LangChain/LangGraph-oriented routing/orchestration entry points
- Agentic DSEL command/control paths
- DSEL-based MCP servers that wrap template REST facades
- OpenAPI3 and key-vault-oriented control-plane roles
- Real OS key vault-backed enforcement paths (implemented in `literbike`/`litebike` gates)
- Absorption of DSEL MCP-over-template-REST flows into a shared realtime transport profile (QUIC/h2)

## Problem

Current routing, classification, and gate decisions are distributed across hardcoded path checks and repo-specific logic. This makes it difficult to:

- add new provider/model surfaces consistently,
- share policy/quota/grant behavior across proxy entry points,
- expose a stable facade route matrix for both runtime and generated specs,
- bind authentication/keymux/keyvault enforcement to the same normalized route model.
- converge on one Rust DSEL surface that can replace the existing `cc-switch` app behavior end-to-end.

## Goals

- Define and use a shared `literbike` model-serving taxonomy for provider/model/action/mux classification.
- Define a `literbike` facade matrix that maps route patterns to templates, grants, wrappers, quotas, and macros.
- Subsume the `cc-switch` app’s core command/proxy/switch behavior into `litebike` as a single Rust DSEL-driven implementation.
- Preserve and improve the `cc-switch` `.env`-driven execution facade as the primary parity target for migration.
- Preserve `cc-switch` `.env` capability toggles such as `*_SEARCH_API_KEY` enabling websearch, including multi-key multi-pumping behavior.
- Treat generic `*_API_KEY` bindings as facade inputs that may represent either exchange APIs or model/provider APIs, with typed classification derived from hostname + capability probes (including `models` calls).
- Route `litebike` decode/log/count behavior through shared classification primitives.
- Migrate gate decisions (including cache/path gates) from hardcoded checks to matrix-driven logic.
- Support keymux/keyvault enforcement using typed OAuth/pubkey grant specs.
- Generate a self-contained OpenAPI3 facade spec from the same facade matrix metadata.
- Absorb DSEL-based MCP servers wrapping template REST into a shared QUIC/h2 realtime profile instead of separate protocol-specific stacks.
- Support pragmatic DSEL model hierarchies for pooling, reviewing, dispatching, and accommodating provider/model capability differences.
- Deliver a template-driven self-improving agent FSM slice before painful live external API integration work.
- Use FOPL/GOFAI-style explicit symbolic rules/policies for orchestration and dispatch, including controlled model-directed model selection.
- Provide a reusable agent guidance profile ("QuotaDrainer") for OpenClaw/other agents: discover -> score -> drain owned free quotas first, then fallback by policy.

## Functional Requirements

1. `literbike` exposes canonical model-serving taxonomy types, templates, actions, and mux surfaces for supported provider families.
2. `literbike` exposes provider facade object models for:
   - ENV roles and recognition rules
   - OAuth grants
   - pubkey grants
   - wrappers/quotas/macros
   - facade v1 route matrix rows
3. `literbike` provides HTTP prefix classification that normalizes incoming requests into `{family, template, action, mux}` keys.
4. `litebike` integrated proxy consumes the shared classifier and records decoded route metrics/counters.
5. `litebike` gates (starting with `cccache_gate`) use shared classifier + facade matrix decisions rather than local path heuristics.
6. Keymux/keyvault enforcement in `litebike` can resolve and apply grant specs defined in `literbike`.
7. OpenAPI3 facade documentation can be generated from the facade matrix without duplicating route definitions by hand.
8. The migration preserves existing supported proxy behaviors for current v1-compatible clients.
9. The Rust DSEL layer is capable of expressing the `cc-switch` app's primary `.env`-configured switch/route/policy behaviors without requiring parallel legacy app logic for those flows.
10. `.env` role/binding resolution uses the shared `literbike` provider facade ENV models and recognition rules where applicable.
11. `*_SEARCH_API_KEY` environment bindings (including multiple matching keys) enable websearch capability in the execution facade and map into typed ENV roles without ad hoc special cases.
12. Multiple `*_SEARCH_API_KEY` bindings can be aggregated for "multi-key multi-pumping" behavior (e.g., rotation/fanout/load-sharing semantics defined by facade policy/DSEL).
13. Generic `*_API_KEY` environment bindings can be classified as exchange-facing or model-provider-facing using hostname metadata and probeable capabilities (for example `GET /models` or equivalent `models` endpoints), then mapped into typed ENV roles.
14. Probe-based classification can be tested and cached without breaking offline/static `.env` execution (fallback to hostname/rule-based inference when probing is unavailable).
15. DSEL-defined MCP server facades that wrap template REST routes can be mapped onto the same facade matrix and executed through a shared realtime transport profile (QUIC/h2) without duplicating route semantics.
16. The realtime profile preserves template REST-derived capabilities (streaming/events/tools/control paths as applicable) while allowing MCP-facing adapters to remain thin.
17. The Rust DSEL layer can define pragmatic model hierarchies/pools with first-class support for pooling, reviewing, dispatching, and accommodating capability or surface mismatches.
18. LangChain/LangGraph interoperability is achieved via DSEL hierarchy semantics and adapters, without requiring strict framework-internal parity.
19. A template-defined self-improving agent FSM can run locally in Rust DSEL with explicit states/transitions for at least dispatch, review, and accommodate loops (state names may vary), without requiring live external API calls.
20. Self-improvement behavior is bounded by templates, symbolic rules/policies, and tests (no unconstrained runtime mutation), and is reproducible in a no-network mode.
21. External provider/exchange calls and capability probes are optional adapters for the FSM path, and can be disabled or mocked during template-first development.
22. The DSEL supports FOPL/GOFAI-style symbolic task-routing predicates and policies that can influence provider/model selection deterministically.
23. A model (or model-backed review/selector step) may propose or dictate which model should serve a task, but the final dispatch is mediated by explicit DSEL policy/guardrails (quota, capability, safety, grants, and fallback rules).
24. An agent guidance addendum defines a local-first "QuotaDrainer" worker profile for OpenClaw or similar agents, including:
   - quota discovery,
   - project scoring,
   - free-tier-first draining,
   - paid fallback policy,
   - dry-run/no-network execution.
25. The QuotaDrainer profile can consume quota inventory from pluggable local adapters (for example `litebike` budget/key APIs, LiteLLM-compatible admin APIs, `cc-switch` SQLite, or static mocks) without changing core FSM logic.
26. OpenClaw- or runtime-specific integration details (scheduling, tunneling/phone-home, worker invocation) are expressed as thin adapters/operator guidance and do not alter DSEL policy semantics.
27. Quota draining behavior is limited to user-owned/authorized quotas and is bounded by explicit budget, grant, and safety guardrails.

## Acceptance Criteria

- A shared taxonomy and facade matrix exist in `literbike` and compile/test independently.
- `litebike` integrated proxy logs and counts normalized decoded model routes using the shared classifier.
- `cccache_gate` (or equivalent cache gate path detection) is driven by shared classification/matrix mapping.
- Keymux/keyvault gate decisions reference typed OAuth/pubkey grant specs from `literbike`.
- An OpenAPI3 facade spec generator produces a self-contained spec from matrix rows.
- Representative `cc-switch` `.env` profiles/workflows can be expressed and executed via the Rust DSEL-first path in `litebike` (with documented parity gaps, if any).
- `.env`-driven execution facade behavior is documented with a migration mapping from `cc-switch` env keys/semantics to `litebike`/`literbike` equivalents.
- A profile containing one or more `*_SEARCH_API_KEY` env bindings enables websearch in the DSEL execution facade, and multiple keys follow documented multi-key pumping semantics.
- A profile containing generic `*_API_KEY` bindings can distinguish exchange vs model-provider keys using documented hostname + `models` probe logic (with deterministic fallback behavior).
- At least one DSEL-based MCP wrapper over template REST is shown to run through the shared realtime profile (QUIC/h2) with no duplicated route/matrix definitions.
- At least one DSEL model hierarchy demonstrates pooling + dispatch and one review/accommodation behavior (combined flow is acceptable) using shared facade/matrix definitions.
- A template self-improving agent FSM runs end-to-end in a local/no-network test path, exercising at least dispatch + review + accommodate transitions.
- At least one flow demonstrates model-directed model selection (selector/reviewer proposes the serving model) with explicit DSEL policy arbitration/guardrails.
- An agent guidance addendum exists for OpenClaw/other agents and documents a no-network/dry-run QuotaDrainer path plus optional live adapter paths.
- A QuotaDrainer-style discover -> score -> drain -> fallback loop is covered by tests or executable dry-run fixtures using mock or local adapter sources.
- `cargo check` passes in `litebike`; targeted `cargo test` passes in `literbike` for taxonomy/facade modules.

## Out of Scope

- Full LangChain/LangGraph framework parity or framework-internal execution semantics beyond pragmatic DSEL interoperability needs
- Mandatory live provider/exchange API integration for the initial template self-improving FSM slice
- Non-essential `cc-switch` surfaces that are not part of the `.env`-driven execution facade (unless needed to support facade parity)
- Immediate removal of all legacy gates/path checks in a single slice
- Cloud secret store integrations outside the OS key-vault/keymux path in this track
- Broad active endpoint scanning beyond targeted capability probes needed to classify `.env` facade keys
- Full bespoke MCP protocol stacks per provider when the same behavior can be expressed via template REST + shared realtime profile adapters
- Dependence on any external SaaS agent-control platform for the core QuotaDrainer/FSM logic (self-hosted/local-first only)

## Expected Files / Modules

- `conductor/tracks/litebike-modelmux-superpath_20260225/spec.md`
- `conductor/tracks/litebike-modelmux-superpath_20260225/plan.md`
- `conductor/tracks/litebike-modelmux-superpath_20260225/agent_guidance_quota_drainer.md`
- `conductor/tracks/litebike-modelmux-superpath_20260225/cc_switch_env_parity_inventory.md`
- `literbike/src/model_serving_taxonomy.rs`
- `literbike/src/provider_facade_models.rs`
- `literbike/src/universal_listener.rs`
- `literbike/src/lib.rs`
- `src/integrated_proxy.rs`
- `src/gates/cccache_gate.rs`
- `src/gates/*` (as matrix-driven gate routing is expanded)

## Current Baseline (Reported Implemented Slice)

The following slice is treated as already implemented at track creation time (per user report):

- Shared `literbike` model-serving taxonomy and provider facade models (templates/actions/mux/env/grants/matrix)
- `literbike` universal listener overlay prefix decode/logging
- `litebike` integrated proxy decode/log/count hooks using the shared classifier
- `literbike` provider facade ENV role/binding models and ENV recognition rules (foundation for `.env` execution facade parity)
- Validation:
  - `cargo test model_serving_taxonomy --quiet` in `literbike`
- `cargo test provider_facade_models --quiet` in `literbike`
- `cargo check --quiet` in `litebike`

## Terminology Clarification

- `cccache` != `cc-switch`.
- Phase 1 `cccache_gate` classifier/matrix work is gate-detection migration work.
- `cc-switch` parity work refers to `.env` execution facade semantics and DSEL/FSM replacement behavior.
- Current feature focus in this conversation is the latter (`cc-switch` `.env` execution-facade parity), not compiler/cache-gate behavior.
