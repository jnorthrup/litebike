# Plan: Litebike Modelmux Superpath Consolidation

## 100% Slices (Zero-Discovery)

- [x] CLI parser hardening: add `modelmux_mvp_lifecycle` parser test for invalid `--port` value (`confidence=100`, `discovery=none`)
- [x] CLI parser hardening: add `modelmux_mvp_lifecycle` parser test for missing `--port` value (`confidence=100`, `discovery=none`)
- [x] CLI parser hardening: add `modelmux_mvp_lifecycle` parser test for invalid `--probe-timeout-secs` value (`confidence=100`, `discovery=none`)
- [x] CLI parser hardening: add `modelmux_mvp_lifecycle` parser test for missing `--probe-timeout-secs` value (`confidence=100`, `discovery=none`)
- [x] CLI parser hardening: add `modelmux_mvp_lifecycle` parser test for missing `--agent-name` value (`confidence=100`, `discovery=none`)
- [x] CLI parser hardening: add `modelmux_mvp_lifecycle` parser test for missing `--env-file` value (`confidence=100`, `discovery=none`)
- [x] CLI parser hardening: add `modelmux_mvp_lifecycle` parser test for missing `--probe` value (`confidence=100`, `discovery=none`)

## Main Todo Recap (Conductor Focus)

- [ ] Main strategic todo: define FOPL/GOFAI-style symbolic policy primitives (predicates/rules) for task classification and model routing decisions, then use them to replace hardcoded QuotaDrainer arbitration paths incrementally. (`confidence<100`, `discovery=subsystem-read`, reason: policy semantics/interface stability still need design choices)
- [ ] Follow-on integration todo: map orchestration intents (LangChain/LangGraph-style) onto those primitives and wire hierarchy dispatch/review flows to shared route/quota/grant policy. (`confidence<100`, `discovery=subsystem-read`)

## Phase 0: Track Bootstrap + Baseline Capture

- [x] Create Conductor track artifacts for the cross-repo modelmux consolidation program.
- [x] Capture the first implemented slice as baseline context (taxonomy, facade models, universal listener decode, integrated proxy decode/log/count).
- [x] Record baseline validation commands/results reported for `literbike` and `litebike`.
- [x] Add initial OpenClaw/other-agent guidance addendum describing the local-first QuotaDrainer worker profile.

## Phase 1: Shared Classification Adoption in `litebike` Gates

- [ ] Replace hardcoded `cccache_gate` path detection with shared `literbike` classifier + `FacadeV1Matrix` lookup. (deprioritized for now; `cccache` is distinct from `cc-switch` parity focus)
- [ ] Add a small adapter in `litebike` for translating decoded classifier output into facade-matrix route selection inputs.
- [ ] Preserve existing gate behavior for unsupported/unclassified paths with explicit fallback logic.
- [ ] Add/extend tests for cache gate classification and fallback behavior.
- [x] Start a `cc-switch` parity inventory focused on the `.env` execution facade (env keys, profiles, route selection, grants, transforms, policies).
- [x] Map `cc-switch` `.env` keys/semantics onto `literbike` ENV roles and recognition rules, documenting gaps.
- [x] Explicitly capture `*_SEARCH_API_KEY` parity semantics (websearch enablement + multi-key multi-pumping) in the env mapping inventory.
- [x] Capture generic `*_API_KEY` parity semantics where keys may target either exchanges or model providers.

Validation

- [ ] `cargo test cccache_gate --quiet` (or nearest targeted gate tests) in `litebike`
- [ ] `cargo check --quiet` in `litebike`

## Phase 2: Facade-Driven Gate Policy and Keymux/Keyvault Grants

- [ ] Bind `litebike` gate enforcement to `literbike` OAuth/pubkey grant specs for matched facade routes.
- [ ] Define grant-resolution flow from route match -> required grant(s) -> gate action.
- [ ] Integrate OS key vault/keymux lookup hooks for grant material resolution (behind clear interfaces if full implementations are staged).
- [ ] Add logging/metrics for grant resolution success/failure by normalized route key.
- [ ] Ensure `.env`-driven execution facade inputs can select/override grant paths through typed ENV roles (without ad hoc parsing).
- [x] Implement typed handling for one-or-many `*_SEARCH_API_KEY` env bindings and wire them to websearch capability enablement in the facade/DSEL path.
- [x] Implement typed handling for generic `*_API_KEY` env bindings with hostname-first inference and a mockable/optional `models` capability probe adapter to classify exchange vs model-provider use.
- [x] Add cache + fallback behavior for probe results so `.env` execution remains deterministic when probing is disabled/unavailable.
- [x] Define a quota inventory adapter interface for QuotaDrainer-style workers (`litebike` native, LiteLLM-compatible admin API, `cc-switch` SQLite, static mock).
- [x] Implement a mock/local quota inventory adapter path so quota discovery/scoring can be developed without live endpoints.

Validation

- [ ] Add unit tests for grant resolution and enforcement decision paths.
- [x] Add tests for `*_API_KEY` classification (hostname-only, probe success, probe failure, cached result).
- [ ] Add a no-network test mode for env classification and grant-path selection (probes disabled/mocked).
- [x] Add tests for quota inventory adapter normalization (LiteLLM-compatible, SQLite, mock).
- [ ] `cargo check --quiet` in `litebike`

## Phase 3: OpenAPI3 Facade Spec Generation

- [ ] Implement a generator that emits a self-contained OpenAPI3 facade spec from `literbike` `provider_facade_models` route matrix data.
- [ ] Ensure generated operations reflect templates/actions/mux surfaces and grant requirements where representable.
- [ ] Add a deterministic output test or snapshot for the generator.
- [ ] Decide output location and invocation path (CLI subcommand, build step, or library function) and document it.
- [ ] Identify which template REST surfaces need MCP wrapping metadata so DSEL-defined MCP servers can reuse generated facade definitions.

Validation

- [ ] `cargo test provider_facade_models --quiet` in `literbike`
- [ ] Run generator and verify spec loads in an OpenAPI validator/tooling path (manual or scripted).

## Phase 4: V1 / Models / DSEL-First Superpath Expansion

- [ ] Expand facade matrix rows and/or adapters to cover `v1/`, `models/`, and control-plane paths required for the superpath.
- [ ] Add compatibility mappings for LangGraph-facing or agentic DSEL entry surfaces (routing layer only).
- [ ] Normalize route naming conventions for logging/metrics across v1/model/control surfaces.
- [ ] Document supported path families and fallback semantics.
- [ ] Implement the Rust DSEL primitives needed to express `cc-switch` `.env` execution facade semantics end-to-end.
- [ ] Define the template self-improving agent FSM (states, transitions, guards, review/adapt loop boundaries) in Rust DSEL.
- [ ] Implement a local/no-network execution path for the FSM using template/mock adapters instead of live external API calls.
- [ ] Define pragmatic DSEL model hierarchy primitives for pooling, reviewing, dispatching, and accommodating capability/surface mismatches.
- [x] Add a fragment-first pragmatic model ref parser + unified-port route resolver in `literbike` (selectors/modality metadata + widening candidates) to support DSEL routing without provider-gateway lock-in.
- [x] Add a modelmux MVP lifecycle harness in `literbike` (env normalize/classify + route resolve + provider-key selection + readiness) plus a VM CLI smoke runner with optional `curl` `models` probe support.
- [x] Expose quota inventory scoring/selection in the modelmux MVP lifecycle VM path via a thin companion API plus local `--mock-quota` CLI inputs (QuotaDrainer dry-run development without live quota backends).
- [x] Print QuotaDrainer dry-run arbitration output in the same modelmux MVP VM CLI path (lifecycle + quota selection + dry-run line) to reduce smoke-run context switching.
- [x] Add VM CLI minima flags for QuotaDrainer dry-run arbitration (`--quota-min-req`, `--quota-min-tok`) to force deterministic free-slot rejection / paid fallback during smoke testing.
- [ ] Add FOPL/GOFAI-style symbolic policy primitives (predicates/rules) for task classification and model routing decisions.
- [ ] Map LangChain/LangGraph-style orchestration intents onto those DSEL hierarchy primitives (adapter layer, not framework lock-in).
- [ ] Wire hierarchy dispatch/review flows to shared facade matrix route/model selection and quota/grant policies.
- [ ] Implement model-directed model selection flow (selector/reviewer proposes target model) with explicit DSEL guardrail arbitration before final dispatch.
- [x] Define and implement the QuotaDrainer worker loop in DSEL/FSM terms (discover -> score -> select -> drain -> review -> fallback), reusing the same symbolic policy primitives.
- [ ] Keep OpenClaw/other runtime integration as a thin worker adapter (scheduler/queue bindings), separate from core QuotaDrainer policy logic.
- [ ] Define a shared realtime profile (QUIC/h2) that DSEL-based MCP wrappers can use to expose template REST-backed behaviors.
- [ ] Implement thin MCP adapter/wrapper bindings from DSEL/template REST routes into the realtime profile without duplicating facade matrix route definitions.
- [ ] Add transport/profile tests covering at least one MCP wrapper path over h2 and one QUIC-compatible path (or a mocked QUIC profile if transport implementation is staged).
- [ ] Implement/document DSEL policy primitives for search-key multi-pumping behavior (rotation/fanout/load-sharing/backoff) as needed for `*_SEARCH_API_KEY` parity.
- [ ] Expose DSEL/facade hooks for capability-probe policy (when to probe `models`, cache TTL/refresh strategy, offline mode).
- [ ] Keep live external API/probe adapters out of the critical path while the template FSM slice is implemented and tested.
- [ ] Keep any non-facade `cc-switch` app surfaces explicitly deferred unless they block `.env` execution facade parity.

Validation

- [ ] Add classification tests for new path families in `literbike`.
- [ ] Add integration-level checks in `litebike` for decode/log/count route keys.
- [ ] Add hierarchy tests for pooling/dispatch and at least one review/accommodation flow.
- [ ] Add FSM tests covering state transitions and a bounded self-improvement loop in no-network mode.
- [ ] Add tests for symbolic-rule dispatch and model-directed model selection with policy arbitration outcomes.
- [x] Add QuotaDrainer dry-run tests/fixtures covering free-tier-first draining and paid fallback policy arbitration.

## Phase 5: Hardening and Legacy Retirement

- [ ] Identify and remove redundant legacy `cc-switch`/betanet-era path heuristics after matrix-driven replacements are verified.
- [ ] Execute a `cc-switch` `.env` execution facade parity checklist and document any intentionally deferred non-facade behaviors.
- [ ] Refine the OpenClaw/other-agent guidance addendum with concrete adapter examples (OpenClaw, generic worker runtime) after core FSM APIs stabilize.
- [ ] Add migration notes for operators (env vars, grants, keyvault expectations, logging keys).
- [ ] Perform end-to-end smoke tests for representative provider-compatible paths.
- [ ] Update track metadata/status when implementation is active and phase completion is verified.

Validation

- [ ] `cargo test --quiet` in `literbike` (targeted or full)
- [ ] `cargo test --quiet` in `litebike` (targeted or full)

## Notes / Assumptions

- Assumes `literbike` remains available to `litebike` as a local workspace dependency (currently via local path/symlink).
- The baseline slice listed in `spec.md` is recorded from the user report and not re-verified during `conductor newTrack`.
- `cccache` and `cc-switch` are distinct entities: `cccache_gate` tasks are cache/proxy gate routing work, while `cc-switch` tasks target `.env` execution-facade parity.
- Current conversation priority is `cc-switch` `.env` execution-facade parity; `cccache_gate` migration is compatibility work and may be deferred until parity slices are in place.
- "Real OS key vaults" is interpreted as platform-native secure storage/keychain integration exposed through `litebike`/`literbike` gate interfaces.
- `cc-switch` subsumption in this track is defined by parity of its `.env`-driven execution facade; non-facade surfaces are secondary and may be deferred.
- "multi-key multi-pumping" for `*_SEARCH_API_KEY` is interpreted as a facade-defined multi-key scheduling policy (at least rotation and/or fanout), to be documented explicitly during implementation.
- Generic `*_API_KEY` classification may use hostname and targeted `models` probes; probe execution should be optional and fall back to static inference for offline/locked-down environments.
- "QUIC h2 realtime profile" is interpreted as a shared realtime transport/profile abstraction that can host DSEL-defined MCP wrappers over template REST semantics across h2 and QUIC-capable transports (staged implementation allowed).
- "pragmatic LangChain/LangGraph DSEL model hierarchies" means native Rust DSEL primitives for pool/review/dispatch/accommodate behaviors with thin adapters for framework-facing integration points.
- "template self-improving agent FSM" means a template/policy-constrained Rust DSEL finite-state machine with explicit transitions and review/adaptation loops, testable without network access.
- "FOPL/GOFAI" means explicit symbolic predicates/rules/guardrails in DSEL for task classification and dispatch decisions, optionally incorporating model-proposed routing but never bypassing policy arbitration.
- "QuotaDrainer" means aggressive scheduling of user-owned/authorized free quotas before paid fallbacks, always bounded by explicit budgets, grants, and policy guardrails.

## Validation Notes

- 2026-02-25: `cargo test env_facade_parity --quiet` in `/Users/jim/work/literbike` passed after implementing:
  - `*_SEARCH_API_KEY` grouping + deterministic ordering/auth hints
  - generic `*_API_KEY` hostname-first no-network classification scaffolding and `/models` probe URL candidate generation
  - fragment-first pragmatic model refs (`/free/...`, `/{host,...}/...`) and configurable unified-port route resolver
- 2026-02-25: `cargo test env_facade_parity --quiet` in `/Users/jim/work/literbike` passed after adding:
  - `GenericApiModelsProbe` trait (mockable optional `models` capability probe adapter)
  - `GenericApiModelsProbeCache` (deterministic cached probe result reuse)
  - `normalize_env_pairs_with_generic_api_probe(...)` while preserving `normalize_env_pairs(...)` as no-network default
  - tests for probe success, probe failure fallback, and cached-result classification reuse
- 2026-02-25: modelmux MVP lifecycle TDD slice landed in `/Users/jim/work/literbike/src/env_facade_parity.rs` + VM CLI harness `/Users/jim/work/literbike/src/bin/modelmux_mvp_lifecycle.rs`:
  - `cargo test env_facade_parity --quiet` passed (lifecycle success/failure/probe-cache scenarios)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
  - local CLI smoke run validated `--ignore-process-env` isolated lifecycle execution and readiness output formatting
- 2026-02-25: quota inventory adapter normalization/scoring slice landed in `/Users/jim/work/literbike/src/env_facade_parity.rs`:
  - added `QuotaInventoryAdapter` interface + `StaticMockQuotaInventoryAdapter` for local/mock QuotaDrainer development
  - added normalization functions for LiteLLM-compatible admin records, `cc-switch` SQLite rows, and mock records
  - added route scoring/selection helpers against `PragmaticUnifiedPortRoute`
  - `cargo test env_facade_parity --quiet` passed (includes quota inventory normalization + mock scoring tests; 30 filtered tests)
- 2026-02-25: modelmux MVP quota-selection companion + VM CLI local dry-run path landed in `/Users/jim/work/literbike/src/env_facade_parity.rs` and `/Users/jim/work/literbike/src/bin/modelmux_mvp_lifecycle.rs`:
  - added `evaluate_modelmux_mvp_quota_inventory(...)` + `format_modelmux_mvp_quota_selection_line(...)` to surface route-scored quota candidates beside lifecycle results
  - added CLI `--mock-quota '<slot>::<model_ref_or_id>[;req=N][;tok=N][;free|paid][;selector=TAG]'` for local QuotaDrainer-style slot selection smoke runs
  - `cargo test env_facade_parity --quiet` passed (31 filtered tests)
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (CLI parser tests for `--mock-quota`)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
  - local CLI smoke run printed `quota_*` selection line and preferred `/free/...` mock slot over paid fallback
- 2026-02-25: QuotaDrainer dry-run loop primitive landed in `/Users/jim/work/literbike/src/env_facade_parity.rs`:
  - added no-network `run_modelmux_quota_drainer_dry_run(...)` / `..._with_options(...)` over existing lifecycle+quota scoring primitives
  - implements discover -> score -> select -> fallback -> review dry-run steps with free-first paid-fallback policy and minima gating
  - added dry-run formatter `format_quota_drainer_dry_run_line(...)` for VM/log output
  - added tests for free-tier-first selection and paid fallback when free slots are depleted
  - `cargo test env_facade_parity --quiet` passed (33 filtered tests)
- 2026-02-25: VM CLI quota smoke path now prints dry-run arbitration line in `/Users/jim/work/literbike/src/bin/modelmux_mvp_lifecycle.rs`:
  - wired `run_modelmux_quota_drainer_dry_run(...)` + `format_quota_drainer_dry_run_line(...)` behind existing `--mock-quota` path
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
  - local smoke run printed lifecycle + `quota_*` selection + `quota_drainer_*` arbitration lines in one invocation
- 2026-02-25: VM CLI dry-run minima tuning landed in `/Users/jim/work/literbike/src/bin/modelmux_mvp_lifecycle.rs`:
  - added `--quota-min-req <n>` and `--quota-min-tok <n>` flags wired to `QuotaDrainerDryRunOptions` / `run_modelmux_quota_drainer_dry_run_with_options(...)`
  - extended CLI parser tests for minima flags
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
  - local smoke run forced paid fallback (`fallback_used=true`) with free slot below configured minima
- 2026-02-25: VM CLI parser hardening for dry-run minima flags:
  - added CLI parser test coverage for invalid `--quota-min-req` / `--quota-min-tok` values (error strings asserted)
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`3` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-25: VM CLI parser hardening for missing dry-run minima flag values:
  - added CLI parser test coverage for missing values after `--quota-min-req` / `--quota-min-tok`
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`4` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-25: VM CLI parser hardening for `--mock-quota` missing value:
  - added CLI parser test coverage for missing value after `--mock-quota`
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`5` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-25: VM CLI parser hardening for invalid `--port` value:
  - added CLI parser test coverage asserting invalid `--port` value error
  - marked first `100% Slices (Zero-Discovery)` parser-hardening stub complete
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`6` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-25: VM CLI parser hardening for missing `--port` value:
  - added CLI parser test coverage asserting missing value after `--port`
  - marked second `100% Slices (Zero-Discovery)` parser-hardening stub complete
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`7` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-26: VM CLI parser hardening for invalid `--probe-timeout-secs` value:
  - added CLI parser test coverage asserting invalid `--probe-timeout-secs` value error
  - marked third `100% Slices (Zero-Discovery)` parser-hardening stub complete
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`8` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-26: VM CLI parser hardening for missing `--probe-timeout-secs` value:
  - added CLI parser test coverage asserting missing value after `--probe-timeout-secs`
  - marked fourth `100% Slices (Zero-Discovery)` parser-hardening stub complete
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`9` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-26: VM CLI parser hardening for missing `--agent-name` value:
  - added CLI parser test coverage asserting missing value after `--agent-name`
  - marked fifth `100% Slices (Zero-Discovery)` parser-hardening stub complete
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`10` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-26: VM CLI parser hardening for missing `--env-file` value:
  - added CLI parser test coverage asserting missing value after `--env-file`
  - marked sixth `100% Slices (Zero-Discovery)` parser-hardening stub complete
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`11` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
- 2026-02-26: VM CLI parser hardening for missing `--probe` value:
  - added CLI parser test coverage asserting missing value after `--probe`
  - marked seventh `100% Slices (Zero-Discovery)` parser-hardening stub complete
  - `cargo test --quiet --bin modelmux_mvp_lifecycle` passed (`12` CLI parser tests)
  - `cargo check --quiet --bin modelmux_mvp_lifecycle` passed
