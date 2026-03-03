# `cc-switch` `.env` Execution Facade Parity Inventory (Initial)

## Scope Boundary (Important)

- This artifact targets `cc-switch` `.env` execution-facade parity.
- `cccache` / `cccache_gate` is a distinct cache/proxy gate concern and is not the primary feature focus for this slice.

## Purpose

Capture the `.env` semantics that matter for `cc-switch` replacement and map them onto `literbike` provider facade ENV roles + recognition rules, with explicit gaps.

References:

- `literbike::provider_facade_models::provider_facade_object_models()`
- `literbike::provider_facade_models::facade_v1_route_matrix()`
- `literbike::provider_facade_models::EnvVarRole`
- `literbike::provider_facade_models::EnvRecognitionRule`

## Known `literbike` ENV Roles (Relevant to Parity)

From `/Users/jim/work/literbike/src/provider_facade_models.rs`:

- `ProviderId`
- `BaseUrl`
- `Model`
- `ReasoningModel`
- `ApiKey`
- `AccessToken`
- `RefreshToken`
- `OAuthClientId`
- `OAuthClientSecret`
- `OAuthTokenUrl`
- `OAuthAuthUrl`
- `OAuthAudience`
- `OAuthScopes`
- `PubkeyFingerprint`
- `PubkeyMaterial`
- `PubkeyAllowedProviders`
- `KeymuxUrl`
- `KeyVaultUrl`
- `MuxPolicy`
- `QuotaProfile`
- `TemplateOverride`
- `WrapperPath`
- `ControlToken`

## Known `literbike` ENV Recognition Rules (Relevant to Parity)

Current rule IDs in `facade_v1_route_matrix().env_rules` include:

- `openai-compatible`
- `anthropic-compatible`
- `gemini-native`
- `opencode-zen`
- `control-plane`

These should be the first-pass static inference layer before any optional capability probing.

## `.env` Parity Inventory (Initial Mapping)

## Core execution-facade controls

| `cc-switch`-style env semantic | Example keys | `literbike` role | Notes / parity status |
|---|---|---|---|
| Provider selector | `MODEL_PROVIDER` | `ProviderId` | Direct mapping available |
| Model selector | `MODEL_NAME`, `OPENAI_MODEL`, `ANTHROPIC_MODEL` | `Model` | Direct mapping available; provider-specific aliases remain provider-owned |
| Reasoning model selector | `ANTHROPIC_REASONING_MODEL` | `ReasoningModel` | Direct mapping available |
| Base URL override | `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `GOOGLE_GEMINI_BASE_URL` | `BaseUrl` | Direct mapping available |
| Template override | `MODEL_API_TEMPLATE` | `TemplateOverride` | Direct mapping available |
| Mux/routing policy | `MODEL_MUX_POLICY` | `MuxPolicy` | Direct mapping available; DSEL policy integration pending |
| Quota policy/profile | `MODEL_QUOTA_PROFILE` | `QuotaProfile` | Direct mapping available; quota macro join behavior pending |
| Wrapper path override | `FACADE_V1_WRAPPER` | `WrapperPath` | Direct mapping available; route validation/guardrails pending |
| Control-plane token | `CC_SWITCH_CONTROL_TOKEN` | `ControlToken` | Direct mapping available |
| Keymux endpoint | `KEYMUX_URL` | `KeymuxUrl` | Direct mapping available |
| Key vault endpoint | `KEYVAULT_URL` | `KeyVaultUrl` | Direct mapping available |

## Provider auth/env bindings (typed)

| Env keys | `literbike` role | Rule family hints | Notes |
|---|---|---|---|
| `OPENAI_API_KEY` | `ApiKey` | `openai-compatible` | Bearer/API-key style auth template inference in `literbike` |
| `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` | `ApiKey` | `anthropic-compatible` | Alias already modeled in `literbike` |
| `GEMINI_API_KEY`, `GOOGLE_API_KEY` | `ApiKey` | `gemini-native` | Alias already modeled in `literbike` |

## Explicit parity semantics required by this track

## 1. `*_SEARCH_API_KEY` semantics (websearch + multi-key pumping)

Required parity behavior:

- Any matching `*_SEARCH_API_KEY` binding enables websearch capability in the execution facade.
- One-or-many matching keys are supported.
- Multiple keys participate in documented "multi-key multi-pumping" policy (minimum: rotation and/or fanout; load-sharing/backoff optional).

Proposed typed mapping (initial):

- Key material -> `EnvVarRole::ApiKey`
- Capability tag -> DSEL policy/facade metadata (`search-enabled`)
- Scheduling policy -> DSEL symbolic policy primitive + quota/profile policy

Normalization rules (initial draft for implementation):

- Suffix match: `*_SEARCH_API_KEY`
- Allow indexed variants: `FOO_SEARCH_API_KEY_1`, `FOO_SEARCH_API_KEY_2` (implementation choice, document exact regex)
- Allow provider/exchange prefixes (e.g., `SERPAPI_SEARCH_API_KEY`, `EXAMPLE_SEARCH_API_KEY`)
- Preserve declaration order for deterministic default rotation unless policy overrides

Open gaps:

- Final naming grammar for indexed keys
- Whether comma-delimited values are accepted (prefer explicit separate keys for determinism)
- Exact default multi-pumping policy in no-network mode (simulate vs static selection)

## 2. Generic `*_API_KEY` semantics (exchange vs model-provider)

Required parity behavior:

- Generic `*_API_KEY` keys are not assumed to be model-provider keys.
- They may represent exchange APIs or model-provider APIs.
- Classification is hostname-first, with optional targeted capability probe (`/models` or equivalent) when adapters are enabled.
- No-network/offline mode falls back to static rule/hostname inference.

Proposed typed mapping (initial):

- Key material -> `EnvVarRole::ApiKey`
- Classification output -> DSEL policy tags / normalized candidate class:
  - `api_kind=model-provider`
  - `api_kind=exchange`
  - `api_kind=unknown` (guarded fallback)

Classification pipeline (initial):

1. Parse env key + optional paired base URL/host envs (`*_BASE_URL`, provider-specific base URLs)
2. Apply `literbike` `EnvRecognitionRule` static hints (`openai-compatible`, `anthropic-compatible`, `gemini-native`, etc.)
3. If unresolved and probing enabled, use targeted `models` capability probe adapter
4. Cache probe result for deterministic reuse
5. If still unresolved, keep `unknown` and require explicit DSEL policy/override

Open gaps:

- Exact paired-host env discovery rules for arbitrary prefixes
- Probe result cache schema + TTL policy
- `unknown` class dispatch behavior defaults (deny vs sandbox vs manual override)

## Initial parity focus (what to build first)

Primary feature focus:

- `cc-switch` `.env` execution facade parity (not `cccache`)
- Template-first DSEL/FSM semantics
- Local/no-network deterministic behavior
- Symbolic policy + guardrailed dispatch

Immediate next implementation slices after this inventory:

1. Rust adapter for normalized env key parsing -> `literbike` `EnvVarRole` mappings
2. No-network classification path for generic `*_API_KEY`
3. `*_SEARCH_API_KEY` aggregator + deterministic multi-key policy primitive
4. Tests/fixtures for the above (no-network first)

## Validation Status (This Artifact)

- Source-validated against `/Users/jim/work/literbike/src/provider_facade_models.rs` for role/rule names
- Behavioral semantics are track-defined requirements and initial mapping proposals (to be implemented and tested)
