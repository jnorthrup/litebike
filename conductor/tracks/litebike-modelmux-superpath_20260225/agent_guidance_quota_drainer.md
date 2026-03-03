# Agent Guidance Addendum: QuotaDrainer (OpenClaw or Other Agent Runtimes)

## Purpose

This addendum defines a local-first worker profile ("QuotaDrainer") that can guide OpenClaw or any other agent runtime.

Primary job:

- discover available quota buckets,
- score viable model/provider options for queued work,
- drain user-owned free quotas first,
- fall back to paid tiers only when policy allows.

This is guidance for runtime adapters. The core behavior should be implemented as Rust DSEL + template/FSM policy, not hardcoded to any one agent framework.

## Design Constraints (Track-Aligned)

- Local-first and self-hosted.
- No external SaaS control plane required.
- Core logic must run in no-network/dry-run mode.
- Live API calls and capability probes are optional adapters.
- All dispatch is mediated by explicit DSEL guardrails.
- Model-directed model selection is allowed only through policy arbitration.

## Canonical Worker Loop (DSEL/FSM View)

The QuotaDrainer worker should be expressible as a bounded FSM with explicit transitions:

1. `Discover`
2. `NormalizeInventory`
3. `ScoreProject`
4. `SelectCandidate`
5. `Dispatch`
6. `ReviewOutcome`
7. `AccommodateOrRetry`
8. `FallbackPaid` (guarded)
9. `PersistAndReport`

Suggested loop shape:

- `Discover -> NormalizeInventory -> ScoreProject -> SelectCandidate -> Dispatch`
- `Dispatch -> ReviewOutcome`
- `ReviewOutcome -> AccommodateOrRetry` when policy detects mismatch/failure/retry condition
- `ReviewOutcome -> PersistAndReport` on success
- `AccommodateOrRetry -> SelectCandidate` for next free candidate
- `AccommodateOrRetry -> FallbackPaid` only if explicit policy permits
- `FallbackPaid -> Dispatch`

## Quota Inventory Sources (Pluggable Adapters)

Quota inventory must be adapter-based so the same policy works with mocks and real systems.

Supported source categories:

- `litebike` native budget/key/quota endpoints (target architecture)
- LiteLLM-compatible admin endpoints (compatibility adapter)
- `cc-switch` SQLite presets/quota metadata (local SSOT or migration source)
- Static fixture/mock inventories for dry-run tests

Normalization target (conceptual fields):

- `bucket_id`
- `model_or_pool`
- `provider_family`
- `quota_kind` (`free`, `paid`, `trial`, `copilot`, etc.)
- `remaining_budget`
- `rpm_left`
- `tpm_left`
- `grants_required`
- `capabilities`
- `route_template`
- `policy_tags`

## Project Queue Inputs (Pluggable)

Worker input queues are also adapter-based:

- OpenClaw queue/jobs
- Generic local SQLite queue
- Filesystem-backed queue
- Git issues/tasks mirrored locally
- Static fixtures for tests

The QuotaDrainer policy should not depend on a specific queue backend.

## Scoring and Dispatch Policy (FOPL/GOFAI)

Use explicit symbolic predicates/rules in DSEL for candidate selection.

Required policy dimensions:

- free-tier-first preference
- capability fit (tools/search/context/response mode)
- quota sufficiency (`remaining >= estimated_demand`)
- rate-limit viability (`rpm_left`, `tpm_left`)
- grant availability
- route/template compatibility
- fallback ordering

Example policy intent (not syntax):

- If `project.kind = coding` and `candidate.free = true` and `candidate.capability >= required`, prefer highest safe remaining free budget.
- If reviewer/selector model proposes a different serving model, accept only if policy guardrails pass.
- If no free candidate passes guards, allow `FallbackPaid` only when project priority and budget policy permit.

## Model-Directed Model Selection (Guarded)

A model may recommend which model should serve a task.

This is allowed, but only as a proposal signal. Final dispatch must pass:

- DSEL symbolic rules
- quota/budget checks
- capability checks
- grant checks
- safety/policy checks
- fallback rules

No model proposal may bypass policy arbitration.

## OpenClaw / Other Agent Runtime Mapping

This addendum is runtime-agnostic. For OpenClaw (or similar systems), keep framework integration thin:

- scheduler trigger -> invokes QuotaDrainer FSM
- queue adapter -> maps framework jobs into normalized project inputs
- dispatch adapter -> calls `litebike` facade (or compatibility endpoint)
- reporting adapter -> writes results back to runtime queue/logs

Optional operator patterns:

- Tailscale/Cloudflared/reverse tunnels for "phone-home" dev-host access
- Kilo server / VPS always-on worker host
- Termux router for mobile/local-first routing

These are deployment choices, not policy semantics.

## No-Network / Dry-Run Mode (Default for Early Development)

First useful slice should support:

- mock quota inventory
- mock queue inputs
- mock dispatch outcomes
- deterministic scoring/selection
- bounded retries/accommodation
- explicit paid-fallback denial/approval behavior

This mode is the baseline for tests and self-improvement loop development.

## Self-Improvement (Template-Bounded)

QuotaDrainer may be "self-improving" only within template/policy bounds:

- tune scoring weights/policy thresholds through explicit config/templates
- record outcomes and propose updates
- require review/approval path for policy changes (human or guarded agent path)
- preserve reproducible behavior in tests

No unconstrained runtime mutation of core policy logic.

## Security and Ownership Guardrails

- Only use user-owned or explicitly authorized quotas.
- Respect budget caps and grant requirements.
- Prefer local storage and OS key vault/keymux-backed secrets.
- Keep audit logs for quota usage and fallback decisions.
- Make dry-run mode the default in new environments.

## Implementation Notes for This Track

- Core QuotaDrainer behavior belongs in Rust DSEL/FSM primitives, not in framework glue code.
- OpenClaw support should be delivered as an adapter profile that reuses the same FSM/policy core.
- LiteLLM-compatible endpoints may be supported as migration/compatibility adapters while `litebike` evolves into the primary facade.
