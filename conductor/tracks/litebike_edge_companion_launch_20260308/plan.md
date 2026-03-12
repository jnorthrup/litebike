<!-- tokens: T004 -->

# Plan: LiteBike Edge Companion Launch

## Phase 1: Boundary Lock

- [x] Inventory the currently shipped `litebike` edge-facing capabilities.
- [x] Remove or supersede stale positioning that treats `literbike` as a future
  fork target instead of the current companion.
- [x] Define the shortest accurate sentence for the repo split:
  `litebike` as primary shell/runtime, `literbike` as gated heart/backplane.

## Phase 2: Launch Narrative

- [x] Publish a launch-ready explanation of `litebike` as the lightweight
  stacked proxy, network utility, and operator shell surface.
- [x] Describe the gate/channel layer as early traffic classification and local
  edge routing.
- [x] Add a simple deployment path showing `client -> litebike -> literbike`.

## Phase 3: Operational Fit

- [x] Improve `modelmux status` control-path UX by printing runtime control summary,
  keymux key presence, and explicit next commands (`modelmux control state`,
  `modelmux test`) instead of a dead-end icon-only status note.
- [x] Confirm the launch story matches current commands, modules, and proxy
  behavior in the repo.
- [x] Call out the constrained-host and local-edge deployment advantages.
- [x] Identify any missing packaging or startup notes that block a clean launch.

## Phase 4: Companion Alignment

- [x] Cross-reference the matching `literbike` launch track.
- [x] Make the boundary crisp enough that future work can be triaged into the
  correct repo without ambiguity.
- [x] Keep `litebike` scope narrow during launch hardening while preserving
  shell ownership.

## Course Correction Notes

- 2026-03-10: boundary truth corrected to treat `litebike` as the deployable
  shell and `literbike` as the gated heart/backplane imported into it when
  available.
- 2026-03-10: matching `literbike` conductor truth now uses the same shell/heart
  split, with direct `literbike` launch language demoted to secondary
  backplane/validation modes instead of competing shell ownership.
- 2026-03-10: clarified that `litebike` `agent8888` on port `8888` is the one
  composed ingress/operator surface and subsumes both repos when `literbike` is
  mounted.
- 2026-03-10: `README.md` now carries the public launch narrative for
  `litebike` as the small shell/operator front door, including the
  `client/app -> litebike agent8888 -> literbike` deployment path and explicit
  `literbike` heart/backplane wording.
- 2026-03-10: `README.md` now documents the native macOS operator bar build,
  install, signing, remote-action environment, and first-launch workflow so the
  packaging/startup launch notes no longer live only in scripts and source.
- 2026-03-10: `README.md` now ties the launch story to the actual repo surfaces:
  constrained-host/direct-syscall deployment, lightweight proxy mode vs
  `agent8888`/modelmux on port `8888`, and operator-bar remote-host fallback
  behavior.
- 2026-03-10: `README.md` now states the repo boundary directly: `litebike`
  owns the shell, syscall utilities, proxy mode, `agent8888`/modelmux entry,
  and operator actions, while `literbike` is the optional backplane for the
  heavier transport and service runtime.
- 2026-03-10: `PRODUCTION_STATUS.md` now inventories the shipped edge-facing
  surfaces and removes stale `8080`/proof-of-concept/broken-main-binary
  positioning so launch materials match the current shell/backplane doctrine.
