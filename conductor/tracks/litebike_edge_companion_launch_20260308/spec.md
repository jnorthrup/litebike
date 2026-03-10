<!-- tokens: T003 -->

# Spec: LiteBike Edge Companion Launch

## Overview

This track positions `litebike` as the primary launch shell of the
`litebike`/`literbike` system. `litebike` should be launch-ready as the small
stacked proxy, interface-aware ingress process, and operator-facing runtime that
runs close to the client. When `literbike` is present, it should function as
the heavier "heart" or backplane imported into `litebike`, not as the owner of
the outer shell.

The emphasis is not to turn `litebike` into the full unified services runtime.
The emphasis is to make it clear, operable, and measurable as the lightweight
runtime shell that can accept `literbike` capabilities through a gated boundary.
The canonical composed surface is `litebike` `agent8888` on port `8888`, and
that one surface must subsume both repo capabilities when `literbike` is
present.

## Problem

- The repo already contains the right primitives for edge operation:
  syscall-based network inspection, gate-based routing, Knox-aware proxying,
  channel management, and multi-call utility behavior.
- The current repo story is still muddy in places because some historical docs
  describe `literbike` as a fork target instead of the heavier companion repo it
  now is, while other recent work drifts toward giving `literbike` ownership of
  operator surfaces that belong to `litebike`.
- Launching both repos without a crisp shell/heart split risks overlap,
  duplicate work, and unclear operational boundaries.

## Goals

- Define `litebike` as the primary edge/runtime shell and lightweight routing layer.
- Keep `litebike` small enough to deploy on constrained or local environments.
- Preserve the single-port, protocol-sniffing proxy story as the primary entry
  point for mixed traffic.
- Make `litebike` `agent8888` the explicit composed ingress/operator surface
  that subsumes both repos when `literbike` is mounted.
- Make the handoff boundary to `literbike` explicit in docs and launch notes:
  `litebike` owns the shell; `literbike` provides the heavier heart/backplane.

## Functional Requirements

### 1. Edge Ingress Identity

- `litebike` must be documented and positioned as the local or edge process that
  binds ports, detects protocols, and chooses local handling versus upstream
  delegation.
- `litebike` must also be documented as the owner of the deployable operator
  shell: install surface, menu-bar/operator automation, and launch entrypoint.
- `litebike` must be documented as the owner of the canonical `agent8888`
  surface on port `8888`, with `literbike` capabilities mounted behind that
  one surface instead of beside it.
- The primary launch story should center on:
  - single-port ingress
  - protocol sniffing/classification
  - interface selection
  - Knox-aware handling
  - syscall-backed network utilities
  - operator shell ownership even when `literbike` is present

### 2. Lightweight Stacked Proxy Behavior

- `litebike` must remain optimized for lightweight stacked routing rather than
  heavy service orchestration.
- Gate and channel behavior should be presented as an edge routing stack:
  inspect, classify, select a local handler, or forward toward a heavier
  runtime.
- The repo must avoid implying that `litebike` owns all transport, storage, API
  translation, or durable service responsibilities.
- The repo must also avoid implying that `literbike` takes ownership of
  `litebike`'s launch shell just because `literbike` capabilities are mounted.

### 3. Cohesive Companion Boundary

- The launch materials must explicitly state that `literbike` is the heavier
  heart/backplane imported into `litebike`, not the replacement outer shell.
- `litebike` launch docs must describe expected handoff patterns into
  `literbike` for:
  - QUIC-heavy transport work
  - API translation
  - DHT and content-addressed service flows
  - broader service composition
  - model/DSEL expansion once the gated heart is available

### 4. Launch Readiness Artifacts

- Provide a launch-oriented architecture note or track summary that answers:
  - what `litebike` is
  - what `litebike` is not
  - how it pairs with `literbike`
  - what a typical deployment path looks like
- Ensure the launch story is accurate to the current codebase, not speculative.

## Non-Functional Requirements

- Preserve small-footprint deployability and constrained-environment usefulness.
- Favor additive documentation and packaging clarification over broad code churn.
- Avoid introducing new public APIs unless current code evidence requires them.
- Keep language concrete and operational; avoid invented architecture nouns.

## Acceptance Criteria

1. `litebike` has a launch track that clearly defines it as the edge ingress and
   lightweight stacked proxy shell of the two-repo system.
2. The track explicitly defines `literbike` as the heavier heart/backplane
   companion imported into that shell.
3. The launch materials avoid stale “fork into literbike” positioning for the
   active product split.
4. A typical deployment flow from client to `litebike` to `literbike` is
   documented in launch-ready language.
5. The launch materials explicitly define `litebike` `agent8888` as the single
   composed ingress/operator surface that subsumes both repos.

## Out of Scope

- Rewriting `litebike` into a heavy service runtime
- Moving QUIC, DHT, CAS, or API translation responsibilities into `litebike`
- Large-scale refactors unrelated to launch positioning
