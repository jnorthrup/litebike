# Tech Stack

## Languages

- Rust (primary)

## Core Components

- `litebike` (primary runtime shell, proxy/router/gates executable, operator surface owner)
- `literbike` (gated heart/backplane library for heavier taxonomy/facade/classification/model work)

## Build & Validation

- `cargo check`
- `cargo test`

## Notes

- Target architecture treats `literbike` as the library heart that can be mounted into `litebike` without transferring shell ownership.
- Current code/docs may still show mixed lineage; repo-local `/conductor/` truth should prefer `litebike`-shell / `literbike`-heart wording until the Cargo edge is fully reconciled.
- Conductor track implementation should prefer targeted tests/checks in dirty worktrees.
