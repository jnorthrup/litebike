# Tech Stack

## Languages

- Rust (primary)

## Core Components

- `litebike` (proxy/router/gates runtime)
- `literbike` (shared taxonomy/facade/classification library; local path dependency)

## Build & Validation

- `cargo check`
- `cargo test`

## Notes

- Local development uses a path-linked `literbike` dependency in this workspace.
- Conductor track implementation should prefer targeted tests/checks in dirty worktrees.
