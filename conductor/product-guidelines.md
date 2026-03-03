# Product Guidelines

## Brand & Voice
- **Tone:** Technical, practical, performance-oriented. Prioritize syscall efficiency over abstraction.
- **Design Philosophy:** "Form follows function." High-performance networking and proxy logic must be the primary focus.

## User Experience (UX)
- **Modularity:** Every component (proxy, utilities, transport) should be independently testable and swappable.
- **Observability:** High-fidelity logging for proxy requests and network state changes.

## Technical Identity
- **Reliability:** 100% test coverage for critical paths (proxy routing, syscall interfaces).
- **Auditability:** Every proxy decision and network state change should be traceable in logs.
- **Performance:** Syscall-based implementation for maximum speed (7x faster than traditional tools).
- **Cross-Platform:** Android/Termux, macOS, and Linux support without platform-specific code.

## Product Principles
- Minimal dependencies over feature richness
- Direct syscalls over /proc,/sys parsing
- Trading integration over generic proxy features
- Performance over convenience
