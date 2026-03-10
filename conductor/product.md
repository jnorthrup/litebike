# Product

## What this repo is

`litebike` is the primary deployable runtime shell for the `litebike` /
`literbike` system. It is the small Rust multi-call binary that must remain
useful on its own while also accepting a heavier `literbike` "heart" when that
companion is present. In concrete terms, `litebike` owns the edge/runtime
surface and `literbike` supplies deeper library/backplane capabilities behind a
gated import boundary.

`litebike` must remain complete enough to launch, proxy, and operate without
`literbike`. When `literbike` is present, it deepens the shell with transport,
model, and DSEL capability, but does not take ownership of the outer operator
surface.

The canonical composed surface is `litebike` `agent8888` on port `8888`. When
`literbike` is mounted, that single ingress/operator surface subsumes both
repos rather than creating a second front door.

`litebike` provides:

- **Network Utilities**: `ifconfig`, `ip`, `route`, `netstat` emulation using direct syscalls
- **Proxy Server**: Multi-protocol proxy on unified port (HTTP, SOCKS5, TLS, DoH)
- **System Info**: Interface probing, carrier detection, radio info
- **Trading Integration**: Origin mirroring for crypto exchange APIs (e.g., Binance)
- **Operator Shell**: launch/install/automation ownership for the lightweight runtime surface

## Product Direction

- Maintain syscall-based implementation for Android/Termux compatibility (no `/proc`, `/sys` dependencies)
- Enhance proxy server capabilities for trading bot integrations
- Keep `litebike` small enough to stay launchable on constrained hosts and macOS menu-bar/operator surfaces
- Import `literbike` as the gated "heart" layer when heavier model facade, DSEL, QUIC, or transport composition is available
- Avoid reversing ownership: `literbike` may animate `litebike`, but it does not replace `litebike` as the primary shell

## Primary Consumers

- **Freqtrade ring agent**: Proxy and transport layer
- **Android/Termux users**: Network utilities in restricted environments
- **Quantitative traders**: Exchange API mirroring and proxy services
- **macOS operators**: menu-bar launch, auto-proxy, SSH, git push, and remote build workflows

## Product Constraints

- Brownfield codebase: Preserve existing behavior where possible
- Cross-platform: Android, macOS, Linux support
- Performance: Syscall-based for speed (7x faster than traditional tools)
- Minimal dependencies: No external parsing libraries

## Relationship to Other Projects

- **literbike**: Gated heart/backplane library for deeper transport, model facade, and DSEL capability
- **freqtrade**: Crypto trading bot with litebike integration
- **moneyfan**: HRM trading system using litebike proxy capabilities
