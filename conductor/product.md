# Product

## What this repo is

`litebike` is a Rust multi-call binary that provides network utilities and proxy services. It serves as a companion to `literbike` and provides:

- **Network Utilities**: `ifconfig`, `ip`, `route`, `netstat` emulation using direct syscalls
- **Proxy Server**: Multi-protocol proxy on unified port (HTTP, SOCKS5, TLS, DoH)
- **System Info**: Interface probing, carrier detection, radio info
- **Trading Integration**: Origin mirroring for crypto exchange APIs (e.g., Binance)

## Product Direction

- Maintain syscall-based implementation for Android/Termux compatibility (no `/proc`, `/sys` dependencies)
- Enhance proxy server capabilities for trading bot integrations
- Improve QUIC transport support via literbike integration
- Support model facade and DSEL quota management for freqtrade ring agent

## Primary Consumers

- **Freqtrade ring agent**: Proxy and transport layer
- **Android/Termux users**: Network utilities in restricted environments
- **Quantitative traders**: Exchange API mirroring and proxy services

## Product Constraints

- Brownfield codebase: Preserve existing behavior where possible
- Cross-platform: Android, macOS, Linux support
- Performance: Syscall-based for speed (7x faster than traditional tools)
- Minimal dependencies: No external parsing libraries

## Relationship to Other Projects

- **literbike**: Core Rust library (local path dependency)
- **freqtrade**: Crypto trading bot with litebike integration
- **moneyfan**: HRM trading system using litebike proxy capabilities
