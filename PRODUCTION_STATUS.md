# LiteBike Production Status

## Shipped Edge-Facing Capabilities

### Binary Inventory
- **modelmux** (src/bin/modelmux.rs): OpenAI-compatible model gateway. When invoked as agent8888, auto-starts on port 8888.
- **dsel** (src/bin/dsel.rs): Decision/selection utility binary.
- **modelmux-cli** (src/bin/modelmux-cli.rs): Console launcher with argv[0] detection for agent8888, ollama, lmstudio modes.

### Port Configuration
- Default bind port: 8888 (not 8080). Configurable via LITEBIKE_BIND_PORT environment variable.
- agent8888 mode: Auto-starts modelmux on port 8888 when invoked with executable name agent8888.

### Protocol Support (via --features proxy)
- HTTP/HTTPS proxy with CONNECT tunneling
- SOCKS5 proxy
- PAC/WPAD detection
- UPnP/SSDP detection

All protocols auto-detected on single unified port 8888.

### Network Utilities (src/syscall_net.rs)
- Direct syscall-based implementation (no /proc, /sys, /dev dependencies)
- list_interfaces() - enumerate network interfaces via getifaddrs
- get_default_gateway() - IPv4 default route via proc/net or netstat
- get_routes() - routing table inspection
- socket_create, socket_bind, socket_connect, socket_accept, socket_read, socket_write, socket_close - raw syscall wrappers
- Interface classification (IPv4/IPv6 scope, private/cgnat/public)
- Android carrier property detection via getprop

### macOS Integration
- Operator Bar App: Native macOS menu bar application built via tools/build_macos_control_plane_app.sh
- Operator Actions: tools/litebike_operator_actions.sh provides:
  - build-release, git-push-current, deploy-remote
  - proxy-status, proxy-ssh, proxy-stop
  - sync-termux, open-ssh-terminal

### Shell/Backplane Doctrine
- litebike (port 8888): canonical ingress/operator surface - shell ownership of binary and port
- literbike (when present): runs behind litebike as heavier transport/service runtime
- litebike subsumes both repos when literbike is present

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| LITEBIKE_BIND_PORT | 8888 | Proxy bind port |
| LITEBIKE_INTERFACE | swlan0 | Ingress interface |
| LITEBIKE_LOG | info | Log level |
| EGRESS_INTERFACE | auto | Egress interface |
| LITEBIKE_BIND_ADDR | 0.0.0.0 | Specific bind address |

## Build Status
- cargo build --release produces optimized binary with LTO
- --features proxy enables warp-based proxy server mode

## Whats NOT Shipped
- Authentication (SOCKS5 has no auth)
- Rate limiting
- Full metrics/monitoring
- Configuration file system (uses env vars)
- Hot reload
- HTTP/2 or HTTP/3
- WebSocket handling
- Connection limits

## Production Posture: SHIPPED

litebike is the operational edge surface:
- Port 8888 is the canonical ingress
- Modelmux/agent8888 runs as the model multiplexing gateway
- Syscall networking is production-ready for constrained hosts
- macOS operator bar is built and installable
- Remote deploy/sync workflows are operational via operator actions
