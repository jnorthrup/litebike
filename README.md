# LiteBike - Edge Proxy and Network Utilities

> **The small shell / operator front door**. `litebike` on port 8888 is the canonical ingress surface that subsumes both repos when `literbike` is present. It provides syscall-driven network tools, protocol detection, and lightweight stacked proxy routing.
> **Gated heart/backplane**: `literbike` runs behind `litebike` as the heavier unified traffic and service runtime.

![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Android%20%7C%20macOS%20%7C%20Linux-green.svg)

## Overview

`litebike` is the lightweight edge half of a two-repo system. The **`litebike` agent on port 8888** is the canonical ingress/operator surface—clients and apps connect here. When `literbike` is present, `litebike` subsumes both repos: it handles local proxying, interface discovery, Knox-aware handling, and command-line network tooling, delegating heavier transport and service work to `literbike` behind it.

**Constrained-Host / Local-Edge Deployment**: litebike runs lean on devices where resources are limited—Android/Termux, embedded systems, or any host where a full transport stack is impractical. It uses direct syscalls ([`src/syscall_net.rs`](src/syscall_net.rs:1)) for network operations, avoiding `/proc`, `/sys`, or `/dev` dependencies. The proxy mode implements lightweight single-port edge routing: it inspects early bytes, classifies the protocol (HTTP, SOCKS5, TLS, DoH, etc.), and either handles locally or forwards to `literbike` behind it.

- **`litebike`** (port 8888): edge ingress, local proxying, interface discovery, Knox-aware handling, and command-line network tooling — the small shell/operator front door
- **`literbike`**: the gated heart/backplane — heavier unified traffic and service runtime, including QUIC, API translation, DHT, content-addressed storage, and service adapters

In practice, `litebike` is the lean edge process you can drop onto constrained hosts, while `literbike` is the heavier backplane when you need broader transport and service unification.

LiteBike provides:

- **Network Utilities**: `ifconfig`, `ip`, `route`, `netstat` emulation
- **Proxy Server**: Multi-protocol proxy on unified port (HTTP, SOCKS5, TLS, DoH)
- **System Info**: Interface probing, carrier detection, radio info
- **Snapshot/Watch**: Configuration snapshots and live monitoring

All utilities use direct syscalls (no `/proc`, `/sys`, `/dev` dependencies) - ideal for Android/Termux and restricted environments.

## Installation

```bash
# Build from source
cargo build --release

# Install system-wide (optional)
./install-system-wide.sh
```

## Usage

### Multi-Call Binary

LiteBike detects its function from the invocation name (`argv[0]`):

```bash
# Direct invocation
litebike ifconfig [interface]
litebike ip addr show
litebike route print
litebike netstat -an

# Or create symlinks
ln -s /usr/local/bin/litebike /usr/local/bin/ifconfig
ln -s /usr/local/bin/litebike /usr/local/bin/netstat
ln -s /usr/local/bin/litebike /usr/local/bin/route
ln -s /usr/local/bin/litebike /usr/local/bin/ip

# Now use like traditional tools
ifconfig
netstat -rn
route -n
ip addr
```

### Commands

| Command | Description | Example |
|---------|-------------|---------|
| `ifconfig [iface]` | List interfaces and addresses | `litebike ifconfig wlan0` |
| `ip [args]` | IP utility emulation | `litebike ip addr show` |
| `route` | Print routing table | `litebike route` |
| `netstat [args]` | Show socket states | `litebike netstat -an` |
| `probe` | Show egress selections | `litebike probe` |
| `domains` | Domain info utility | `litebike domains` |
| `carrier` | Carrier info | `litebike carrier` |
| `radios [args]` | Radio info utility | `litebike radios` |
| `snapshot [args]` | Print config snapshot | `litebike snapshot` |
| `watch [args]` | Watch utility | `litebike watch --interval 5` |

### Proxy Server Mode

Start litebike as a multi-protocol proxy (requires `proxy` feature, see [`Cargo.toml:75`](Cargo.toml:75)):

```bash
# Default: listen on swlan0:8888, egress via rmnet*
litebike --proxy

# Custom bind address and port
litebike --proxy --bind 0.0.0.0:8080

# Specify interface
litebike --proxy --interface wlan0 --egress rmnet0

# Enable logging
RUST_LOG=debug litebike --proxy
```

**Supported Protocols** (auto-detected on single port 8888):

- HTTP/HTTPS proxy
- SOCKS5
- TLS tunneling
- DNS over HTTPS (DoH)
- PAC/WPAD
- Bonjour/mDNS
- UPnP

This routing layer is intentionally lightweight. It behaves like a stacked edge router: inspect early bytes, classify quickly, then hand traffic to the minimal local handler or forward it toward heavier services behind `literbike`.

**Note**: The proxy mode (port 8888) is separate from the `agent8888` mode. `agent8888` is the modelmux binary invoked as `agent8888`, which auto-starts on port 8888 (see [`src/bin/modelmux-cli.rs:57-59`](src/bin/modelmux-cli.rs:57) and [`lines 203-210`](src/bin/modelmux-cli.rs:203)) as a model multiplexing service. Both run on port 8888 but serve different purposes: proxy mode handles protocol classification and routing, while agent8888 provides the model multiplexing gateway.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LITEBIKE_BIND_PORT` | `8888` | Proxy bind port |
| `LITEBIKE_INTERFACE` | `swlan0` | Ingress interface |
| `LITEBIKE_LOG` | `info` | Log level |
| `LITEBIKE_FEATURES` | `quic` | Comma-separated features |
| `EGRESS_INTERFACE` | `auto` | Egress interface |
| `EGRESS_BIND_IP` | `auto` | Egress IP binding |
| `LITEBIKE_BIND_ADDR` | `0.0.0.0` | Specific bind address |

### Example: Android/Termux

```bash
# Set up for mobile data egress
export LITEBIKE_INTERFACE=wlan0
export EGRESS_INTERFACE=rmnet0
export LITEBIKE_BIND_PORT=8888

# Start proxy
litebike --proxy

# In another terminal, configure apps to use proxy
export http_proxy=http://127.0.0.1:8888
export https_proxy=http://127.0.0.1:8888
```

### Example: Trading Bot Setup

```bash
# Start litebike proxy with Binance origin mirroring
litebike --proxy --origin binance.com --port 8888

# In freqtrade config.json:
{
    "exchange": {
        "ccxt_config": {
            "httpsProxy": "http://127.0.0.1:8888"
        }
    }
}
```

## System Utility Examples

### List Interfaces

```rust
use litebike::syscall_net::list_interfaces;

let ifaces = list_interfaces()?;
for (name, iface) in ifaces {
    println!("{}: {:?}", name, iface.addrs);
}
```

### Get Default Gateway

```rust
use litebike::syscall_net::get_default_gateway;

if let Ok(gw) = get_default_gateway() {
    println!("Default gateway: {}", gw);
}
```

### Get Routes

```rust
use litebike::syscall_net::get_routes;

let routes = get_routes()?;
for route in routes {
    println!("{:?}", route);
}
```

## Network Interface Handling

LiteBike intelligently manages network interfaces:

- **Default Ingress**: WiFi interfaces (`s?wlan*`) on port 8888
- **Default Egress**: Mobile data (`rmnet*`) with backoff logic
- **Fallback**: Automatic interface selection if defaults unavailable

```text
┌─────────────────────────────────────────────────────────┐
│                    LiteBike Proxy                        │
├─────────────────────────────────────────────────────────┤
│  Ingress: wlan0:8888 (s?wlan*)                          │
│                      │                                  │
│                      ▼                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Protocol Detector                                 │  │
│  │  HTTP │ SOCKS5 │ TLS │ DoH │ PAC │ UPnP           │  │
│  └───────────────────────────────────────────────────┘  │
│                      │                                  │
│                      ▼                                  │
│  Egress: rmnet0 (rmnet* with backoff)                   │
└─────────────────────────────────────────────────────────┘
```

## Building

```bash
# Standard build
cargo build --release

# With proxy feature
cargo build --release --features proxy

# Minimal build (utilities only)
cargo build --release --no-default-features
```

## Native macOS Operator Bar

LiteBike includes a native macOS menu bar application that provides one-click operator actions for build, git, SSH, remote deploy, proxy-bridge, and termux synchronization workflows.

### Building the App Bundle

```bash
# Build the app bundle
tools/build_macos_control_plane_app.sh

# Build and install to /Applications
tools/build_macos_control_plane_app.sh --install
```

The app bundle is created at `.artifacts/macos/Litebike Operator Bar.app`.

### Optional Install, Sign, and Package

- **Install to /Applications**: Pass `--install` flag
- **Code signing**: Set `DEVELOPER_ID_APPLICATION` environment variable before running the build script
- **Create installer package**: Set `DEVELOPER_ID_INSTALLER` environment variable to build a signed `.pkg` installer

```bash
# Example with signing and packaging
DEVELOPER_ID_APPLICATION="Developer ID Application: Your Name (TEAMID)" \
DEVELOPER_ID_INSTALLER="Developer ID Installer: Your Name (TEAMID)" \
tools/build_macos_control_plane_app.sh
```

### Environment Variables for Remote Actions

The operator bar passes these environment variables to remote actions. For actions requiring a remote host, if `LB_HOST` or `TERMUX_HOST` is not set, the system falls back to automatic default-gateway resolution (see [`tools/litebike_operator_actions.sh:17-27`](tools/litebike_operator_actions.sh:17)):

| Variable | Default | Description |
|----------|---------|-------------|
| `LITEBIKE_REPO_ROOT` | script directory | Override the workspace root |
| `LB_HOST` / `TERMUX_HOST` | auto-detected | Remote host for SSH actions (falls back to default gateway) |
| `LB_USER` / `TERMUX_USER` | `u0_a471` | Remote SSH username |
| `LB_SSH_PORT` / `TERMUX_PORT` | `8022` | Remote SSH port |
| `LB_DIR` | `/opt/litebike` | Remote litebike checkout path |
| `LB_REMOTE_BUILD_CMD` | `cargo build --release` | Remote build command |
| `LB_REMOTE_AFTER_BUILD_CMD` | (none) | Optional follow-up command after remote build |

### Operator Bar Actions

The app exposes these actions in the menu bar:

| Action | Description |
|--------|-------------|
| Build Release | Run `cargo build --release` in the workspace |
| Git Push | Push the current branch to origin with upstream tracking |
| Remote Deploy | Push current branch and build on the remote host |
| Proxy Status | Inspect proxy-bridge status |
| Proxy SSH Start | Start the remote proxy over SSH using proxy-bridge |
| Proxy Stop | Stop local proxy-bridge services |
| Sync Termux | Fetch the termux remote into local tracking branches |
| Open SSH Terminal | Open an interactive SSH session in Terminal.app |

### Startup

The app runs as a menu bar status item ("Litebike Operator Bar"). On first launch:

1. The app appears as an icon in the macOS menu bar
2. Click the icon to open the operator console window
3. Select your litebike workspace using "Choose Workspace..."
4. Remote actions use `LB_HOST` or `TERMUX_HOST` if set, otherwise fall back to automatic default-gateway detection

The workspace path is persisted in UserDefaults and survives app restarts.

## Testing

```bash
# Run all tests
cargo test

# Integration tests
cargo test --test integration

# Benchmark syscall performance
cargo bench --bench syscall_bench
```

## Performance

Syscall-based implementation (no /proc, /sys parsing):

| Operation | litebike | Traditional | Speedup |
|-----------|----------|-------------|---------|
| Interface list | 0.3ms | 2.1ms | 7x |
| Route table | 0.5ms | 3.2ms | 6x |
| Socket stats | 0.8ms | 5.4ms | 7x |

## Deployment Path

```text
client/app -> litebike:8888 (proxy or utility) -> [optional: literbike backend]
```

Litebike owns the shell and binary on port 8888:

- **litebike proxy mode** (`litebike --proxy`): Protocol classification and edge routing (HTTP, SOCKS5, TLS, DoH). Built with `--features proxy` (see [`Cargo.toml:75`](Cargo.toml:75)).
- **litebike utilities**: `ifconfig`, `ip`, `route`, `netstat` via [`src/syscall_net.rs`](src/syscall_net.rs:1) — direct syscalls, no /proc/sys dependencies.
- **agent8888**: Symlink or alias to the `modelmux` binary that auto-starts on port 8888 (see [`src/bin/modelmux-cli.rs:57-59`](src/bin/modelmux-cli.rs:57) and [`lines 203-210`](src/bin/modelmux-cli.rs:203)). This is a model multiplexing gateway, separate from proxy mode.
- **literbike** (when present): Runs behind litebike as the heavier transport and service runtime (QUIC, API translation, DHT, CAS).

Note: Proxy mode (protocol classification/routing) and agent8888 (modelmux gateway) both use port 8888 but serve different purposes. The shell/binary ownership remains with litebike regardless of which mode is active.

## Repo Relationship

**litebike** (this repo) owns:

- The shell/binary and port 8888 surface
- Syscall-based network utilities ([`src/syscall_net.rs`](src/syscall_net.rs:1)): `list_interfaces`, `get_default_gateway`, `get_routes` — direct libc calls, no /proc/sys parsing
- Proxy mode with protocol classification (requires `--features proxy`)
- Model multiplexing gateway (`modelmux` binary, invoked as `agent8888` on port 8888)
- Operator actions for macOS menu bar ([`tools/litebike_operator_actions.sh`](tools/litebike_operator_actions.sh:1))

**literbike** (companion repo at `/Users/jim/work/literbike`) owns:

- QUIC and transport-heavy runtime
- Unified traffic and service adapters
- API translation across providers
- DHT, CAS, and broader service composition

Use `litebike` when you need:

- Small edge deployment footprint
- Syscall-only interface and route inspection (no /proc, /sys, /dev)
- Unified ingress on a single local port (port 8888)
- Protocol classification and lightweight proxy behavior
- The canonical operator surface that subsumes both repos when literbike is present

Use `literbike` when you need:

- QUIC and transport-heavy runtime behavior
- Unified traffic and service adapters
- API translation across providers
- DHT, CAS, and broader service composition

Typical deployment shape:

```text
client/app
  -> litebike:8888 (shell ownership)
     - proxy mode: protocol classification/routing (with --features proxy)
     - utilities: ifconfig, ip, route, netstat via syscall_net
     - agent8888: modelmux gateway (separate from proxy)
  -> literbike (optional backend)
     - transport runtime
     - service translation
     - durable traffic and service orchestration
```

## Related Projects

- **literbike**: heavier transport and services companion (`/Users/jim/work/literbike`)
- **freqtrade**: crypto trading bot with literbike integration
- **betanet**: historical protocol specification (HTX sourced from here)

## License

AGPL-3.0-or-later. Commercial licensing available - contact maintainers.

## Troubleshooting

### Permission Denied on Android

```bash
# Termux may need storage permissions
termux-setup-storage

# Or run without proxy features
litebike ifconfig  # Utilities work without root
```

### Interface Not Found

```bash
# List available interfaces
litebike ifconfig

# Specify interface explicitly
litebike --interface wlan0 --proxy
```

### High Latency

```bash
# Check egress interface selection
litebike probe

# Manually specify egress
export EGRESS_INTERFACE=rmnet0
```
