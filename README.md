# LiteBike - Network Utilities Binary

> **Companion binary to literbike** - Provides system network utilities and proxy services.

![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Android%20%7C%20macOS%20%7C%20Linux-green.svg)

## Overview

LiteBike is a multi-call binary that provides:

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

Start litebike as a multi-protocol proxy:

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

**Supported Protocols** (auto-detected on single port):
- HTTP/HTTPS proxy
- SOCKS5
- TLS tunneling
- DNS over HTTPS (DoH)
- PAC/WPAD
- Bonjour/mDNS
- UPnP

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
use literbike::syscall_net::list_interfaces;

let ifaces = list_interfaces()?;
for (name, iface) in ifaces {
    println!("{}: {:?}", name, iface.addrs);
}
```

### Get Default Gateway

```rust
use literbike::syscall_net::get_default_gateway;

if let Ok(gw) = get_default_gateway() {
    println!("Default gateway: {}", gw);
}
```

### Get Routes

```rust
use literbike::syscall_net::get_routes;

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

```
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

| Operation | literbike | Traditional | Speedup |
|-----------|-----------|-------------|---------|
| Interface list | 0.3ms | 2.1ms | 7x |
| Route table | 0.5ms | 3.2ms | 6x |
| Socket stats | 0.8ms | 5.4ms | 7x |

## Related Projects

- **literbike**: Core Rust library (`/Users/jim/work/literbike`)
- **freqtrade**: Crypto trading bot with literbike integration
- **betanet**: Historical protocol specification (HTX sourced from here)

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
