# Decoupled Desktop Control Plane (The Vault GUI)

**Track ID:** `mcmo_control_plane_gui_20260226`  
**Type:** Feature  
**Status:** Spec Needed  
**Priority:** Medium  
**Created:** 2026-02-26

---

## Overview

Implement a standalone desktop GUI (gated under `litebike`) that controls the remote agent mesh via SSH/UPnP "Creeping Vine" tunnels.

## Goals

1. **Desktop GUI** - Cross-platform desktop application
2. **Remote Control** - Control agent mesh over secure tunnels
3. **Zero Trust** - Authentication and authorization for all operations
4. **Real-time Monitoring** - Live status of agents and tunnels
5. **Configuration Management** - Manage agent configurations

## Requirements

### Functional

- [ ] Display agent mesh topology
- [ ] Show tunnel status and metrics
- [ ] Start/stop/restart agents
- [ ] Configure agent parameters
- [ ] View agent logs
- [ ] Manage credentials and keys
- [ ] Monitor quota usage
- [ ] Alert on issues

### Non-Functional

- [ ] Cross-platform (macOS, Linux, Windows)
- [ ] Secure communication (TLS/mTLS)
- [ ] Responsive UI (< 100ms latency)
- [ ] Offline mode support
- [ ] Minimal resource usage

## Architecture

```
┌─────────────────────────────────────────────────┐
│           The Vault GUI (Desktop)               │
│  ┌─────────────────────────────────────────┐    │
│  │  UI Layer (Tauri/Druid/Iced)            │    │
│  │  - Dashboard                            │    │
│  │  - Agent Management                     │    │
│  │  - Tunnel Visualization                 │    │
│  │  - Configuration Editor                 │    │
│  └──────────────┬──────────────────────────┘    │
│                 │                                │
│  ┌──────────────▼──────────────────────────┐    │
│  │  Control Plane Client                   │    │
│  │  - SSH tunnel management                │    │
│  │  - UPnP port mapping                    │    │
│  │  - Authentication                       │    │
│  │  - Command serialization                │    │
│  └──────────────┬──────────────────────────┘    │
└─────────────────┼───────────────────────────────┘
                  │ Creeping Vine Tunnels
                  │ (SSH/UPnP/TLS)
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│ Agent 1 │ │ Agent 2 │ │ Agent 3 │
│ (local) │ │(remote) │ │(remote) │
└─────────┘ └─────────┘ └─────────┘
```

## Implementation Plan

### Phase 1: GUI Framework Selection
- [ ] Evaluate Tauri (Rust + Web frontend)
- [ ] Evaluate Druid (Pure Rust)
- [ ] Evaluate Iced (Pure Rust, Elm-like)
- [ ] Select framework and create skeleton

### Phase 2: Core UI Components
- [ ] Dashboard view
- [ ] Agent list and status
- [ ] Tunnel visualization
- [ ] Log viewer
- [ ] Configuration editor

### Phase 3: Control Plane Integration
- [ ] SSH tunnel client
- [ ] UPnP control client
- [ ] Authentication flow
- [ ] Command/response protocol

### Phase 4: Real-time Updates
- [ ] WebSocket/SSE for live updates
- [ ] Agent status polling
- [ ] Tunnel health monitoring
- [ ] Notification system

### Phase 5: Security Hardening
- [ ] mTLS authentication
- [ ] Credential storage (OS keychain)
- [ ] Audit logging
- [ ] Role-based access control

## Dependencies

- GUI Framework (Tauri/Druid/Iced)
- `tokio` for async operations
- `russh` for SSH
- `igdc-rust` for UPnP
- `serde` for serialization
- `security-framework` (macOS)
- `secret-service` (Linux)
- `windows` crate (Windows)

## Files to Create

```
litebike/src/control_plane_gui/
├── mod.rs              # Main module
├── app.rs              # Application state
├── dashboard.rs        # Dashboard view
├── agents.rs           # Agent management
├── tunnels.rs          # Tunnel visualization
├── logs.rs             # Log viewer
├── config.rs           # Configuration editor
├── client.rs           # Control plane client
└── auth.rs             # Authentication
```

## Success Criteria

- [ ] GUI builds and runs on macOS
- [ ] GUI builds and runs on Linux
- [ ] GUI builds and runs on Windows
- [ ] Can connect to remote agents
- [ ] Can start/stop agents
- [ ] Can view agent logs
- [ ] Can configure agents
- [ ] Secure authentication working
- [ ] Real-time status updates

## Risks

1. **GUI Framework Immaturity** - Mitigated by choosing established framework
2. **Cross-platform Issues** - Mitigated by early testing on all platforms
3. **Security Vulnerabilities** - Mitigated by security review
4. **Performance Issues** - Mitigated by profiling and optimization

## Next Steps

1. Create detailed specification
2. Select GUI framework
3. Implement skeleton application
4. Integrate with control plane
