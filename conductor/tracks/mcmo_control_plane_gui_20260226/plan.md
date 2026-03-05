# Decoupled Desktop Control Plane Implementation Plan

**Track:** `mcmo_control_plane_gui_20260226`  
**Status:** Ready to Start  
**Priority:** Medium

---

## Phase 1: GUI Framework Selection 🔴 IN PROGRESS

### 1.1 Framework Evaluation
- [ ] Create Tauri proof-of-concept
- [ ] Create Druid proof-of-concept
- [ ] Create Iced proof-of-concept
- [ ] Benchmark performance
- [ ] Evaluate ecosystem and documentation

### 1.2 Framework Selection
- [ ] Document selection criteria
- [ ] Make final selection
- [ ] Set up project structure

### 1.3 Skeleton Application
- [ ] Create main window
- [ ] Add menu bar
- [ ] Add basic navigation
- [ ] Set up build system

**Validation:**
- [ ] Application builds successfully
- [ ] Window opens on all platforms
- [ ] Basic navigation works

---

## Phase 2: Core UI Components 🟡 PENDING

### 2.1 Dashboard View
- [ ] Agent count and status summary
- [ ] Tunnel status overview
- [ ] Quota usage summary
- [ ] Recent alerts
- [ ] Quick actions

### 2.2 Agent Management
- [ ] Agent list with status
- [ ] Agent details panel
- [ ] Start/stop/restart controls
- [ ] Agent configuration view
- [ ] Agent logs view

### 2.3 Tunnel Visualization
- [ ] Network topology diagram
- [ ] Tunnel status indicators
- [ ] Bandwidth usage graphs
- [ ] Latency metrics
- [ ] Connection details

### 2.4 Configuration Editor
- [ ] YAML/TOML editor
- [ ] Syntax highlighting
- [ ] Validation
- [ ] Save/load configurations
- [ ] Configuration templates

### 2.5 Log Viewer
- [ ] Real-time log streaming
- [ ] Log filtering
- [ ] Log search
- [ ] Log export
- [ ] Log level controls

**Validation:**
- [ ] All views render correctly
- [ ] Navigation between views works
- [ ] Data displays correctly

---

## Phase 3: Control Plane Integration 🟡 PENDING

### 3.1 SSH Tunnel Client
- [ ] Connect to SSH tunnels
- [ ] Authenticate with keys/passwords
- [ ] Port forwarding
- [ ] Connection pooling
- [ ] Error handling

### 3.2 UPnP Control Client
- [ ] Discover UPnP devices
- [ ] Create port mappings
- [ ] Delete port mappings
- [ ] Monitor mappings
- [ ] Error handling

### 3.3 Authentication Flow
- [ ] Login screen
- [ ] Credential storage
- [ ] Token management
- [ ] Session management
- [ ] Logout

### 3.4 Command/Response Protocol
- [ ] Define command types
- [ ] Implement serialization
- [ ] Implement deserialization
- [ ] Error handling
- [ ] Timeout handling

**Validation:**
- [ ] Can connect to remote agents
- [ ] Commands execute successfully
- [ ] Responses display correctly

---

## Phase 4: Real-time Updates 🟡 PENDING

### 4.1 WebSocket/SSE Client
- [ ] Connect to update stream
- [ ] Parse updates
- [ ] Update UI state
- [ ] Handle disconnections
- [ ] Reconnection logic

### 4.2 Agent Status Polling
- [ ] Periodic status checks
- [ ] Status change detection
- [ ] UI updates on changes
- [ ] Configurable poll interval

### 4.3 Tunnel Health Monitoring
- [ ] Latency monitoring
- [ ] Bandwidth monitoring
- [ ] Error rate monitoring
- [ ] Health score calculation

### 4.4 Notification System
- [ ] In-app notifications
- [ ] System notifications
- [ ] Notification preferences
- [ ] Notification history

**Validation:**
- [ ] UI updates in real-time
- [ ] Notifications appear correctly
- [ ] No memory leaks from updates

---

## Phase 5: Security Hardening 🟡 PENDING

### 5.1 mTLS Authentication
- [ ] Generate client certificates
- [ ] Validate server certificates
- [ ] Certificate pinning
- [ ] Certificate renewal

### 5.2 Credential Storage
- [ ] macOS Keychain integration
- [ ] Linux Secret Service integration
- [ ] Windows Credential Manager integration
- [ ] Encrypted local storage fallback

### 5.3 Audit Logging
- [ ] Log all user actions
- [ ] Log all system events
- [ ] Log search and export
- [ ] Tamper-evident logs

### 5.4 Role-Based Access Control
- [ ] Define roles (admin, operator, viewer)
- [ ] Implement permission checks
- [ ] UI based on permissions
- [ ] Audit role changes

**Validation:**
- [ ] Security tests pass
- [ ] Credentials stored securely
- [ ] Access control enforced
- [ ] Audit logs complete

---

## Success Criteria

| Criterion | Target | Status |
|-----------|--------|--------|
| GUI framework selected | Complete | ⏳ |
| Core UI components | Complete | ⏳ |
| Control plane integration | Working | ⏳ |
| Real-time updates | Working | ⏳ |
| Security hardening | Complete | ⏳ |
| Cross-platform builds | Success | ⏳ |
| Test coverage | >80% | ⏳ |
| Documentation | Complete | ⏳ |

---

## Dependencies

- [ ] GUI framework (Tauri/Druid/Iced)
- [ ] `tokio` for async
- [ ] `russh` for SSH
- [ ] `igdc-rust` for UPnP
- [ ] `serde` for serialization
- [ ] `security-framework` (macOS)
- [ ] `secret-service` (Linux)
- [ ] `windows` crate (Windows)
- [ ] `native-tls` for TLS

---

## Files to Create

1. `litebike/src/control_plane_gui/mod.rs`
2. `litebike/src/control_plane_gui/app.rs`
3. `litebike/src/control_plane_gui/dashboard.rs`
4. `litebike/src/control_plane_gui/agents.rs`
5. `litebike/src/control_plane_gui/tunnels.rs`
6. `litebike/src/control_plane_gui/logs.rs`
7. `litebike/src/control_plane_gui/config.rs`
8. `litebike/src/control_plane_gui/client.rs`
9. `litebike/src/control_plane_gui/auth.rs`
10. `litebike/src/control_plane_gui/security.rs`

---

## Timeline

- **Phase 1:** 1 week
- **Phase 2:** 3 weeks
- **Phase 3:** 2 weeks
- **Phase 4:** 2 weeks
- **Phase 5:** 2 weeks

**Total:** 10 weeks
