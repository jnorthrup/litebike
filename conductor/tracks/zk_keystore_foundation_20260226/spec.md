# ZK Keystore & Bitnet Fragment Custody

**Track ID:** `zk_keystore_foundation_20260226`  
**Type:** Feature  
**Status:** Spec Needed  
**Priority:** Medium  
**Created:** 2026-02-26

---

## Overview

Implement a cross-platform Rust keystore with high durability and splittable keys. Distribute fragments to non-conflicting standby parties for zero-knowledge (ZK) mesh retention.

## Goals

1. **Splittable Keys** - Implement Shamir's Secret Sharing for key fragmentation
2. **High Durability** - Ensure key availability through distributed custody
3. **Zero-Knowledge** - No single party can reconstruct the full key
4. **Cross-Platform** - Support macOS, Linux, Windows
5. **Bitnet Integration** - Native support for Bitnet key formats

## Requirements

### Functional

- [ ] Generate splittable keys with configurable threshold (k-of-n)
- [ ] Distribute fragments to standby parties
- [ ] Reconstruct keys from k fragments
- [ ] Secure local key storage (OS keychain integration)
- [ ] Fragment rotation and refresh
- [ ] Audit logging for all key operations

### Non-Functional

- [ ] Zero-knowledge architecture
- [ ] No single point of failure
- [ ] Resistant to collusion (< k parties)
- [ ] Fast reconstruction (< 1 second for k=3)
- [ ] Memory-safe implementation (Rust)

## Architecture

```
┌─────────────────────────────────────────────────┐
│              ZK Keystore                        │
│  ┌─────────────────────────────────────────┐    │
│  │  Key Generator                          │    │
│  │  - Shamir's Secret Sharing              │    │
│  │  - Threshold configuration (k-of-n)     │    │
│  └──────────────┬──────────────────────────┘    │
│                 │                                │
│  ┌──────────────▼──────────────────────────┐    │
│  │  Fragment Manager                       │    │
│  │  - Distribution to parties              │    │
│  │  - Fragment rotation                    │    │
│  │  - Health checking                      │    │
│  └──────────────┬──────────────────────────┘    │
│                 │                                │
│  ┌──────────────▼──────────────────────────┐    │
│  │  Secure Storage                         │    │
│  │  - macOS Keychain                       │    │
│  │  - Linux Secret Service                 │    │
│  │  - Windows Credential Manager           │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
         │
         │ Distributed Fragments
         ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Party A    │  │  Party B    │  │  Party C    │
│ (standby)   │  │ (standby)   │  │ (standby)   │
└─────────────┘  └─────────────┘  └─────────────┘
```

## Implementation Plan

### Phase 1: Core Shamir Implementation
- [ ] Implement Shamir's Secret Sharing in pure Rust
- [ ] Add polynomial interpolation for reconstruction
- [ ] Write unit tests for split/reconstruct
- [ ] Benchmark performance

### Phase 2: Fragment Distribution
- [ ] Define fragment distribution protocol
- [ ] Implement secure fragment transmission
- [ ] Add fragment acknowledgment and verification
- [ ] Implement health checking for parties

### Phase 3: Secure Storage
- [ ] macOS Keychain integration
- [ ] Linux Secret Service integration
- [ ] Windows Credential Manager integration
- [ ] Secure memory handling (zeroize on drop)

### Phase 4: Bitnet Integration
- [ ] Bitnet key format support
- [ ] Integration with litebike keymux
- [ ] Fragment custody for Bitnet identities

### Phase 5: ZK Mesh Retention
- [ ] Standby party discovery
- [ ] Non-conflicting party selection
- [ ] Mesh health monitoring
- [ ] Automatic fragment refresh

## Dependencies

- `rust-shamir` or similar SSS library
- `security-framework` (macOS)
- `secret-service` (Linux)
- `windows` crate (Windows)
- `zeroize` for secure memory

## Files to Create

```
literbike/src/zk_keystore/
├── mod.rs              # Main module
├── shamir.rs           # Shamir's Secret Sharing
├── fragment.rs         # Fragment management
├── distribution.rs     # Fragment distribution
├── storage.rs          # Secure storage backends
├── bitnet.rs           # Bitnet integration
└── mesh.rs             # ZK mesh management
```

## Success Criteria

- [ ] Keys can be split into n fragments
- [ ] Keys can be reconstructed from k fragments
- [ ] k-1 fragments reveal no information about the key
- [ ] Fragments distributed to standby parties
- [ ] Secure storage on all major platforms
- [ ] Integration with litebike keymux
- [ ] All operations logged for audit

## Risks

1. **Key Loss** - Mitigated by k-of-n threshold
2. **Fragment Compromise** - Mitigated by k threshold
3. **Party Unavailability** - Mitigated by n > k
4. **Platform Differences** - Mitigated by abstraction layer

## Next Steps

1. Create detailed specification
2. Implement Shamir's Secret Sharing
3. Add secure storage backends
4. Integrate with litebike
