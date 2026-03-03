# Plan: Litebike Creeping Vine Optimization

## Phase 1: Tunneling & UPnP Foundation
- [ ] Implement the `TunnelManager` for self-stacking SSH flows.
- [ ] Add UPnP port mapping logic using `igdc-rust` or raw SOAP calls.
- [ ] Test local "Vine" establishment between two peers on the same subnet.

## Phase 2: Tethering & Depth Awareness
- [ ] Define the tethering protocol for persistent agent sessions.
- [ ] Implement the traceroute-based path optimizer.
- [ ] Add session handover logic for moving between private subnets.

## Phase 3: Zero Trust Enforcement
- [ ] Implement the Zero Trust threshold gatekeeper.
- [ ] Integrate authentication tokens into the tunneling headers.
- [ ] Demonstrate a secure "Dystopian Holdout" link crossing an untrusted segment.
