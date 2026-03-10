# Litebike Conductor Tracks

This file orchestrates the "Creeping Vine" transport and "Dystopian Holdout" control plane.

**Last Updated:** 2026-03-10  
**Overall Completion:** 44/203 tasks (21.7%) → Target: 100% on context-resident tasks

---

## [x] Track: Universal Model Facade (`keymux`) ✅ 100% COMPLETE
- **Objective:** Establish a unified `v1/models` facade in `litebike`. Standardize model protocols and specialized metadata via Web Model Cards.
- **Status:** All tasks complete (3/3)
- **Link:** [./tracks/universal_model_facade_20260226/](./tracks/universal_model_facade_20260226/)

---

## [~] Track: Litebike Edge Companion Launch 🔄 IN PROGRESS
- **Objective:** Lock launch truth so `litebike` remains the primary runtime shell/operator surface and `literbike` is treated as the gated heart/backplane imported into it.
- **Status:** Boundary truth corrected in both repos; README launch narrative published; packaging alignment still open
- **Priority:** High
- **Link:** [./tracks/litebike_edge_companion_launch_20260308/](./tracks/litebike_edge_companion_launch_20260308/)

---

## [~] Track: CC-Store DSEL & Quota Potential (Freqtrade Alpha Priority) 🔄 38% COMPLETE
- **Objective:** Implement the first-principles DSEL for CC-Store to manage consumer-provider quota potentials and metadata specialization. **CRITICAL for Freqtrade alpha integration** - provides model selection logic for ring agent.
- **Status:** Phase 1 complete, awaiting Freqtrade integration
- **Priority:** URGENT - Blocks Freqtrade alpha release
- **Link:** [./tracks/cc_store_dsel_quota_20260226/](./tracks/cc_store_dsel_quota_20260226/)

---

## [~] Track: Ollama Emulator for Copilot Models 🔄 65% COMPLETE
- **Objective:** Ship Ollama wrapper/emulator as modelmux in literbike through litebike 888agent - the only nexus to copilot models and first priority for gateway quota bearing.
- **Status:** Phase 1 complete, binaries building, 228 tests passing
- **Priority:** P0
- **Link:** [./tracks/ollama-emulator-copilot-20260304/](./tracks/ollama-emulator-copilot-20260304/)

---

## [~] Track: N-Way API Conversion Layer 🔄 85% COMPLETE
- **Objective:** Unified API translation between all major AI providers (OpenAI, Anthropic, Gemini, DeepSeek, WebSearch).
- **Status:** Phase 1 complete, all modules implemented
- **Priority:** High
- **Link:** [./tracks/nway-api-conversion-20260304/](./tracks/nway-api-conversion-20260304/)

---

## [~] Track: Quota Countdown Error Codes 🔄 50% COMPLETE
- **Objective:** Find error codes that contain quota countdown information (remaining tokens, requests, reset times).
- **Status:** Documented, patterns cataloged
- **Priority:** Medium
- **Link:** [./tracks/quota-error-codes-20260304/](./tracks/quota-error-codes-20260304/)

---

## [ ] Track: ZK Keystore & Bitnet Fragment Custody (`literbike`) 📋 SPECIFIED
- **Objective:** Implement an X-platform Rust keystore with high durability and splittable keys. Distribute fragments to non-conflicting standby parties for ZK meshy retention.
- **Status:** Specification and plan complete, ready to start
- **Priority:** Medium
- **Link:** [./tracks/zk_keystore_foundation_20260226/](./tracks/zk_keystore_foundation_20260226/)

---

## [ ] Track: Decoupled Desktop Control Plane (The Vault GUI) 📋 SPECIFIED
- **Objective:** Implement a standalone desktop GUI (gated under `litebike`) that controls the remote agent mesh via SSH/UPnP "Creeping Vine" tunnels.
- **Status:** Specification and plan complete, ready to start
- **Priority:** Medium
- **Link:** [./tracks/mcmo_control_plane_gui_20260226/](./tracks/mcmo_control_plane_gui_20260226/)

---

## [ ] Track: Litebike Creeping Vine Optimization 📋 PLANNED
- **Objective:** Self-stacking SSH tunnels, agent tethering, and private UPnP network services. Define Zero Trust thresholds for external communication.
- **Status:** Plan exists, implementation pending
- **Priority:** Medium
- **Link:** [./tracks/litebike_creeping_vine_20260226/](./tracks/litebike_creeping_vine_20260226/)
