# Spec: Universal Model Facade & Quota DSEL

## Overview
This specification defines a first-principles rethink of model orchestration. It replaces legacy, configuration-heavy routing with a unified `v1/models` facade and a Domain-Specific Embedded Language (DSEL) for managing "quota potentials" across consumer-provider containers.

## Requirements
- **Standardized Facade:** Implement an OpenAI-compatible `v1/models` endpoint that aggregates models from all configured providers (OpenAI, Anthropic, Google, etc.).
- **Web Model Cards:** A cached metadata system that enriches model listings with specialized agent-focused tags (e.g., "reasoning_depth", "code_native").
- **CC-Store DSEL:** A first-principles DSEL to replace manual GUI routing. It allows for declarative definition of quota containers and priority logic.
- **Protocol Agnostic:** The facade must abstract away the underlying provider protocols, presenting a unified interface to agents.

## Verification Criteria
- `GET /v1/models` returns a deduplicated, metadata-enriched list of all available models.
- The ranker correctly selects models based on DSEL-defined quota potentials.
- Agent-specific metadata (Web Model Cards) is successfully cached and served.
