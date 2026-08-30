# ADR-001 - Python Runtime Selection

Date: 2026-08-30
Status: Accepted

## Context

GuardMCP requires a production-quality runtime with strong typing, modern packaging, and a mature security ecosystem. Initial implementation must avoid premature infrastructure (K8s, Kafka) and preserve domain independence.

## Decision

Use **Python 3.11+** as baseline runtime with:

- `hatchling` build backend, `uv` for env management
- `ruff` for lint+format, `mypy` strict type checking, `pytest` + coverage
- Structured, immutable domain models (dataclasses/Pydantic to be evaluated in G1)

## Consequences

- Strong typing and testability with minimal infra.
- Domain layer remains independent of FastAPI/PostgreSQL/Redis/MCP transport.
- Future adapters (FastAPI gateway, PostgreSQL audit store) added via `apps/` and adapter packages without contaminating domain.

## Alternatives Considered

- TypeScript/Node - rejected for G0 to leverage Python's security and policy ecosystem and to meet prompt's technology baseline.
- Go - deferred; Python offers faster iteration for domain modeling and policy/risk engines.
