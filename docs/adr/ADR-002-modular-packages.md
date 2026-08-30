# ADR-002 - Modular Package Architecture

Date: 2026-08-30
Status: Accepted

## Context

GuardMCP must remain modular, testable, and provider-independent while evolving into a security control plane.

## Decision

Monorepo with 11 packages under `packages/`:

```
guardmcp-core, -context, -errors, -policy, -risk, -budget, -decision, -audit, -observability, -security, -proxy
```

Apps under `apps/{gateway,control-plane}` depend inward on packages; packages depend inward `Application → Adapters → Services → Domain`.

## Consequences

- Clear bounded contexts; each package has its own `pyproject.toml` and can be versioned independently.
- Enforces dependency direction via `scripts/check-deps.py`.
- G0 creates only `guardmcp-core` with real code; others are placeholders until their phase, avoiding premature complexity.

## Alternatives

- Single package - rejected: would create god package and circular dependencies.
- Micro-repos - rejected: would complicate CI and atomic refactors during early phases.
