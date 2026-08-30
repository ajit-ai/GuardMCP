# GuardMCP Architecture Overview (G0)

## Mission

GuardMCP is a trusted execution and security control layer between AI agents and MCP tools.

```
AI Agent → GuardMCP → Security Decision → MCP Tool / Server
```

Rule: **NO PROTECTED TOOL EXECUTION WITHOUT A GUARD DECISION**

## Dependency Direction

```
Application
  ↓
Adapters
  ↓
Services
  ↓
Domain
```

Domain packages (`guardmcp-core`, `guardmcp-context`, etc.) must not import `fastapi`, `sqlalchemy`, `psycopg`, `redis`, `opentelemetry`, `mcp`.

Enforced by `scripts/check-deps.py` and future CI.

## Execution Pipeline

Pre-execution:
```
REQUEST → VALIDATE → CONSTRUCT CONTEXT → RESOLVE IDENTITY → VALIDATE DELEGATION → POLICY → RISK → BUDGET → SECURITY INTELLIGENCE → DECISION → EXECUTE OR BLOCK
```

Post-execution:
```
TOOL RESULT → CLASSIFY → INSPECT SECURITY → CHECK SENSITIVE OUTPUT → FINALIZE BUDGET → AUDIT → RETURN/REDACT/BLOCK
```

## Decision Precedence (G6)

1. Invalid identity → DENY
2. Invalid delegation → DENY
3. Explicit policy deny → DENY
4. Critical confirmed threat → DENY
5. Budget exhausted → DENY/RESTRICT
6. Approval required → APPROVAL_REQUIRED
7. High risk → RESTRICT/APPROVAL_REQUIRED
8. Otherwise → ALLOW

Every decision must be explainable: `action, reasons, risk, policy, restrictions, trace_id`.

## Packages

- `guardmcp-core` - GuardContext, GuardRequest/Decision/Result
- `guardmcp-context` - Request/Identity/Delegation/Agent/Tool/Resource/Env/Budget/Security/Trace contexts
- `guardmcp-errors` - GuardError (13 categories)
- `guardmcp-policy` - Policy/Rule/Condition/Evaluator
- `guardmcp-risk` - RiskSignal/Score/Level/Evaluator
- `guardmcp-budget` - Budget types + CHECK/RESERVE/CONSUME/RELEASE/EXPIRE
- `guardmcp-decision` - orchestration, precedence
- `guardmcp-audit` - domain events
- `guardmcp-proxy` - MCP interception (after G0-G7)
- `guardmcp-security` - Intelligence provider interfaces
- `guardmcp-observability` - logs/metrics/tracing (adapter-based)

## Phases

G0 foundation is dependency-free; databases (PostgreSQL/Redis), OpenTelemetry, Docker added only when justified.
