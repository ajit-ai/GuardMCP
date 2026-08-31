# G7 — Audit/Event System

## Architecture

```
AuditEvent (13 types) → EventEmitter (Protocol) → InMemoryEventSink (thread-safe list) → future PG/Kafka adapters
```

No Kafka required for G7 — in-memory sink for tests and dev.

## AuditEventType — 13 lifecycle events

```
REQUEST_RECEIVED, IDENTITY_RESOLVED, DELEGATION_VALIDATED, POLICY_EVALUATED,
RISK_CALCULATED, BUDGET_RESERVED, SECURITY_CHECKED, DECISION_MADE,
TOOL_STARTED, TOOL_COMPLETED, TOOL_FAILED, RESULT_INSPECTED, REQUEST_COMPLETED
```

## AuditEvent

`event_id (UUID), timestamp (tz-aware), request_id (UUID), trace_id (UUID), event_type, metadata (dict), actor, duration_ms`

- `frozen, slots`, validates UUIDs and `event_type` enum, ensures `timestamp` tz-aware
- `to_dict/from_dict` with isoformat, `create(request_id, trace_id, event_type, metadata, actor, duration_ms)` factory generates `event_id` + `timestamp`
- `duration_ms` optional, non-negative

## EventEmitter

Protocol `emit(event)`, `emit_many(events)` — must not raise for business logic, future adapters will implement same interface.

## InMemoryEventSink

Thread-safe `list[AuditEvent]` + `threading.Lock`

- `emit(event)`, `emit_many(events)`
- `list_events() → list[AuditEvent]` (copy)
- `filter_by_request(request_id)`, `filter_by_type(event_type)`, `filter_by_trace(trace_id)`
- `clear()`, `count()`

## Files

- `packages/guardmcp-audit/src/guardmcp_audit/types.py` — `AuditEventType`
- `packages/guardmcp-audit/src/guardmcp_audit/event.py` — `AuditEvent`
- `packages/guardmcp-audit/src/guardmcp_audit/emitter.py` — `EventEmitter`
- `packages/guardmcp-audit/src/guardmcp_audit/memory.py` — `InMemoryEventSink`
- `packages/guardmcp-audit/src/guardmcp_audit/__init__.py` — public API
- `packages/guardmcp-audit/pyproject.toml` — no deps (pure domain)

## Tests

`tests/unit/test_audit.py` — 6 tests: validation/serialization, all 13 types, sink basic (emit, emit_many, count, filter), lifecycle 12 events ordered, concurrency (5×20 =100), metadata/duration.

## Bugs fixed in G7

- `ruff` unused imports (auto-fixed)
- No other bugs — `mypy` strict 33 files OK, `pytest` 68 passed.
