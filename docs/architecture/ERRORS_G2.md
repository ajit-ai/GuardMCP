# G2 — Structured Error Protocol

## GuardError

Immutable, serializable, sanitized.

```python
GuardError(
    code="POLICY_DENY",
    category=ErrorCategory.POLICY,
    severity=ErrorSeverity.HIGH,
    retryable=False,
    message="policy denied",   # user-facing, no secrets
    reason="rule matched",
    trace_id="uuid",
    timestamp=datetime.now(timezone.utc),
    details={},
)
```

Fields: `code, category, severity, retryable, message, reason, trace_id, timestamp, details`.

- `category` — 13: `IDENTITY, AUTHENTICATION, DELEGATION, AUTHORIZATION, POLICY, BUDGET, RISK, SECURITY, INTELLIGENCE, EXECUTION, NETWORK, TIMEOUT, INTERNAL`
- `severity` — `LOW, MEDIUM, HIGH, CRITICAL`
- `retryable` — explicit bool; `NETWORK/TIMEOUT/INTELLIGENCE` safe to retry via `from_exception()`
- `trace_id` — UUID linking to `GuardContext`/`GuardDecision`

## Serialization

`to_dict()` → plain dict with enum values + isoformat, `from_dict()` → validated instance, JSON stable via `json.dumps(to_dict())`. `from_exception(exc, category, code, trace_id)` sanitizes `type(exc).__name__ + str(exc)[:200]`.

## Files

- `packages/guardmcp-errors/src/guardmcp_errors/types.py` — enums
- `packages/guardmcp-errors/src/guardmcp_errors/error.py` — `GuardError`
- `packages/guardmcp-errors/src/guardmcp_errors/__init__.py` — public API

## Tests

`tests/unit/test_errors.py` — 9 tests: categories, validation, immutability, serialization stability, retryable, from_exception sanitized, str, details.
