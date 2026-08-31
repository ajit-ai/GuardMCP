# G9 — Post-Execution Controls

## Architecture

```
TOOL RESULT → CLASSIFY → INSPECT SECURITY → CHECK SENSITIVE OUTPUT → FINALIZE BUDGET → EMIT AUDIT → RETURN/REDACT/BLOCK
```

Extension points for future DLP — no advanced ML, just architecture.

## Inspector

- `InspectionAction` — `ALLOW, REDACT, BLOCK`
- `InspectionResult` — `action, original_result, redacted_result, reasons, blocked_keys`, `result` property returns redacted if REDACT
- `ResultInspector` Protocol — `inspect(result, context, decision) → InspectionResult`
- `Redactor` Protocol — `redact(data) → dict`
- `BasicRedactor` — replaces `password, secret, token, credential, key, passwd` values with `"***"`, recursive for nested dicts
- `BasicResultInspector` — 1. check sensitive keys/values (`/etc/passwd`), 2. block if `malicious`/`exploit` in values, 3. else redact if sensitive, 4. else redact if `RESTRICT/SANDBOX` and `len(str(result))>10000`, 5. else `ALLOW`

## Proxy Integration

`GuardMCPProxy` now takes `inspector: ResultInspector` (default `BasicResultInspector`), after `router.route()` calls `inspector.inspect()`, emits `RESULT_INSPECTED` with `inspection` name, then:

- `BLOCK` → `REQUEST_COMPLETED blocked` + `allowed False, error="blocked: ...", status="blocked"`
- `REDACT` → merge `decision.restrictions`, return redacted result, `status="completed_restricted"` or `completed`
- `ALLOW` → return original result

Budget finalize: if `budget_result.reservation_id` exists, `consume` on success, `release` on failure via `pipeline._budget_svc` (try/except, never corrupts).

## Files

- `packages/guardmcp-proxy/src/guardmcp_proxy/inspector.py` — `InspectionAction, InspectionResult, Redactor, BasicRedactor, ResultInspector, BasicResultInspector`
- `packages/guardmcp-proxy/src/guardmcp_proxy/proxy.py` — updated to use inspector + budget finalize, `handle()` now 8 responsibilities with post-execution
- `packages/guardmcp-proxy/src/guardmcp_proxy/__init__.py` — exports inspector
- `packages/guardmcp-proxy/pyproject.toml` — no new deps

## Tests

`tests/unit/test_inspector.py` — 7 tests: `redactor` (nested), `allow`, `redact sensitive keys`, `redact passwd_value`, `block malicious`, `restricted large`, `proxy post-execution redacted and blocked` (via custom backend) → **90 total** (83 G8 +7) passed.

## Bugs fixed in G9

- `ruff` RUF012 `ClassVar` for `SENSITIVE_KEYS`, E501 line length, `mypy` unused `type:ignore` for `self.redact(v)` and `consume/release`
- `pytest` delegation `expires_at must be after issued_at` (make_ctx used same `now`) → `now+timedelta(hours=1)`, `large restricted output` mismatch → `large output`
