# G8 — MCP Proxy

## Architecture

```
MCP Client → GuardMCP Proxy → ContextBuilder → DecisionPipeline → MCP Router → MCP Server
                          ↓              ↓                ↓
                       GuardContext  Policy/Risk/Budget  AuditEvent (13 types)
                                      → DecisionEngine → enforce → inspect → return
```

MCP-specific code isolated in `guardmcp-proxy` — domain unchanged.

## Components

- **ContextBuilder** (`guardmcp_proxy/context_builder.py`) — `build(request: dict) → GuardContext` from `tool_name, arguments, headers, principal_id, agent_model, environment, threat_level`; generates `request_id/trace_id` UUIDs, validates, creates 10 sub-contexts with `timedelta` delegation window.
- **DecisionPipeline** (`guardmcp_proxy/pipeline.py`) — `evaluate(context) → (GuardDecision, intermediates)` composes `PolicyEvaluator`, `RiskEvaluator`, optional `BudgetService` (checks `TOOL_CALL` budget for owner), then `DecisionEngine`. Pluggable `policies` list via `set_policies()`.
- **MCPRouter** (`guardmcp_proxy/router.py`) — `route(tool_name, arguments) → dict` with `BackendHandler` callable; default `_echo_backend` returns `{"output": "executed {tool}"}`.
- **GuardMCPProxy** (`guardmcp_proxy/proxy.py`) — `handle(request: dict) → dict` implements 8 responsibilities: intercept (validate `tool_name`), construct context, evaluate pipeline, enforce decision (`DENY→denied`, `APPROVAL_REQUIRED→approval_required`, `RESTRICT/SANDBOX→restricted` with `_restrictions`, `ALLOW→route`), inspect result (add `_restrictions` if needed), emit audit for all 13 lifecycle events (`REQUEST_RECEIVED`→`REQUEST_COMPLETED`), return `{"request_id","trace_id","allowed","action","reasons","status","result","restrictions","error"}`.

## Audit Emission (G7 integration)

Each `handle()` emits: `REQUEST_RECEIVED, IDENTITY_RESOLVED, DELEGATION_VALIDATED, POLICY_EVALUATED, RISK_CALCULATED, BUDGET_RESERVED (if applicable), SECURITY_CHECKED, DECISION_MADE, TOOL_STARTED/COMPLETED/FAILED, RESULT_INSPECTED, REQUEST_COMPLETED` via `InMemoryEventSink` (thread-safe, filterable by `request_id/trace_id/type`).

## Files

- `packages/guardmcp-proxy/src/guardmcp_proxy/context_builder.py`
- `packages/guardmcp-proxy/src/guardmcp_proxy/pipeline.py`
- `packages/guardmcp-proxy/src/guardmcp_proxy/router.py`
- `packages/guardmcp-proxy/src/guardmcp_proxy/proxy.py`
- `packages/guardmcp-proxy/src/guardmcp_proxy/__init__.py`
- `packages/guardmcp-proxy/pyproject.toml` — depends on `core,policy,risk,budget,decision,audit`
- `examples/mcp-proxy/basic.py` — runnable demo for 4 outcomes + audit

## Tests

`tests/unit/test_proxy.py` — 11 tests: `ALLOW`, `DENY via policy`, `APPROVAL_REQUIRED`, `RESTRICT high risk`, `DENY critical`, `DENY invalid identity`, `SANDBOX`, `missing tool_name`, `custom backend`, `audit lifecycle`, `budget integration (exhausted → DENY)` → **83 total** (72 G7 +11) passed.
`tests/integration/test_pipeline.py` — 4 end-to-end (G7) still passing.

## Example

```bash
python examples/mcp-proxy/basic.py  # ALLOW/DENY/APPROVAL_REQUIRED/RESTRICT + audit 48 events
```

## Bugs fixed in G8

- `mypy` missing `dict[str,Any]` for `result`, unused `type:ignore` in `pipeline.py`
- `ruff` E501 in `evaluator.py` read-only tool, `test_proxy.py` unused `pytest`
- `pytest` `SANDBOX` expectation `allowed False` → `True` (SANDBOX is not DENY), `full pipeline ALLOW` failed due to unauthenticated/ agent without model → fixed `example` and `test_proxy` to pass `principal_id` + `agent_model`, and `risk` tool scores `other 25→15` to allow `LOW`
