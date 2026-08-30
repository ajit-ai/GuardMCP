# G1 — Core Domain Models

## GuardContext

Aggregate of 10 immutable sub-contexts:

- `RequestContext` — request_id (UUID), timestamp (tz-aware), method, tool_name, arguments
- `IdentityContext` — principal_type (HUMAN/APPLICATION/SERVICE/AGENT), principal_id, display_name, authenticated, issuer
- `DelegationContext` — delegator, delegate, scope, issued_at, expires_at, delegation_chain, `is_expired()`
- `AgentContext` — agent_id, agent_type, model, version, name
- `ToolContext` — tool_name, tool_version, server_id, description, category
- `ResourceContext` — resource_id, resource_type, uri, owner
- `EnvironmentContext` — environment (development/staging/production/test), region, ip, user_agent
- `BudgetContext` — budgets dict[str,int], `remaining(BudgetType)`
- `SecurityContext` — threat_level (RiskLevel), provider, signals, intelligence_timestamp
- `TraceContext` — trace_id, request_id, span_id, parent_span_id

All are `frozen=True, slots=True`, validate UUID/non-empty/enum, normalize `datetime` to UTC, provide `to_dict()/from_dict()` with isoformat.

## GuardRequest

`request_id, timestamp, context: GuardContext, tool_name, arguments, headers` — validates UUID and requires tool_name on request or context.tool.

## GuardDecision

`request_id, trace_id, action: GuardDecisionAction, reasons: list[str] (non-empty), risk_level, policy_id, restrictions, evaluated_at, expires_at` — explainable security: every decision has at least one reason, `is_allowed`/`is_denied` helpers.

Actions: `ALLOW, DENY, RESTRICT, APPROVAL_REQUIRED, SANDBOX`.

## GuardResult

`request_id, trace_id, decision: GuardDecision, context: GuardContext, execution_output, error, completed_at` — validates linkage `request_id==decision.request_id`, provides `success` property.

## Types

`Environment, PrincipalType, AgentType, GuardDecisionAction, RiskLevel, BudgetType` as `StrEnum`.

## Serialization

All models: `to_dict()` → plain dict with isoformat timestamps and enum values, `from_dict()` → validated instance, JSON roundtrip via `json.dumps(to_dict())`.

## Files

- `packages/guardmcp-core/src/guardmcp_core/types.py`
- `packages/guardmcp-core/src/guardmcp_core/context.py`
- `packages/guardmcp-core/src/guardmcp_core/request.py`
- `packages/guardmcp-core/src/guardmcp_core/decision.py`
- `packages/guardmcp-core/src/guardmcp_core/result.py`
- `packages/guardmcp-core/src/guardmcp_core/__init__.py` — public API

## Tests

`tests/unit/test_core_domain.py` — 13 tests covering validation, serialization, immutability, no-infra (plus 4 placeholders = 17 total).
