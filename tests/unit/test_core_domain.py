"""G1: Core domain models — validation, serialization, immutability, no-infra."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from guardmcp_core import (
    AgentContext,
    AgentType,
    BudgetContext,
    BudgetType,
    DelegationContext,
    Environment,
    EnvironmentContext,
    GuardContext,
    GuardDecision,
    GuardDecisionAction,
    GuardRequest,
    GuardResult,
    IdentityContext,
    PrincipalType,
    RequestContext,
    ResourceContext,
    RiskLevel,
    SecurityContext,
    ToolContext,
    TraceContext,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def make_guard_context() -> GuardContext:
    now = datetime.now(UTC)
    req_id = _uuid()
    trace_id = _uuid()
    return GuardContext(
        request=RequestContext(
            request_id=req_id,
            timestamp=now,
            method="tool_call",
            tool_name="test_tool",
            arguments={"x": 1},
        ),
        identity=IdentityContext(
            principal_type=PrincipalType.HUMAN,
            principal_id="user_123",
            display_name="Alice",
            authenticated=True,
        ),
        delegation=DelegationContext(
            delegator="human:alice",
            delegate="agent:assistant",
            scope=["tool:test_tool"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            delegation_chain=["human:alice", "app:myapp"],
        ),
        agent=AgentContext(agent_id="agent_1", agent_type=AgentType.ASSISTANT, model="gpt-4"),
        tool=ToolContext(tool_name="test_tool", server_id="srv_1"),
        resource=ResourceContext(resource_id="res_1", resource_type="file", uri="file://tmp/a"),
        environment=EnvironmentContext(environment=Environment.DEVELOPMENT),
        budget=BudgetContext(budgets={BudgetType.TOOL_CALL.value: 10}),
        security=SecurityContext(threat_level=RiskLevel.LOW),
        trace=TraceContext(trace_id=trace_id, request_id=req_id, span_id="span_1"),
    )


# ---------------------------------------------------------------------------
# RequestContext
# ---------------------------------------------------------------------------


def test_request_context_validation_and_serialization() -> None:
    now = datetime.now(UTC)
    rc = RequestContext(request_id=_uuid(), timestamp=now, tool_name="t")
    d = rc.to_dict()
    assert d["request_id"] == rc.request_id
    assert datetime.fromisoformat(d["timestamp"]) == rc.timestamp
    back = RequestContext.from_dict(d)
    assert back == rc

    with pytest.raises(ValueError, match="request_id must be a valid UUID"):
        RequestContext(request_id="bad", timestamp=now)

    # immutability — frozen dataclass
    with pytest.raises((AttributeError, TypeError)):
        rc.tool_name = "other"  # type: ignore[misc]


def test_request_context_tz_normalization() -> None:
    naive = datetime(2026, 1, 1, 12, 0, 0)
    rc = RequestContext(request_id=_uuid(), timestamp=naive)
    assert rc.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# Identity / Delegation
# ---------------------------------------------------------------------------


def test_identity_validation() -> None:
    IdentityContext(principal_type=PrincipalType.HUMAN, principal_id="u1")
    with pytest.raises(ValueError):
        IdentityContext(principal_type=PrincipalType.HUMAN, principal_id="")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        IdentityContext(principal_type="bad", principal_id="u1")  # type: ignore[arg-type]

    ic = IdentityContext(principal_type=PrincipalType.APPLICATION, principal_id="app1")
    assert IdentityContext.from_dict(ic.to_dict()) == ic


def test_delegation_validation_and_expiry() -> None:
    now = datetime.now(UTC)
    dc = DelegationContext(
        delegator="a", delegate="b", issued_at=now, expires_at=now + timedelta(hours=1)
    )
    assert not dc.is_expired(at=now)
    assert dc.is_expired(at=now + timedelta(hours=2))
    assert DelegationContext.from_dict(dc.to_dict()) == dc

    with pytest.raises(ValueError, match="expires_at must be after issued_at"):
        DelegationContext(
            delegator="a", delegate="b", issued_at=now, expires_at=now - timedelta(seconds=1)
        )
    with pytest.raises(ValueError):
        DelegationContext(delegator="", delegate="b")


# ---------------------------------------------------------------------------
# GuardContext aggregate
# ---------------------------------------------------------------------------


def test_guard_context_serializable_and_immutable() -> None:
    ctx = make_guard_context()
    d = ctx.to_dict()
    # json roundtrip
    json_str = json.dumps(d)
    back = GuardContext.from_dict(json.loads(json_str))
    assert back == ctx

    with pytest.raises((AttributeError, TypeError)):
        ctx.tool = ToolContext(tool_name="x")  # type: ignore[misc]


def test_guard_context_no_infra_imports() -> None:
    # domain must not import forbidden infra — already enforced by scripts/check-deps.py
    # here verify runtime import does not pull infra
    import guardmcp_core.context as mod

    src = mod.__file__ or ""
    assert src.endswith("context.py")
    with open(src, encoding="utf-8") as f:
        text = f.read()
    for forbidden in ["import fastapi", "import redis", "from fastapi"]:
        assert forbidden not in text


# ---------------------------------------------------------------------------
# GuardDecision — explainable
# ---------------------------------------------------------------------------


def test_guard_decision_validation_and_explainability() -> None:
    req_id = _uuid()
    trace_id = _uuid()
    gd = GuardDecision(
        request_id=req_id,
        trace_id=trace_id,
        action=GuardDecisionAction.ALLOW,
        reasons=["policy allows"],
        risk_level=RiskLevel.LOW,
    )
    assert gd.is_allowed
    assert not gd.is_denied
    d = gd.to_dict()
    assert d["action"] == "ALLOW"
    assert GuardDecision.from_dict(d) == gd

    with pytest.raises(ValueError, match="reasons must be non-empty"):
        GuardDecision(
            request_id=req_id, trace_id=trace_id, action=GuardDecisionAction.DENY, reasons=[]
        )

    with pytest.raises(ValueError):
        GuardDecision(
            request_id="bad", trace_id=trace_id, action=GuardDecisionAction.DENY, reasons=["x"]
        )

    # expires_at validation
    now = datetime.now(UTC)
    with pytest.raises(ValueError):
        GuardDecision(
            request_id=req_id,
            trace_id=trace_id,
            action=GuardDecisionAction.DENY,
            reasons=["x"],
            evaluated_at=now,
            expires_at=now - timedelta(seconds=1),
        )


def test_guard_decision_all_actions() -> None:
    req_id = _uuid()
    trace_id = _uuid()
    for action in GuardDecisionAction:
        gd = GuardDecision(
            request_id=req_id, trace_id=trace_id, action=action, reasons=[f"{action} reason"]
        )
        assert gd.action == action


# ---------------------------------------------------------------------------
# GuardRequest
# ---------------------------------------------------------------------------


def test_guard_request_validation_and_serialization() -> None:
    ctx = make_guard_context()
    req = GuardRequest(
        request_id=ctx.request.request_id,
        timestamp=ctx.request.timestamp,
        context=ctx,
        tool_name="test_tool",
    )
    d = req.to_dict()
    back = GuardRequest.from_dict(d)
    assert back.request_id == req.request_id
    assert back.context == req.context

    # tool_name fallback to context.tool
    req2 = GuardRequest(request_id=_uuid(), timestamp=datetime.now(UTC), context=ctx)
    assert req2.to_dict()["tool_name"] == "test_tool"

    with pytest.raises(ValueError, match="tool_name must be"):
        empty_tool_ctx = GuardContext(
            request=ctx.request,
            identity=ctx.identity,
            delegation=ctx.delegation,
            agent=ctx.agent,
            tool=ToolContext(tool_name=""),  # fails at ToolContext validation
            resource=ctx.resource,
            environment=ctx.environment,
            budget=ctx.budget,
            security=ctx.security,
            trace=ctx.trace,
        )
        GuardRequest(
            request_id=_uuid(),
            timestamp=datetime.now(UTC),
            context=empty_tool_ctx,
            tool_name="",
        )


# ---------------------------------------------------------------------------
# GuardResult
# ---------------------------------------------------------------------------


def test_guard_result_validation_and_linkage() -> None:
    ctx = make_guard_context()
    req_id = ctx.request.request_id
    trace_id = ctx.trace.trace_id
    decision = GuardDecision(
        request_id=req_id, trace_id=trace_id, action=GuardDecisionAction.ALLOW, reasons=["ok"]
    )
    gr = GuardResult(
        request_id=req_id,
        trace_id=trace_id,
        decision=decision,
        context=ctx,
        execution_output={"ok": True},
    )
    assert gr.success
    d = gr.to_dict()
    back = GuardResult.from_dict(d)
    assert back == gr

    # mismatch linkage
    with pytest.raises(ValueError, match="request_id must match decision"):
        GuardResult(request_id=_uuid(), trace_id=trace_id, decision=decision, context=ctx)

    # denied result not success
    deny = GuardDecision(
        request_id=req_id,
        trace_id=trace_id,
        action=GuardDecisionAction.DENY,
        reasons=["policy deny"],
    )
    gr2 = GuardResult(
        request_id=req_id, trace_id=trace_id, decision=deny, context=ctx, error="denied"
    )
    assert not gr2.success


# ---------------------------------------------------------------------------
# Budget / Security / Env
# ---------------------------------------------------------------------------


def test_budget_context_validation() -> None:
    BudgetContext(budgets={BudgetType.TOOL_CALL.value: 5})
    with pytest.raises(ValueError):
        BudgetContext(budgets={"tool_call": -1})

    bc = BudgetContext(budgets={BudgetType.DATA.value: 100})
    assert bc.remaining(BudgetType.DATA) == 100
    assert BudgetContext.from_dict(bc.to_dict()) == bc


def test_security_context_serialization() -> None:
    sc = SecurityContext(threat_level=RiskLevel.HIGH, signals=["sig1"])
    assert SecurityContext.from_dict(sc.to_dict()) == sc
    with pytest.raises(ValueError):
        SecurityContext(threat_level="bad")  # type: ignore[arg-type]


def test_trace_context_validation() -> None:
    t = TraceContext(trace_id=_uuid(), request_id=_uuid())
    assert TraceContext.from_dict(t.to_dict()) == t
    with pytest.raises(ValueError):
        TraceContext(trace_id="bad", request_id=_uuid())
