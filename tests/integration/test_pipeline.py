"""Integration: full GuardMCP pipeline G1-G7."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from guardmcp_audit import AuditEventType, InMemoryEventSink
from guardmcp_audit.event import AuditEvent
from guardmcp_budget import BudgetService, InMemoryBudgetProvider
from guardmcp_core import AgentContext as AC
from guardmcp_core import BudgetContext as BC
from guardmcp_core import DelegationContext as DC
from guardmcp_core import Environment as Env
from guardmcp_core import EnvironmentContext as EC
from guardmcp_core import GuardContext
from guardmcp_core import IdentityContext as IC
from guardmcp_core import PrincipalType as PT
from guardmcp_core import RequestContext as RC
from guardmcp_core import ResourceContext as ResC
from guardmcp_core import RiskLevel as RL
from guardmcp_core import SecurityContext as SC
from guardmcp_core import ToolContext as TC
from guardmcp_core import TraceContext as TrC
from guardmcp_core.types import BudgetType
from guardmcp_core.types import GuardDecisionAction as Action
from guardmcp_decision import DecisionEngine
from guardmcp_policy import Condition, Policy, PolicyEvaluator, Rule
from guardmcp_policy import ConditionOperator as Op
from guardmcp_risk import RiskEvaluator


def _uuid() -> str:
    return str(uuid.uuid4())


def make_ctx(
    tool_name: str = "test_tool", authenticated: bool = True, threat: RL = RL.LOW
) -> GuardContext:
    now = datetime.now(UTC)
    req_id = _uuid()
    return GuardContext(
        request=RC(request_id=req_id, timestamp=now, tool_name=tool_name),
        identity=IC(principal_type=PT.HUMAN, principal_id="user_123", authenticated=authenticated),
        delegation=DC(
            delegator="human:alice",
            delegate="agent:bot",
            issued_at=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=1),
        ),
        agent=AC(agent_id="agent_1", model="gpt-4"),
        tool=TC(tool_name=tool_name),
        resource=ResC(),
        environment=EC(environment=Env.DEVELOPMENT),
        budget=BC(),
        security=SC(threat_level=threat),
        trace=TrC(trace_id=_uuid(), request_id=req_id),
    )


def test_full_pipeline_allow() -> None:
    """Happy path: low risk, no policy deny, budget ok → ALLOW."""
    ctx = make_ctx(tool_name="read")
    sink = InMemoryEventSink()
    sink.emit(
        AuditEvent.create(
            ctx.request.request_id, ctx.trace.trace_id, AuditEventType.REQUEST_RECEIVED
        )
    )

    policy_result = PolicyEvaluator().evaluate(ctx, [])
    sink.emit(
        AuditEvent.create(
            ctx.request.request_id,
            ctx.trace.trace_id,
            AuditEventType.POLICY_EVALUATED,
            metadata={"action": policy_result.action.value},
        )
    )

    risk_result = RiskEvaluator().evaluate(ctx)
    sink.emit(
        AuditEvent.create(
            ctx.request.request_id,
            ctx.trace.trace_id,
            AuditEventType.RISK_CALCULATED,
            metadata={"level": risk_result.level.value},
        )
    )

    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.TOOL_CALL, owner_id="user_123", limit=10)
    budget_result = svc.check(b.budget_id, amount=1)
    sink.emit(
        AuditEvent.create(
            ctx.request.request_id, ctx.trace.trace_id, AuditEventType.BUDGET_RESERVED
        )
    )

    decision = DecisionEngine().evaluate(ctx, policy_result, risk_result, budget_result)
    sink.emit(
        AuditEvent.create(
            ctx.request.request_id,
            ctx.trace.trace_id,
            AuditEventType.DECISION_MADE,
            metadata={"action": decision.action.value},
        )
    )

    assert decision.action == Action.ALLOW
    assert sink.count() == 5
    assert sink.filter_by_type(AuditEventType.DECISION_MADE)[0].metadata["action"] == "ALLOW"


def test_full_pipeline_deny_via_policy() -> None:
    """Policy deny overrides low risk → DENY."""
    ctx = make_ctx(tool_name="blocked_tool")
    policy = Policy(
        id=_uuid(),
        name="block",
        rules=[
            Rule(
                id="r1",
                action=Action.DENY,
                conditions=[
                    Condition(field="tool.tool_name", operator=Op.EQUALS, value="blocked_tool")
                ],
            )
        ],
    )
    policy_result = PolicyEvaluator().evaluate(ctx, [policy])
    risk_result = RiskEvaluator().evaluate(ctx)
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.TOOL_CALL, owner_id="user_123", limit=10)
    budget_result = svc.check(b.budget_id, amount=1)

    decision = DecisionEngine().evaluate(ctx, policy_result, risk_result, budget_result)
    assert decision.action == Action.DENY
    assert "policy deny" in decision.reasons[0].lower()


def test_full_pipeline_deny_via_critical_risk() -> None:
    """Critical risk → DENY even with allow policy."""
    ctx = make_ctx(tool_name="exec", threat=RL.CRITICAL)
    policy_result = PolicyEvaluator().evaluate(ctx, [])
    risk_result = RiskEvaluator().evaluate(ctx)  # exec + critical → CRITICAL
    assert risk_result.level == RL.CRITICAL
    decision = DecisionEngine().evaluate(ctx, policy_result, risk_result)
    assert decision.action == Action.DENY


def test_audit_lifecycle_order() -> None:
    """Ensure audit events preserve order and trace linkage."""
    ctx = make_ctx()
    sink = InMemoryEventSink()
    order = [
        AuditEventType.REQUEST_RECEIVED,
        AuditEventType.IDENTITY_RESOLVED,
        AuditEventType.POLICY_EVALUATED,
        AuditEventType.RISK_CALCULATED,
        AuditEventType.DECISION_MADE,
        AuditEventType.REQUEST_COMPLETED,
    ]
    for et in order:
        sink.emit(AuditEvent.create(ctx.request.request_id, ctx.trace.trace_id, et))
    events = sink.list_events()
    assert [e.event_type for e in events] == order
    assert all(e.trace_id == ctx.trace.trace_id for e in events)
    assert all(e.request_id == ctx.request.request_id for e in events)
