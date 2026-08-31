"""G6: Decision Engine — 8 precedence rules, explainable, deterministic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from guardmcp_budget import BudgetService, InMemoryBudgetProvider
from guardmcp_core import AgentContext as AC
from guardmcp_core import BudgetContext as BC
from guardmcp_core import DelegationContext as DC
from guardmcp_core import Environment as Env
from guardmcp_core import EnvironmentContext as EC
from guardmcp_core import GuardContext, IdentityContext, PrincipalType, RequestContext
from guardmcp_core import ResourceContext as RC
from guardmcp_core import RiskLevel as RL
from guardmcp_core import SecurityContext as SC
from guardmcp_core import ToolContext as TC
from guardmcp_core import TraceContext as TrC
from guardmcp_core.types import BudgetType
from guardmcp_core.types import GuardDecisionAction as Action
from guardmcp_decision import DecisionEngine
from guardmcp_policy import PolicyResult
from guardmcp_risk import RiskEvaluator


def _uuid() -> str:
    return str(uuid.uuid4())


def make_ctx(
    *,
    authenticated: bool = True,
    principal_id: str = "user_123",
    delegation_expired: bool = False,
    tool_name: str = "test_tool",
    threat: RL = RL.LOW,
    arguments: dict | None = None,
) -> GuardContext:
    now = datetime.now(UTC)
    req_id = _uuid()
    return GuardContext(
        request=RequestContext(
            request_id=req_id, timestamp=now, tool_name=tool_name, arguments=arguments or {}
        ),
        identity=IdentityContext(
            principal_type=PrincipalType.HUMAN,
            principal_id=principal_id,
            authenticated=authenticated,
        ),
        delegation=DC(
            delegator="human:alice",
            delegate="agent:bot",
            issued_at=now - timedelta(hours=1),
            expires_at=now - timedelta(seconds=1)
            if delegation_expired
            else now + timedelta(hours=1),
        ),
        agent=AC(agent_id="agent_1"),
        tool=TC(tool_name=tool_name),
        resource=RC(),
        environment=EC(environment=Env.DEVELOPMENT),
        budget=BC(),
        security=SC(threat_level=threat),
        trace=TrC(trace_id=_uuid(), request_id=req_id),
    )


def make_policy_result(
    action: Action = Action.ALLOW, matched_id: str | None = None
) -> PolicyResult:
    return PolicyResult(
        action=action,
        matched_policy_id=matched_id or _uuid(),
        matched_rule_id="r1",
        reasons=[f"policy {action.value}"],
        restrictions={},
        evaluated_policies=1,
    )


def make_risk_result(ctx: GuardContext, level: RL = RL.LOW) -> object:
    # use evaluator, override level if needed for precedence tests
    ev = RiskEvaluator()
    r = ev.evaluate(ctx)
    if r.level == level:
        return r
    # fallback: create RiskResult with overridden level via from_dict
    d = r.to_dict()
    # find score that maps to level
    score_map = {RL.LOW: 10, RL.MODERATE: 30, RL.ELEVATED: 50, RL.HIGH: 70, RL.CRITICAL: 90}
    d["level"] = level.value
    d["score"]["level"] = level.value
    d["score"]["total_score"] = score_map[level]
    # also need to ensure score.level matches
    from guardmcp_risk import RiskResult as RR

    return RR.from_dict(d)


def test_precedence_1_invalid_identity() -> None:
    ctx = make_ctx(authenticated=False)
    policy = make_policy_result(Action.ALLOW)
    risk = make_risk_result(ctx, RL.LOW)
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.DENY
    assert any("identity" in r.lower() for r in dec.reasons)


def test_precedence_2_invalid_delegation() -> None:
    ctx = make_ctx(delegation_expired=True)
    policy = make_policy_result(Action.ALLOW)
    risk = make_risk_result(ctx, RL.LOW)
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.DENY
    assert any("delegation" in r.lower() for r in dec.reasons)


def test_precedence_3_policy_deny() -> None:
    ctx = make_ctx()
    policy = make_policy_result(Action.DENY)
    risk = make_risk_result(ctx, RL.LOW)
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.DENY
    assert "policy deny" in dec.reasons[0].lower()


def test_precedence_4_critical_security() -> None:
    ctx = make_ctx(threat=RL.CRITICAL)
    policy = make_policy_result(Action.ALLOW)
    risk = make_risk_result(ctx, RL.LOW)  # risk low but security critical
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.DENY
    assert "critical" in dec.reasons[0].lower()


def test_precedence_4_critical_risk() -> None:
    # create ctx that yields critical risk: exec + password
    ctx2 = make_ctx(tool_name="exec", arguments={"password": "secret"}, threat=RL.LOW)
    risk = make_risk_result(ctx2, RL.CRITICAL)
    policy = make_policy_result(Action.ALLOW)
    dec = DecisionEngine().evaluate(ctx2, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.DENY
    assert "critical risk" in dec.reasons[0].lower()


def test_precedence_5_budget_exhausted() -> None:
    ctx = make_ctx()
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.TOOL_CALL, owner_id="user_1", limit=1)
    svc.reserve(b.budget_id, amount=1)
    budget_res = svc.check(b.budget_id, amount=1)  # will be success False
    assert not budget_res.success
    policy = make_policy_result(Action.ALLOW)
    risk = make_risk_result(ctx, RL.LOW)
    dec = DecisionEngine().evaluate(ctx, policy, risk, budget_res)  # type: ignore[arg-type]
    assert dec.action == Action.DENY
    assert "budget" in dec.reasons[0].lower()


def test_precedence_6_approval_required() -> None:
    ctx = make_ctx()
    policy = make_policy_result(Action.APPROVAL_REQUIRED)
    risk = make_risk_result(ctx, RL.LOW)
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.APPROVAL_REQUIRED


def test_precedence_7_high_risk_restrict() -> None:
    ctx = make_ctx(tool_name="exec", arguments={"path": "/tmp"})
    ev = RiskEvaluator()
    risk = ev.evaluate(ctx)
    # ensure HIGH for restrict test (exec gives 80 → HIGH)
    if risk.level != RL.HIGH:
        risk = make_risk_result(ctx, RL.HIGH)  # type: ignore[assignment]
    policy = make_policy_result(Action.ALLOW)
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.RESTRICT
    assert "high risk" in dec.reasons[0].lower() or "elevated" in dec.reasons[0].lower()


def test_precedence_8_allow() -> None:
    ctx = make_ctx(tool_name="read", arguments={}, threat=RL.LOW)
    policy = make_policy_result(Action.ALLOW)
    # low risk
    risk = make_risk_result(ctx, RL.LOW)
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.ALLOW
    assert any("allow" in r.lower() for r in dec.reasons)


def test_precedence_deny_overrides_high_risk() -> None:
    # policy deny should win over high risk
    ctx = make_ctx(tool_name="exec", arguments={"password": "secret"})
    policy = make_policy_result(Action.DENY)
    risk = make_risk_result(ctx, RL.HIGH)
    dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert dec.action == Action.DENY


def test_explainable_and_deterministic() -> None:
    ctx = make_ctx()
    policy = make_policy_result(Action.ALLOW)
    risk = make_risk_result(ctx, RL.LOW)
    eng = DecisionEngine()
    d1 = eng.evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    d2 = eng.evaluate(ctx, policy, risk)  # type: ignore[arg-type]
    assert d1.action == d2.action
    assert d1.trace_id == ctx.trace.trace_id
    assert d1.request_id == ctx.request.request_id
    assert len(d1.reasons) > 0
    assert d1.risk_level == risk.level  # type: ignore[attr-defined]
    assert d1.policy_id == policy.matched_policy_id
    # serialization
    assert d1.to_dict()["action"] == d1.action.value


def test_sandbox_and_restrict_from_policy() -> None:
    ctx = make_ctx()
    for action in [Action.SANDBOX, Action.RESTRICT]:
        policy = make_policy_result(action)
        risk = make_risk_result(ctx, RL.LOW)
        dec = DecisionEngine().evaluate(ctx, policy, risk)  # type: ignore[arg-type]
        assert dec.action == action
