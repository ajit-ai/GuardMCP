"""G4: Risk engine — deterministic, explainable, provider extensible."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from guardmcp_core import (
    AgentContext,
    BudgetContext,
    Environment,
    EnvironmentContext,
    GuardContext,
    IdentityContext,
    PrincipalType,
    RequestContext,
    ResourceContext,
    SecurityContext,
    ToolContext,
    TraceContext,
)
from guardmcp_core import DelegationContext as DC
from guardmcp_core.types import RiskLevel
from guardmcp_risk import (
    RiskEvaluator,
    RiskFactor,
    RiskResult,
    RiskScore,
    RiskSignal,
    RiskSignalCategory,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def make_ctx(
    *,
    authenticated: bool = True,
    delegation_expired: bool = False,
    tool_name: str = "test_tool",
    arguments: dict | None = None,
    threat: RiskLevel = RiskLevel.LOW,
) -> GuardContext:
    now = datetime.now(UTC)
    req_id = _uuid()
    delegation = DC(
        delegator="human:alice",
        delegate="agent:bot",
        issued_at=now - timedelta(hours=1),
        expires_at=now - timedelta(seconds=1) if delegation_expired else now + timedelta(hours=1),
        delegation_chain=["human:alice", "app:myapp"],
    )
    return GuardContext(
        request=RequestContext(
            request_id=req_id, timestamp=now, tool_name=tool_name, arguments=arguments or {}
        ),
        identity=IdentityContext(
            principal_type=PrincipalType.HUMAN, principal_id="user_123", authenticated=authenticated
        ),
        delegation=delegation,
        agent=AgentContext(agent_id="agent_1"),
        tool=ToolContext(tool_name=tool_name),
        resource=ResourceContext(),
        environment=EnvironmentContext(environment=Environment.DEVELOPMENT),
        budget=BudgetContext(),
        security=SecurityContext(threat_level=threat),
        trace=TraceContext(trace_id=_uuid(), request_id=req_id),
    )


def test_risk_signal_validation() -> None:
    s = RiskSignal(
        signal_id=_uuid(),
        category=RiskSignalCategory.TOOL_RISK,
        score=50,
        confidence=0.9,
        description="test",
    )
    assert RiskSignal.from_dict(s.to_dict()) == s
    with pytest.raises(ValueError):
        RiskSignal(
            signal_id="bad",
            category=RiskSignalCategory.TOOL_RISK,
            score=50,
            confidence=0.9,
            description="x",
        )
    with pytest.raises(ValueError):
        RiskSignal(
            signal_id=_uuid(),
            category=RiskSignalCategory.TOOL_RISK,
            score=150,
            confidence=0.9,
            description="x",
        )


def test_risk_score_level_mapping() -> None:
    # thresholds: 0-20 LOW, 21-40 MODERATE, 41-60 ELEVATED, 61-80 HIGH, 81-100 CRITICAL
    for score, level in [
        (10, RiskLevel.LOW),
        (30, RiskLevel.MODERATE),
        (50, RiskLevel.ELEVATED),
        (70, RiskLevel.HIGH),
        (90, RiskLevel.CRITICAL),
    ]:
        rs = RiskScore(total_score=score, level=level)
        assert rs.level == level
    with pytest.raises(ValueError, match="inconsistent with score"):
        RiskScore(total_score=90, level=RiskLevel.LOW)

    json_round = RiskScore(total_score=50, level=RiskLevel.ELEVATED)
    assert RiskScore.from_dict(json.loads(json.dumps(json_round.to_dict()))) == json_round


def test_risk_evaluator_deterministic_and_explainable() -> None:
    ctx = make_ctx()
    ev = RiskEvaluator()
    r1 = ev.evaluate(ctx)
    r2 = ev.evaluate(ctx)
    # deterministic — same ctx → same score/level (UUIDs differ, categories same)
    assert r1.level == r2.level
    assert r1.score.total_score == r2.score.total_score
    assert len(r1.reasons) > 0
    assert any("Total risk" in r for r in r1.reasons)
    # 7 categories at least
    assert len(r1.signals) >= 7
    assert len(r1.factors) >= 7
    # serialization
    d = r1.to_dict()
    back = RiskResult.from_dict(json.loads(json.dumps(d)))
    assert back.level == r1.level
    assert back.score.total_score == r1.score.total_score


def test_risk_levels_trigger() -> None:
    # unauthenticated -> HIGH
    ctx1 = make_ctx(authenticated=False)
    r1 = RiskEvaluator().evaluate(ctx1)
    assert r1.level in {RiskLevel.HIGH, RiskLevel.ELEVATED, RiskLevel.CRITICAL}

    # delegation expired -> CRITICAL
    ctx2 = make_ctx(delegation_expired=True)
    r2 = RiskEvaluator().evaluate(ctx2)
    assert r2.level == RiskLevel.CRITICAL

    # sensitive tool + sensitive args + critical threat -> CRITICAL
    ctx3 = make_ctx(tool_name="exec", arguments={"password": "secret"}, threat=RiskLevel.CRITICAL)
    r3 = RiskEvaluator().evaluate(ctx3)
    assert r3.level == RiskLevel.CRITICAL

    # low risk context -> LOW/MODERATE/ELEVATED (agent without model gives 50)
    ctx4 = make_ctx(tool_name="read", arguments={}, threat=RiskLevel.LOW)
    r4 = RiskEvaluator().evaluate(ctx4)
    assert r4.level in {RiskLevel.LOW, RiskLevel.MODERATE, RiskLevel.ELEVATED}


def test_risk_provider_extension() -> None:
    class CustomProvider:
        def provide(self, context):  # type: ignore[no-untyped-def]
            return [
                RiskSignal(
                    signal_id=_uuid(),
                    category=RiskSignalCategory.SECURITY_RISK,
                    score=95,
                    confidence=1.0,
                    description="custom threat",
                )
            ]

    ctx = make_ctx()
    ev = RiskEvaluator()
    base = ev.evaluate(ctx)
    with_provider = ev.evaluate(ctx, providers=[CustomProvider()])  # type: ignore[arg-type]
    assert with_provider.score.total_score > base.score.total_score
    assert any("custom threat" in s.description for s in with_provider.signals)

    # provider failure must not corrupt core
    class FailingProvider:
        def provide(self, context):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

    r_fail = ev.evaluate(ctx, providers=[FailingProvider()])  # type: ignore[arg-type]
    assert r_fail.level is not None
    assert any("failed" in s.description.lower() for s in r_fail.signals)


def test_risk_extra_signals() -> None:
    ctx = make_ctx()
    extra = RiskSignal(
        signal_id=_uuid(),
        category=RiskSignalCategory.TOOL_RISK,
        score=100,
        confidence=1.0,
        description="extra high",
    )
    r = RiskEvaluator().evaluate(ctx, extra_signals=[extra])
    assert any(s.signal_id == extra.signal_id for s in r.signals)


def test_risk_result_validation() -> None:
    ctx = make_ctx()
    r = RiskEvaluator().evaluate(ctx)
    assert r.request_id == ctx.request.request_id
    assert r.trace_id == ctx.trace.trace_id
    # level matches score.level
    assert r.level == r.score.level
    with pytest.raises(ValueError, match="level must match score"):
        RiskResult(
            request_id=ctx.request.request_id,
            trace_id=ctx.trace.trace_id,
            score=r.score,
            level=RiskLevel.CRITICAL if r.level != RiskLevel.CRITICAL else RiskLevel.LOW,
            signals=r.signals,
            factors=r.factors,
            reasons=r.reasons,
        )


def test_risk_factor_serialization() -> None:
    s = RiskSignal(
        signal_id=_uuid(),
        category=RiskSignalCategory.AGENT_RISK,
        score=30,
        confidence=0.8,
        description="agent",
    )
    f = RiskFactor(
        factor_id=_uuid(),
        name="AgentRisk",
        category=RiskSignalCategory.AGENT_RISK,
        weight=1.0,
        signals=[s],
        score=30,
    )
    assert RiskFactor.from_dict(json.loads(json.dumps(f.to_dict()))) == f
