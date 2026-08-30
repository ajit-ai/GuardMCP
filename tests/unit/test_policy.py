"""G3: Policy engine — Condition, Rule, Policy, Evaluator."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

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
from guardmcp_core import RiskLevel as RL
from guardmcp_core.types import GuardDecisionAction as Action
from guardmcp_policy import (
    Condition,
    Policy,
    PolicyEvaluator,
    Rule,
    RuleOperator,
)
from guardmcp_policy import (
    ConditionOperator as Op,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def make_ctx(
    *,
    tool_name: str = "test_tool",
    principal_id: str = "user_123",
    principal_type: PrincipalType = PrincipalType.HUMAN,
    environment: Environment = Environment.DEVELOPMENT,
    arguments: dict | None = None,
    agent_model: str = "gpt-4",
) -> GuardContext:
    now = datetime.now(UTC)
    req_id = _uuid()
    return GuardContext(
        request=RequestContext(
            request_id=req_id, timestamp=now, tool_name=tool_name, arguments=arguments or {}
        ),
        identity=IdentityContext(principal_type=principal_type, principal_id=principal_id),
        delegation=DC(
            delegator="human:alice",
            delegate="agent:bot",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        agent=AgentContext(agent_id="agent_1", model=agent_model),
        tool=ToolContext(tool_name=tool_name),
        resource=ResourceContext(),
        environment=EnvironmentContext(environment=environment),
        budget=BudgetContext(),
        security=SecurityContext(threat_level=RL.LOW),
        trace=TraceContext(trace_id=_uuid(), request_id=req_id),
    )


def test_condition_operators() -> None:
    ctx = make_ctx(tool_name="my_tool", arguments={"role": "admin", "count": 5})
    # EQUALS / NOT_EQUALS
    assert Condition(field="tool.tool_name", operator=Op.EQUALS, value="my_tool").evaluate(ctx)
    assert not Condition(field="tool.tool_name", operator=Op.EQUALS, value="other").evaluate(ctx)
    assert Condition(field="tool.tool_name", operator=Op.NOT_EQUALS, value="other").evaluate(ctx)
    # IN / NOT_IN
    assert Condition(
        field="identity.principal_type", operator=Op.IN, value=["human", "agent"]
    ).evaluate(ctx)
    assert Condition(field="tool.tool_name", operator=Op.NOT_IN, value=["other"]).evaluate(ctx)
    # CONTAINS
    assert Condition(field="tool.tool_name", operator=Op.CONTAINS, value="my").evaluate(ctx)
    # EXISTS / NOT_EXISTS
    assert Condition(field="arguments.role", operator=Op.EXISTS).evaluate(ctx)
    assert Condition(field="arguments.missing", operator=Op.NOT_EXISTS).evaluate(ctx)
    # REGEX
    assert Condition(field="tool.tool_name", operator=Op.REGEX, value="my_.*").evaluate(ctx)
    # GT / LT
    assert Condition(field="arguments.count", operator=Op.GT, value=3).evaluate(ctx)
    assert Condition(field="arguments.count", operator=Op.LT, value=10).evaluate(ctx)


def test_condition_all_input_types() -> None:
    # identity, agent, tool, resource, environment, arguments
    ctx = make_ctx(
        principal_id="user_123",
        principal_type=PrincipalType.HUMAN,
        environment=Environment.PRODUCTION,
        agent_model="claude-3",
        tool_name="fs_read",
        arguments={"path": "/etc/passwd"},
    )
    assert Condition(field="identity.principal_id", operator=Op.EQUALS, value="user_123").evaluate(
        ctx
    )
    assert Condition(field="agent.model", operator=Op.EQUALS, value="claude-3").evaluate(ctx)
    assert Condition(field="tool.tool_name", operator=Op.EQUALS, value="fs_read").evaluate(ctx)
    assert Condition(
        field="environment.environment", operator=Op.EQUALS, value="production"
    ).evaluate(ctx)
    assert Condition(field="arguments.path", operator=Op.CONTAINS, value="passwd").evaluate(ctx)


def test_rule_and_or() -> None:
    ctx = make_ctx(tool_name="tool_a", arguments={"x": 1})
    c1 = Condition(field="tool.tool_name", operator=Op.EQUALS, value="tool_a")
    c2 = Condition(field="arguments.x", operator=Op.EQUALS, value=1)
    c3 = Condition(field="arguments.x", operator=Op.EQUALS, value=99)

    and_rule = Rule(id="r1", action=Action.DENY, conditions=[c1, c2], operator=RuleOperator.AND)
    assert and_rule.matches(ctx)
    and_rule2 = Rule(id="r2", action=Action.DENY, conditions=[c1, c3], operator=RuleOperator.AND)
    assert not and_rule2.matches(ctx)

    or_rule = Rule(id="r3", action=Action.DENY, conditions=[c2, c3], operator=RuleOperator.OR)
    assert or_rule.matches(ctx)


def test_policy_all_actions() -> None:
    ctx = make_ctx()
    for action in [
        Action.ALLOW,
        Action.DENY,
        Action.RESTRICT,
        Action.APPROVAL_REQUIRED,
        Action.SANDBOX,
    ]:
        policy = Policy(
            id=_uuid(),
            name="test",
            rules=[
                Rule(
                    id="r1",
                    action=action,
                    conditions=[
                        Condition(field="tool.tool_name", operator=Op.EQUALS, value="test_tool")
                    ],
                )
            ],
        )
        ev = PolicyEvaluator()
        res = ev.evaluate(ctx, [policy])
        assert res.action == action
        assert res.matched_rule_id == "r1"


def test_policy_precedence_and_disabled() -> None:
    ctx = make_ctx(tool_name="tool_x")
    high = Policy(
        id="high",
        name="high",
        priority=10,
        rules=[
            Rule(
                id="r_high",
                action=Action.DENY,
                conditions=[Condition(field="tool.tool_name", operator=Op.EQUALS, value="tool_x")],
                priority=10,
            )
        ],
    )
    low = Policy(
        id="low",
        name="low",
        priority=1,
        rules=[
            Rule(
                id="r_low",
                action=Action.ALLOW,
                conditions=[Condition(field="tool.tool_name", operator=Op.EQUALS, value="tool_x")],
            )
        ],
    )
    ev = PolicyEvaluator()
    res = ev.evaluate(ctx, [low, high])
    assert res.action == Action.DENY
    assert res.matched_policy_id == "high"

    # disabled ignored
    high_disabled = Policy(id="high", name="high", priority=10, enabled=False, rules=high.rules)
    res2 = ev.evaluate(ctx, [high_disabled, low])
    assert res2.action == Action.ALLOW


def test_policy_no_match_defaults_allow() -> None:
    ctx = make_ctx(tool_name="tool_a")
    policy = Policy(
        id=_uuid(),
        name="p",
        rules=[
            Rule(
                id="r1",
                action=Action.DENY,
                conditions=[Condition(field="tool.tool_name", operator=Op.EQUALS, value="other")],
            )
        ],
    )
    ev = PolicyEvaluator()
    res = ev.evaluate(ctx, [policy])
    assert res.action == Action.ALLOW
    assert res.matched_policy_id is None
    assert "no policy matched" in res.reasons[0].lower()


def test_policy_empty_conditions_matches() -> None:
    ctx = make_ctx()
    policy = Policy(id=_uuid(), name="p", rules=[Rule(id="r1", action=Action.DENY)])
    ev = PolicyEvaluator()
    res = ev.evaluate(ctx, [policy])
    assert res.action == Action.DENY


def test_policy_serialization() -> None:
    policy = Policy(
        id=_uuid(),
        name="my policy",
        description="desc",
        rules=[
            Rule(
                id="r1",
                action=Action.RESTRICT,
                conditions=[Condition(field="tool.tool_name", operator=Op.EQUALS, value="x")],
                restrictions={"max_rows": 100},
            )
        ],
        priority=5,
    )
    d = policy.to_dict()
    back = Policy.from_dict(d)
    assert back == policy
    # evaluator result serialization
    ctx = make_ctx(tool_name="x")
    res = PolicyEvaluator().evaluate(ctx, [policy])
    assert Policy.from_dict(d) == policy
    assert res.to_dict()["action"] == "RESTRICT"


def test_policy_restrictions_propagated() -> None:
    ctx = make_ctx(tool_name="sensitive")
    policy = Policy(
        id=_uuid(),
        name="p",
        rules=[
            Rule(
                id="r1",
                action=Action.RESTRICT,
                conditions=[
                    Condition(field="tool.tool_name", operator=Op.EQUALS, value="sensitive")
                ],
                restrictions={"redact": True},
            )
        ],
    )
    res = PolicyEvaluator().evaluate(ctx, [policy])
    assert res.restrictions["redact"] is True
