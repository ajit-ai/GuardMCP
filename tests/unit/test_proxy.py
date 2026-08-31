"""G8: MCP Proxy — ALLOW, DENY, RESTRICT, APPROVAL_REQUIRED, audit."""

from __future__ import annotations

from guardmcp_audit import AuditEventType
from guardmcp_core.types import GuardDecisionAction as Action
from guardmcp_policy import Condition, Policy, Rule
from guardmcp_policy import ConditionOperator as Op
from guardmcp_proxy import DecisionPipeline, GuardMCPProxy, MCPRouter


def _req(tool_name: str, arguments: dict | None = None, principal_id: str = "user_123") -> dict:
    return {
        "tool_name": tool_name,
        "arguments": arguments or {},
        "principal_id": principal_id,
        "authenticated": True,
        "agent_model": "gpt-4",
    }


def test_proxy_allow() -> None:
    proxy = GuardMCPProxy()
    res = proxy.handle(_req("read_tool", {"path": "/tmp"}))
    assert res["allowed"] is True
    assert res["action"] == Action.ALLOW.value
    assert "result" in res
    # audit
    assert proxy.sink.count() >= 7
    assert any(e.event_type == AuditEventType.DECISION_MADE for e in proxy.sink.list_events())


def test_proxy_deny_via_policy() -> None:
    policy = Policy(
        id="p1",
        name="block",
        rules=[
            Rule(
                id="r1",
                action=Action.DENY,
                conditions=[Condition(field="tool.tool_name", operator=Op.EQUALS, value="blocked")],
            )
        ],
    )
    pipeline = DecisionPipeline(policies=[policy])
    proxy = GuardMCPProxy(pipeline=pipeline)
    res = proxy.handle(_req("blocked"))
    assert res["allowed"] is False
    assert res["action"] == Action.DENY
    assert res["status"] == "denied"
    assert "policy deny" in res["reasons"][0].lower()


def test_proxy_approval_required() -> None:
    policy = Policy(
        id="p1",
        name="approval",
        rules=[
            Rule(
                id="r1",
                action=Action.APPROVAL_REQUIRED,
                conditions=[
                    Condition(field="tool.tool_name", operator=Op.EQUALS, value="sensitive")
                ],
            )
        ],
    )
    pipeline = DecisionPipeline(policies=[policy])
    proxy = GuardMCPProxy(pipeline=pipeline)
    res = proxy.handle(_req("sensitive"))
    assert res["action"] == Action.APPROVAL_REQUIRED
    assert res["allowed"] is False
    assert res["status"] == "approval_required"


def test_proxy_restrict_high_risk() -> None:
    # exec gives HIGH → RESTRICT
    proxy = GuardMCPProxy()
    res = proxy.handle(_req("exec", {"cmd": "ls"}))
    assert res["action"] == Action.RESTRICT
    assert res["allowed"] is True
    assert "_restrictions" in res["result"]


def test_proxy_deny_critical_risk() -> None:
    # exec + password → CRITICAL → DENY
    proxy = GuardMCPProxy()
    res = proxy.handle(_req("exec", {"password": "secret"}))
    assert res["action"] == Action.DENY
    assert not res["allowed"]


def test_proxy_deny_invalid_identity() -> None:
    proxy = GuardMCPProxy()
    res = proxy.handle({"tool_name": "read_tool"})  # anonymous → unauthenticated → DENY
    assert res["action"] == Action.DENY
    assert not res["allowed"]


def test_proxy_sandbox_from_policy() -> None:
    policy = Policy(
        id="p1",
        name="sandbox",
        rules=[
            Rule(
                id="r1",
                action=Action.SANDBOX,
                conditions=[
                    Condition(field="tool.tool_name", operator=Op.EQUALS, value="sandbox_tool")
                ],
            )
        ],
    )
    pipeline = DecisionPipeline(policies=[policy])
    proxy = GuardMCPProxy(pipeline=pipeline)
    res = proxy.handle(_req("sandbox_tool"))
    assert res["action"] == Action.SANDBOX
    assert res["allowed"] is True
    assert "result" in res


def test_proxy_missing_tool_name() -> None:
    proxy = GuardMCPProxy()
    res = proxy.handle({"arguments": {}})
    assert res["allowed"] is False
    assert "missing tool_name" in res["error"].lower()


def test_proxy_router_custom_backend() -> None:
    def backend(tool_name: str, args: dict) -> dict:
        return {"custom": f"{tool_name}-{args.get('x')}"}

    router = MCPRouter(backend=backend)
    proxy = GuardMCPProxy(router=router)
    res = proxy.handle(_req("my_tool", {"x": 123}))
    assert res["allowed"] is True
    assert res["result"]["custom"] == "my_tool-123"


def test_proxy_audit_lifecycle() -> None:
    proxy = GuardMCPProxy()
    proxy.handle(_req("read_tool"))
    events = proxy.sink.list_events()
    types = [e.event_type for e in events]
    assert AuditEventType.REQUEST_RECEIVED in types
    assert AuditEventType.DECISION_MADE in types
    assert AuditEventType.REQUEST_COMPLETED in types
    # ensure trace linkage
    req_ids = {e.request_id for e in events}
    assert len(req_ids) == 1


def test_proxy_budget_integration() -> None:
    from guardmcp_budget import BudgetService, InMemoryBudgetProvider
    from guardmcp_core.types import BudgetType

    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.TOOL_CALL, owner_id="user_123", limit=1)
    svc.reserve(b.budget_id, amount=1)
    # now budget exhausted
    pipeline = DecisionPipeline(budget_service=svc)
    proxy = GuardMCPProxy(pipeline=pipeline)
    res = proxy.handle(_req("read_tool"))
    assert res["action"] == Action.DENY
    assert "budget" in res["reasons"][0].lower()
