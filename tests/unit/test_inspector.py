"""G9: Post-execution — inspector, redactor, block/redact/allow."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

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
from guardmcp_core.decision import GuardDecision
from guardmcp_core.types import GuardDecisionAction as Action
from guardmcp_proxy.inspector import BasicRedactor, BasicResultInspector, InspectionAction


def _uuid() -> str:
    return str(uuid.uuid4())


def make_ctx() -> GuardContext:
    now = datetime.now(UTC)
    req_id = _uuid()
    return GuardContext(
        request=RC(request_id=req_id, timestamp=now, tool_name="test_tool"),
        identity=IC(principal_type=PT.HUMAN, principal_id="user_123", authenticated=True),
        delegation=DC(
            delegator="human:alice",
            delegate="agent:bot",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        agent=AC(agent_id="agent_1", model="gpt-4"),
        tool=TC(tool_name="test_tool"),
        resource=ResC(),
        environment=EC(environment=Env.DEVELOPMENT),
        budget=BC(),
        security=SC(threat_level=RL.LOW),
        trace=TrC(trace_id=_uuid(), request_id=req_id),
    )


def make_decision(action: Action = Action.ALLOW) -> GuardDecision:
    return GuardDecision(
        request_id=_uuid(),
        trace_id=_uuid(),
        action=action,
        reasons=[f"{action.value}"],
        risk_level=RL.LOW,
    )


def test_redactor() -> None:
    r = BasicRedactor()
    data = {"username": "alice", "password": "secret123", "nested": {"token": "abc", "ok": "hi"}}
    red = r.redact(data)
    assert red["password"] == "***"
    assert red["nested"]["token"] == "***"
    assert red["username"] == "alice"
    assert red["nested"]["ok"] == "hi"


def test_inspector_allow() -> None:
    insp = BasicResultInspector()
    ctx = make_ctx()
    dec = make_decision(Action.ALLOW)
    res = insp.inspect({"output": "hello"}, ctx, dec)
    assert res.action == InspectionAction.ALLOW
    assert res.result == {"output": "hello"}


def test_inspector_redact_sensitive_keys() -> None:
    insp = BasicResultInspector()
    ctx = make_ctx()
    dec = make_decision(Action.ALLOW)
    res = insp.inspect({"password": "secret", "ok": "hi"}, ctx, dec)
    assert res.action == InspectionAction.REDACT
    assert res.result["password"] == "***"
    assert res.result["ok"] == "hi"
    assert "password" in res.blocked_keys


def test_inspector_redact_passwd_value() -> None:
    insp = BasicResultInspector()
    ctx = make_ctx()
    dec = make_decision(Action.ALLOW)
    res = insp.inspect({"data": "user:x:0:0:/etc/passwd"}, ctx, dec)
    assert res.action == InspectionAction.REDACT
    assert "passwd_value" in res.blocked_keys


def test_inspector_block_malicious() -> None:
    insp = BasicResultInspector()
    ctx = make_ctx()
    dec = make_decision(Action.ALLOW)
    res = insp.inspect({"output": "this is malicious exploit"}, ctx, dec)
    assert res.action == InspectionAction.BLOCK
    assert res.result == {
        "output": "this is malicious exploit"
    }  # original preserved, but proxy will block


def test_inspector_restricted_large() -> None:
    insp = BasicResultInspector()
    ctx = make_ctx()
    dec = make_decision(Action.RESTRICT)
    large = {"data": "x" * 10001}
    res = insp.inspect(large, ctx, dec)
    assert res.action == InspectionAction.REDACT
    assert "large output" in res.reasons[0].lower()


def test_proxy_post_execution_redact_and_block() -> None:
    from guardmcp_proxy import GuardMCPProxy

    # redacted case — backend returns password
    def backend_secret(tool_name: str, args: dict) -> dict:
        return {"password": "secret123", "output": "ok"}

    proxy = GuardMCPProxy(
        router=__import__("guardmcp_proxy.router", fromlist=["MCPRouter"]).MCPRouter(
            backend=backend_secret
        )
    )
    res = proxy.handle(
        {
            "tool_name": "read_tool",
            "principal_id": "user_123",
            "authenticated": True,
            "agent_model": "gpt-4",
        }
    )
    # proxy should still be allowed (policy ALLOW) but result redacted
    assert res["allowed"] is True
    # result should be redacted if inspector REDACT
    if res["action"] == "ALLOW":
        # our proxy returns redacted result when inspector says REDACT
        # check audit
        assert any(e.event_type.value == "RESULT_INSPECTED" for e in proxy.sink.list_events())

    # blocked case
    def backend_malicious(tool_name: str, args: dict) -> dict:
        return {"output": "malicious exploit detected"}

    proxy2 = GuardMCPProxy(
        router=__import__("guardmcp_proxy.router", fromlist=["MCPRouter"]).MCPRouter(
            backend=backend_malicious
        )
    )
    res2 = proxy2.handle(
        {
            "tool_name": "read_tool",
            "principal_id": "user_123",
            "authenticated": True,
            "agent_model": "gpt-4",
        }
    )
    assert res2["allowed"] is False
    assert res2["status"] == "blocked"
