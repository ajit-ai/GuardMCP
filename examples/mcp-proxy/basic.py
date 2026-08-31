"""Basic MCP Proxy example — G8.

Run: python examples/mcp-proxy/basic.py
"""

from __future__ import annotations

from guardmcp_core.types import GuardDecisionAction as Action
from guardmcp_policy import Condition, Policy, Rule
from guardmcp_policy import ConditionOperator as Op
from guardmcp_proxy import DecisionPipeline, GuardMCPProxy, MCPRouter

# 1. Define a policy: block "blocked_tool", require approval for "sensitive_tool"
policies = [
    Policy(
        id="block-policy",
        name="block sensitive",
        rules=[
            Rule(
                id="r1",
                action=Action.DENY,
                conditions=[
                    Condition(field="tool.tool_name", operator=Op.EQUALS, value="blocked_tool")
                ],
                priority=10,
            ),
            Rule(
                id="r2",
                action=Action.APPROVAL_REQUIRED,
                conditions=[
                    Condition(field="tool.tool_name", operator=Op.EQUALS, value="sensitive_tool")
                ],
                priority=5,
            ),
        ],
    )
]


# 2. Mock backend
def my_backend(tool_name: str, arguments: dict) -> dict:
    return {"output": f"executed {tool_name} with {arguments}"}


# 3. Create proxy
pipeline = DecisionPipeline(policies=policies)
router = MCPRouter(backend=my_backend)
proxy = GuardMCPProxy(pipeline=pipeline, router=router)


# helper to include identity and low-risk agent
def req(tool_name: str, arguments: dict | None = None) -> dict:
    return {
        "tool_name": tool_name,
        "arguments": arguments or {},
        "principal_id": "user_123",
        "authenticated": True,
        "agent_model": "gpt-4",
    }


# 4. ALLOW
print("=== ALLOW ===")
res = proxy.handle(req("read_tool", {"path": "/tmp/file"}))
print(res)
assert res["allowed"] and res["action"] == "ALLOW"

# 5. DENY
print("\n=== DENY ===")
res = proxy.handle(req("blocked_tool"))
print(res)
assert not res["allowed"] and res["action"] == "DENY"

# 6. APPROVAL_REQUIRED
print("\n=== APPROVAL_REQUIRED ===")
res = proxy.handle(req("sensitive_tool"))
print(res)
assert res["action"] == "APPROVAL_REQUIRED"

# 7. RESTRICT via high risk (exec + password → HIGH → RESTRICT)
print("\n=== RESTRICT (high risk) ===")
res = proxy.handle(req("exec", {"password": "secret"}))
print(res)
assert res["action"] in {"RESTRICT", "DENY"}  # exec+password is CRITICAL → DENY
# For pure high risk without critical, use exec with normal args
res2 = proxy.handle(req("exec", {"cmd": "ls"}))
print("exec normal:", res2)
assert res2["action"] == "RESTRICT"

# 8. Audit
print("\n=== AUDIT ===")
print(f"Total audit events: {proxy.sink.count()}")
for e in proxy.sink.list_events()[:5]:
    print(e.event_type, e.metadata)

print("\nG8 example passed — proxy works for ALLOW/DENY/RESTRICT/APPROVAL_REQUIRED")
