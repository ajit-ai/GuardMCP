"""ContextBuilder — constructs GuardContext from MCP request."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

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
from guardmcp_core.types import AgentType


class ContextBuilder:
    """Builds GuardContext from raw MCP request — adapter layer, no domain pollution."""

    def build(self, request: dict[str, Any]) -> GuardContext:
        tool_name: str = str(request.get("tool_name") or request.get("tool") or "unknown_tool")
        arguments: dict[str, Any] = dict(request.get("arguments") or {})
        headers: dict[str, str] = dict(request.get("headers") or {})

        # identity hints
        principal_id: str = str(
            request.get("principal_id") or headers.get("x-principal-id") or "anonymous"
        )
        principal_type_raw: str = str(request.get("principal_type") or "human").lower()
        try:
            principal_type = PT(principal_type_raw)
        except ValueError:
            principal_type = PT.HUMAN

        authenticated = bool(request.get("authenticated", principal_id != "anonymous"))
        issuer: str = str(request.get("issuer") or "")

        # delegation hints
        delegator: str = str(request.get("delegator") or f"human:{principal_id}")
        delegate: str = str(
            request.get("delegate") or f"agent:{request.get('agent_id', 'default')}"
        )

        # agent hints
        agent_id: str = str(request.get("agent_id") or "agent_1")
        agent_model: str = str(request.get("agent_model") or request.get("model") or "")

        # resource hints
        resource_id: str = str(request.get("resource_id") or "")
        uri: str = str(request.get("uri") or "")

        # environment hints
        env_raw: str = str(request.get("environment") or "development").lower()
        try:
            env = Env(env_raw)
        except ValueError:
            env = Env.DEVELOPMENT

        # security hints
        threat_raw: str = str(request.get("threat_level") or "LOW").upper()
        try:
            threat = RL(threat_raw)
        except ValueError:
            threat = RL.LOW

        now = datetime.now(UTC)
        request_id = str(request.get("request_id") or uuid.uuid4())
        trace_id = str(request.get("trace_id") or uuid.uuid4())
        # validate uuids — generate if not valid
        try:
            uuid.UUID(request_id)
        except ValueError:
            request_id = str(uuid.uuid4())
        try:
            uuid.UUID(trace_id)
        except ValueError:
            trace_id = str(uuid.uuid4())

        return GuardContext(
            request=RC(
                request_id=request_id, timestamp=now, tool_name=tool_name, arguments=arguments
            ),
            identity=IC(
                principal_type=principal_type,
                principal_id=principal_id,
                authenticated=authenticated,
                issuer=issuer,
            ),
            delegation=DC(
                delegator=delegator,
                delegate=delegate,
                issued_at=now - timedelta(minutes=5),
                expires_at=now + timedelta(hours=1),
                delegation_chain=[delegator, delegate],
            ),
            agent=AC(agent_id=agent_id, agent_type=AgentType.ASSISTANT, model=agent_model),
            tool=TC(tool_name=tool_name),
            resource=ResC(resource_id=resource_id, uri=uri),
            environment=EC(environment=env),
            budget=BC(budgets={}),
            security=SC(threat_level=threat),
            trace=TrC(trace_id=trace_id, request_id=request_id),
        )
