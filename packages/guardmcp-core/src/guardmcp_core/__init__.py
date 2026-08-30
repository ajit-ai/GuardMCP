"""GuardMCP Core — domain models, no infrastructure dependencies."""

from __future__ import annotations

from guardmcp_core.context import (
    AgentContext,
    BudgetContext,
    DelegationContext,
    EnvironmentContext,
    GuardContext,
    IdentityContext,
    RequestContext,
    ResourceContext,
    SecurityContext,
    ToolContext,
    TraceContext,
)
from guardmcp_core.decision import GuardDecision
from guardmcp_core.request import GuardRequest
from guardmcp_core.result import GuardResult
from guardmcp_core.types import (
    AgentType,
    BudgetType,
    Environment,
    GuardDecisionAction,
    PrincipalType,
    RiskLevel,
)

__version__ = "0.1.0"

__all__ = [
    "AgentContext",
    "AgentType",
    "BudgetContext",
    "BudgetType",
    "DelegationContext",
    # Enums
    "Environment",
    "EnvironmentContext",
    # Contexts
    "GuardContext",
    "GuardDecision",
    "GuardDecisionAction",
    # Request / Decision / Result
    "GuardRequest",
    "GuardResult",
    "IdentityContext",
    "PrincipalType",
    "RequestContext",
    "ResourceContext",
    "RiskLevel",
    "SecurityContext",
    "ToolContext",
    "TraceContext",
    "__version__",
]
