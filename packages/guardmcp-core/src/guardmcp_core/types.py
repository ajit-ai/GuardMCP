"""Shared value objects and enums for GuardMCP core domain.

No infrastructure dependencies. Pure domain types.
"""

from __future__ import annotations

from enum import StrEnum


class Environment(StrEnum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class PrincipalType(StrEnum):
    """Identity principal type in the delegation chain."""

    HUMAN = "human"
    APPLICATION = "application"
    SERVICE = "service"
    AGENT = "agent"


class AgentType(StrEnum):
    """AI agent type."""

    ASSISTANT = "assistant"
    AUTONOMOUS = "autonomous"
    WORKFLOW = "workflow"
    TOOL = "tool"


class GuardDecisionAction(StrEnum):
    """Policy decision actions — must be explainable."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    RESTRICT = "RESTRICT"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SANDBOX = "SANDBOX"


class RiskLevel(StrEnum):
    """Risk levels for explainable risk engine (G4)."""

    LOW = "LOW"
    MODERATE = "MODERATE"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BudgetType(StrEnum):
    """Budget authority types."""

    TOOL_CALL = "tool_call"
    NETWORK_CALL = "network_call"
    TIME = "time"
    DATA = "data"
    PRIVILEGE = "privilege"
    COST = "cost"
