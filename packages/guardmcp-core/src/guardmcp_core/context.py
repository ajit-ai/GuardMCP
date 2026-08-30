"""GuardContext and its 10 sub-contexts — immutable, validated, serializable.

Architecture: Domain layer, no infrastructure imports.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from guardmcp_core.types import (
    AgentType,
    BudgetType,
    Environment,
    PrincipalType,
    RiskLevel,
)


def _validate_uuid(value: str, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be a valid UUID, got {value!r}") from exc


def _validate_non_empty(value: str, name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# Sub-contexts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Inbound request identity."""

    request_id: str
    timestamp: datetime
    method: str = "tool_call"
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_uuid(self.request_id, "request_id")
        _validate_non_empty(self.method, "method")
        object.__setattr__(self, "timestamp", _ensure_tz(self.timestamp))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestContext:
        data = dict(data)
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class IdentityContext:
    """Resolved principal identity."""

    principal_type: PrincipalType
    principal_id: str
    display_name: str = ""
    authenticated: bool = False
    issuer: str = ""

    def __post_init__(self) -> None:
        _validate_non_empty(self.principal_id, "principal_id")
        if not isinstance(self.principal_type, PrincipalType):
            raise ValueError(f"principal_type must be PrincipalType, got {self.principal_type!r}")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["principal_type"] = self.principal_type.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdentityContext:
        data = dict(data)
        data["principal_type"] = PrincipalType(data["principal_type"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class DelegationContext:
    """Delegation chain from human → application → agent → tool."""

    delegator: str
    delegate: str
    scope: list[str] = field(default_factory=list)
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    delegation_chain: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _validate_non_empty(self.delegator, "delegator")
        _validate_non_empty(self.delegate, "delegate")
        object.__setattr__(self, "issued_at", _ensure_tz(self.issued_at))
        if self.expires_at is not None:
            exp = _ensure_tz(self.expires_at)
            object.__setattr__(self, "expires_at", exp)
            if exp <= self.issued_at:
                raise ValueError("expires_at must be after issued_at")

    def is_expired(self, at: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        at = _ensure_tz(at) if at else datetime.now(UTC)
        return at >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["issued_at"] = self.issued_at.isoformat()
        if self.expires_at:
            d["expires_at"] = self.expires_at.isoformat()
        else:
            d["expires_at"] = None
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DelegationContext:
        data = dict(data)
        data["issued_at"] = datetime.fromisoformat(data["issued_at"])
        if data.get("expires_at"):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class AgentContext:
    """AI agent identity."""

    agent_id: str
    agent_type: AgentType = AgentType.ASSISTANT
    model: str = ""
    version: str = ""
    name: str = ""

    def __post_init__(self) -> None:
        _validate_non_empty(self.agent_id, "agent_id")
        if not isinstance(self.agent_type, AgentType):
            raise ValueError(f"agent_type must be AgentType, got {self.agent_type!r}")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["agent_type"] = self.agent_type.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentContext:
        data = dict(data)
        data["agent_type"] = AgentType(data["agent_type"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ToolContext:
    """Target MCP tool."""

    tool_name: str
    tool_version: str = ""
    server_id: str = ""
    description: str = ""
    category: str = ""

    def __post_init__(self) -> None:
        _validate_non_empty(self.tool_name, "tool_name")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolContext:
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ResourceContext:
    """Target resource (file, API, DB, etc.)."""

    resource_id: str = ""
    resource_type: str = ""
    uri: str = ""
    owner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceContext:
        return cls(**data)


@dataclass(frozen=True, slots=True)
class EnvironmentContext:
    """Runtime environment."""

    environment: Environment = Environment.DEVELOPMENT
    region: str = ""
    ip: str = ""
    user_agent: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.environment, Environment):
            raise ValueError(f"environment must be Environment, got {self.environment!r}")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["environment"] = self.environment.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvironmentContext:
        data = dict(data)
        data["environment"] = Environment(data["environment"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class BudgetContext:
    """Execution authority limits snapshot."""

    budgets: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for k, v in self.budgets.items():
            if not isinstance(v, int) or v < 0:
                raise ValueError(f"budget {k} must be non-negative int, got {v!r}")
            if k not in {t.value for t in BudgetType}:
                # allow custom but warn via validation — accept any for now
                pass

    def remaining(self, budget_type: BudgetType) -> int | None:
        return self.budgets.get(budget_type.value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BudgetContext:
        return cls(**data)


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Security intelligence snapshot."""

    threat_level: RiskLevel = RiskLevel.LOW
    provider: str = ""
    signals: list[str] = field(default_factory=list)
    intelligence_timestamp: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.threat_level, RiskLevel):
            raise ValueError(f"threat_level must be RiskLevel, got {self.threat_level!r}")
        if self.intelligence_timestamp is not None:
            object.__setattr__(
                self, "intelligence_timestamp", _ensure_tz(self.intelligence_timestamp)
            )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["threat_level"] = self.threat_level.value
        if self.intelligence_timestamp:
            d["intelligence_timestamp"] = self.intelligence_timestamp.isoformat()
        else:
            d["intelligence_timestamp"] = None
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityContext:
        data = dict(data)
        data["threat_level"] = RiskLevel(data["threat_level"])
        if data.get("intelligence_timestamp"):
            data["intelligence_timestamp"] = datetime.fromisoformat(data["intelligence_timestamp"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class TraceContext:
    """Distributed tracing identifiers."""

    trace_id: str
    request_id: str
    span_id: str = ""
    parent_span_id: str | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.trace_id, "trace_id")
        _validate_uuid(self.request_id, "request_id")
        if self.span_id:
            _validate_non_empty(self.span_id, "span_id")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TraceContext:
        return cls(**data)


# ---------------------------------------------------------------------------
# GuardContext — aggregate
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GuardContext:
    """Central context for a protected execution — 10 sub-contexts.

    Immutable, validated, serializable. No infrastructure dependencies.
    """

    request: RequestContext
    identity: IdentityContext
    delegation: DelegationContext
    agent: AgentContext
    tool: ToolContext
    resource: ResourceContext
    environment: EnvironmentContext
    budget: BudgetContext
    security: SecurityContext
    trace: TraceContext

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "identity": self.identity.to_dict(),
            "delegation": self.delegation.to_dict(),
            "agent": self.agent.to_dict(),
            "tool": self.tool.to_dict(),
            "resource": self.resource.to_dict(),
            "environment": self.environment.to_dict(),
            "budget": self.budget.to_dict(),
            "security": self.security.to_dict(),
            "trace": self.trace.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardContext:
        return cls(
            request=RequestContext.from_dict(data["request"]),
            identity=IdentityContext.from_dict(data["identity"]),
            delegation=DelegationContext.from_dict(data["delegation"]),
            agent=AgentContext.from_dict(data["agent"]),
            tool=ToolContext.from_dict(data["tool"]),
            resource=ResourceContext.from_dict(data["resource"]),
            environment=EnvironmentContext.from_dict(data["environment"]),
            budget=BudgetContext.from_dict(data["budget"]),
            security=SecurityContext.from_dict(data["security"]),
            trace=TraceContext.from_dict(data["trace"]),
        )
