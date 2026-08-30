"""GuardDecision — explainable security decision."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from guardmcp_core.types import GuardDecisionAction, RiskLevel


def _validate_uuid(value: str, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be valid UUID, got {value!r}") from exc


def _ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


@dataclass(frozen=True, slots=True)
class GuardDecision:
    """Explainable decision for a GuardRequest.

    Must provide: action, reasons, risk, policy, restrictions, trace_id.
    Secure-by-default: unknown/invalid conditions default to DENY (enforced by DecisionEngine G6).
    """

    request_id: str
    trace_id: str
    action: GuardDecisionAction
    reasons: list[str] = field(default_factory=list)
    risk_level: RiskLevel | None = None
    policy_id: str | None = None
    restrictions: dict[str, Any] = field(default_factory=dict)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.request_id, "request_id")
        _validate_uuid(self.trace_id, "trace_id")
        if not isinstance(self.action, GuardDecisionAction):
            raise ValueError(f"action must be GuardDecisionAction, got {self.action!r}")
        if not self.reasons:
            raise ValueError(
                "reasons must be non-empty — explainable security requires at least one reason"
            )
        object.__setattr__(self, "evaluated_at", _ensure_tz(self.evaluated_at))
        if self.expires_at is not None:
            exp = _ensure_tz(self.expires_at)
            object.__setattr__(self, "expires_at", exp)
            if exp <= self.evaluated_at:
                raise ValueError("expires_at must be after evaluated_at")
        if self.risk_level is not None and not isinstance(self.risk_level, RiskLevel):
            raise ValueError(f"risk_level must be RiskLevel, got {self.risk_level!r}")

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardDecisionAction.ALLOW

    @property
    def is_denied(self) -> bool:
        return self.action == GuardDecisionAction.DENY

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "action": self.action.value,
            "reasons": list(self.reasons),
            "risk_level": self.risk_level.value if self.risk_level else None,
            "policy_id": self.policy_id,
            "restrictions": dict(self.restrictions),
            "evaluated_at": self.evaluated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardDecision:
        return cls(
            request_id=data["request_id"],
            trace_id=data["trace_id"],
            action=GuardDecisionAction(data["action"]),
            reasons=data.get("reasons", []),
            risk_level=RiskLevel(data["risk_level"]) if data.get("risk_level") else None,
            policy_id=data.get("policy_id"),
            restrictions=data.get("restrictions", {}),
            evaluated_at=datetime.fromisoformat(data["evaluated_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"])
            if data.get("expires_at")
            else None,
        )
