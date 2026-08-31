"""Budget domain models — immutable, validated."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from guardmcp_core.types import BudgetType


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
class Budget:
    """Budget authority for a principal/agent."""

    budget_id: str
    budget_type: BudgetType
    owner_id: str
    limit: int
    remaining: int
    window_seconds: int = 3600

    def __post_init__(self) -> None:
        _validate_uuid(self.budget_id, "budget_id")
        if not isinstance(self.budget_type, BudgetType):
            raise ValueError(f"budget_type must be BudgetType, got {self.budget_type!r}")
        if not self.owner_id.strip():
            raise ValueError("owner_id must be non-empty")
        if self.limit < 0 or self.remaining < 0:
            raise ValueError("limit/remaining must be non-negative")
        if self.remaining > self.limit:
            raise ValueError("remaining cannot exceed limit")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            "budget_type": self.budget_type.value,
            "owner_id": self.owner_id,
            "limit": self.limit,
            "remaining": self.remaining,
            "window_seconds": self.window_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Budget:
        return cls(
            budget_id=data["budget_id"],
            budget_type=BudgetType(data["budget_type"]),
            owner_id=data["owner_id"],
            limit=int(data["limit"]),
            remaining=int(data["remaining"]),
            window_seconds=int(data.get("window_seconds", 3600)),
        )


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    """Reserved budget — holds amount until consume/release/expire."""

    reservation_id: str
    budget_id: str
    budget_type: BudgetType
    owner_id: str
    amount: int
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _validate_uuid(self.reservation_id, "reservation_id")
        _validate_uuid(self.budget_id, "budget_id")
        if not isinstance(self.budget_type, BudgetType):
            raise ValueError(f"budget_type must be BudgetType, got {self.budget_type!r}")
        if self.amount <= 0:
            raise ValueError("amount must be positive")
        object.__setattr__(self, "created_at", _ensure_tz(self.created_at))
        object.__setattr__(self, "expires_at", _ensure_tz(self.expires_at))
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")

    def is_expired(self, at: datetime | None = None) -> bool:
        at = _ensure_tz(at) if at else datetime.now(UTC)
        return at >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "budget_id": self.budget_id,
            "budget_type": self.budget_type.value,
            "owner_id": self.owner_id,
            "amount": self.amount,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BudgetReservation:
        return cls(
            reservation_id=data["reservation_id"],
            budget_id=data["budget_id"],
            budget_type=BudgetType(data["budget_type"]),
            owner_id=data["owner_id"],
            amount=int(data["amount"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )


@dataclass(frozen=True, slots=True)
class BudgetResult:
    """Result of a budget operation — explainable."""

    success: bool
    budget_type: BudgetType
    operation: str
    remaining: int
    requested: int
    reason: str
    reservation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "budget_type": self.budget_type.value,
            "operation": self.operation,
            "remaining": self.remaining,
            "requested": self.requested,
            "reason": self.reason,
            "reservation_id": self.reservation_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BudgetResult:
        return cls(
            success=bool(data["success"]),
            budget_type=BudgetType(data["budget_type"]),
            operation=str(data["operation"]),
            remaining=int(data["remaining"]),
            requested=int(data["requested"]),
            reason=str(data["reason"]),
            reservation_id=data.get("reservation_id"),
        )
