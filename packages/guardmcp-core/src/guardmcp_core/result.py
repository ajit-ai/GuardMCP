"""GuardResult — post-execution result with decision and audit linkage."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from guardmcp_core.context import GuardContext
from guardmcp_core.decision import GuardDecision


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
class GuardResult:
    """Result of a protected execution — links decision, context, and tool output."""

    request_id: str
    trace_id: str
    decision: GuardDecision
    context: GuardContext
    execution_output: dict[str, Any] | None = None
    error: str | None = None
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.request_id, "request_id")
        _validate_uuid(self.trace_id, "trace_id")
        if self.request_id != self.decision.request_id:
            raise ValueError("request_id must match decision.request_id")
        if self.trace_id != self.decision.trace_id:
            raise ValueError("trace_id must match decision.trace_id")
        if self.completed_at is not None:
            object.__setattr__(self, "completed_at", _ensure_tz(self.completed_at))

    @property
    def success(self) -> bool:
        return self.error is None and self.decision.is_allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "decision": self.decision.to_dict(),
            "context": self.context.to_dict(),
            "execution_output": self.execution_output,
            "error": self.error,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardResult:
        return cls(
            request_id=data["request_id"],
            trace_id=data["trace_id"],
            decision=GuardDecision.from_dict(data["decision"]),
            context=GuardContext.from_dict(data["context"]),
            execution_output=data.get("execution_output"),
            error=data.get("error"),
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None,
        )
