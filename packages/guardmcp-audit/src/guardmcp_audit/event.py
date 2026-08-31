"""AuditEvent — domain event, immutable, serializable."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from guardmcp_audit.types import AuditEventType


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
class AuditEvent:
    """Domain event for audit trail.

    Fields: event_id, timestamp, request_id, trace_id, event_type, metadata
    plus optional actor and duration for observability.
    """

    event_id: str
    timestamp: datetime
    request_id: str
    trace_id: str
    event_type: AuditEventType
    metadata: dict[str, Any] = field(default_factory=dict)
    actor: str = ""
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.event_id, "event_id")
        _validate_uuid(self.request_id, "request_id")
        _validate_uuid(self.trace_id, "trace_id")
        if not isinstance(self.event_type, AuditEventType):
            raise ValueError(f"event_type must be AuditEventType, got {self.event_type!r}")
        object.__setattr__(self, "timestamp", _ensure_tz(self.timestamp))
        if self.duration_ms is not None and self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "event_type": self.event_type.value,
            "metadata": dict(self.metadata),
            "actor": self.actor,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        return cls(
            event_id=data["event_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            request_id=data["request_id"],
            trace_id=data["trace_id"],
            event_type=AuditEventType(data["event_type"]),
            metadata=data.get("metadata", {}),
            actor=data.get("actor", ""),
            duration_ms=data.get("duration_ms"),
        )

    @classmethod
    def create(
        cls,
        request_id: str,
        trace_id: str,
        event_type: AuditEventType,
        metadata: dict[str, Any] | None = None,
        actor: str = "",
        duration_ms: int | None = None,
    ) -> AuditEvent:
        """Factory — generates event_id and timestamp."""
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            request_id=request_id,
            trace_id=trace_id,
            event_type=event_type,
            metadata=metadata or {},
            actor=actor,
            duration_ms=duration_ms,
        )
