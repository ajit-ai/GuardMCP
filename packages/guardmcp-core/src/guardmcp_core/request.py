"""GuardRequest — inbound protected execution request."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from guardmcp_core.context import GuardContext


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
class GuardRequest:
    """Validated request to GuardMCP — must be constructed before any decision.

    Fields have architectural purpose: request_id/timestamp for audit,
    context for policy/risk/budget/security evaluation.
    """

    request_id: str
    timestamp: datetime
    context: GuardContext
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_uuid(self.request_id, "request_id")
        object.__setattr__(self, "timestamp", _ensure_tz(self.timestamp))
        if self.tool_name == "" and self.context.tool.tool_name == "":
            raise ValueError("tool_name must be set on request or context.tool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context.to_dict(),
            "tool_name": self.tool_name or self.context.tool.tool_name,
            "arguments": self.arguments,
            "headers": self.headers,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardRequest:
        return cls(
            request_id=data["request_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            context=GuardContext.from_dict(data["context"]),
            tool_name=data.get("tool_name", ""),
            arguments=data.get("arguments", {}),
            headers=data.get("headers", {}),
        )
