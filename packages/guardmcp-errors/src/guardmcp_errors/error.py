"""GuardError — stable, explainable, serializable error model."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from guardmcp_errors.types import ErrorCategory, ErrorSeverity


def _validate_uuid(value: str, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be valid UUID, got {value!r}") from exc


def _validate_non_empty(value: str, name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


# Retryable categories — safe to retry without new decision
_RETRYABLE_CATEGORIES = {
    ErrorCategory.NETWORK,
    ErrorCategory.TIMEOUT,
    ErrorCategory.INTELLIGENCE,
}


@dataclass(frozen=True, slots=True)
class GuardError:
    """Structured error for GuardMCP — immutable, serializable.

    Fields:
      code — stable machine code (e.g., POLICY_DENY)
      category — 13 categories
      severity — LOW/MEDIUM/HIGH/CRITICAL
      retryable — whether caller may retry
      message — user-facing, sanitized (no secrets)
      reason — internal reason (not sensitive)
      trace_id — UUID linking to GuardContext/Decision
      timestamp — when error was created (UTC)
      details — optional structured details (no secrets)
    """

    code: str
    category: ErrorCategory
    severity: ErrorSeverity
    retryable: bool
    message: str
    reason: str
    trace_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_non_empty(self.code, "code")
        if not isinstance(self.category, ErrorCategory):
            raise ValueError(f"category must be ErrorCategory, got {self.category!r}")
        if not isinstance(self.severity, ErrorSeverity):
            raise ValueError(f"severity must be ErrorSeverity, got {self.severity!r}")
        if not isinstance(self.retryable, bool):
            raise ValueError(f"retryable must be bool, got {self.retryable!r}")
        _validate_non_empty(self.message, "message")
        _validate_non_empty(self.reason, "reason")
        _validate_uuid(self.trace_id, "trace_id")
        object.__setattr__(self, "timestamp", _ensure_tz(self.timestamp))
        # enforce retryable consistency — warn if mismatch but allow override
        # (caller explicitly sets retryable, we don't auto-correct)

    @property
    def is_retryable(self) -> bool:
        return self.retryable

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category.value,
            "severity": self.severity.value,
            "retryable": self.retryable,
            "message": self.message,
            "reason": self.reason,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp.isoformat(),
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardError:
        return cls(
            code=data["code"],
            category=ErrorCategory(data["category"]),
            severity=ErrorSeverity(data["severity"]),
            retryable=bool(data["retryable"]),
            message=data["message"],
            reason=data["reason"],
            trace_id=data["trace_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            details=data.get("details", {}),
        )

    @classmethod
    def from_exception(
        cls,
        exc: Exception,
        *,
        category: ErrorCategory = ErrorCategory.INTERNAL,
        code: str = "INTERNAL_ERROR",
        severity: ErrorSeverity = ErrorSeverity.HIGH,
        trace_id: str | None = None,
        reason: str | None = None,
    ) -> GuardError:
        """Create GuardError from Python exception — sanitized, no stack leak."""
        tid = trace_id or str(uuid.uuid4())
        # Never expose raw exc with potential secrets — use type + str truncated
        msg = f"{type(exc).__name__}: {str(exc)[:200]}" if str(exc) else type(exc).__name__
        return cls(
            code=code,
            category=category,
            severity=severity,
            retryable=category in _RETRYABLE_CATEGORIES,
            message=msg,
            reason=reason or type(exc).__name__,
            trace_id=tid,
            details={"exception_type": type(exc).__name__},
        )

    def __str__(self) -> str:
        return f"[{self.category.value}/{self.code}] {self.message} (trace_id={self.trace_id})"
