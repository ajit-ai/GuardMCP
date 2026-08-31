"""Risk domain models — Signal, Factor, Score, Result."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from guardmcp_core.types import RiskLevel


class RiskSignalCategory(StrEnum):
    """7 signal categories as per spec."""

    IDENTITY_RISK = "IdentityRisk"
    DELEGATION_RISK = "DelegationRisk"
    AGENT_RISK = "AgentRisk"
    TOOL_RISK = "ToolRisk"
    ARGUMENT_RISK = "ArgumentRisk"
    RESOURCE_RISK = "ResourceRisk"
    SECURITY_RISK = "SecurityRisk"


def _validate_uuid(value: str, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be valid UUID, got {value!r}") from exc


def _ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _score_to_level(score: float) -> RiskLevel:
    if score >= 81:
        return RiskLevel.CRITICAL
    if score >= 61:
        return RiskLevel.HIGH
    if score >= 41:
        return RiskLevel.ELEVATED
    if score >= 21:
        return RiskLevel.MODERATE
    return RiskLevel.LOW


@dataclass(frozen=True, slots=True)
class RiskSignal:
    """Single risk signal — explainable."""

    signal_id: str
    category: RiskSignalCategory
    score: float
    confidence: float
    description: str
    indicators: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _validate_uuid(self.signal_id, "signal_id")
        if not isinstance(self.category, RiskSignalCategory):
            raise ValueError(f"category must be RiskSignalCategory, got {self.category!r}")
        if not 0 <= self.score <= 100:
            raise ValueError(f"score must be 0-100, got {self.score!r}")
        if not 0 <= self.confidence <= 1:
            raise ValueError(f"confidence must be 0-1, got {self.confidence!r}")
        if not self.description.strip():
            raise ValueError("description must be non-empty")
        object.__setattr__(self, "timestamp", _ensure_tz(self.timestamp))

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "category": self.category.value,
            "score": self.score,
            "confidence": self.confidence,
            "description": self.description,
            "indicators": list(self.indicators),
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskSignal:
        return cls(
            signal_id=data["signal_id"],
            category=RiskSignalCategory(data["category"]),
            score=float(data["score"]),
            confidence=float(data["confidence"]),
            description=data["description"],
            indicators=data.get("indicators", []),
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """Aggregated factor for a category — weighted signals."""

    factor_id: str
    name: str
    category: RiskSignalCategory
    weight: float
    signals: list[RiskSignal] = field(default_factory=list)
    score: float = 0.0

    def __post_init__(self) -> None:
        _validate_uuid(self.factor_id, "factor_id")
        if not 0 <= self.weight <= 1:
            raise ValueError(f"weight must be 0-1, got {self.weight!r}")
        if not 0 <= self.score <= 100:
            raise ValueError(f"score must be 0-100, got {self.score!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor_id": self.factor_id,
            "name": self.name,
            "category": self.category.value,
            "weight": self.weight,
            "signals": [s.to_dict() for s in self.signals],
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskFactor:
        return cls(
            factor_id=data["factor_id"],
            name=data["name"],
            category=RiskSignalCategory(data["category"]),
            weight=float(data["weight"]),
            signals=[RiskSignal.from_dict(s) for s in data.get("signals", [])],
            score=float(data["score"]),
        )


@dataclass(frozen=True, slots=True)
class RiskScore:
    """Total score and level."""

    total_score: float
    level: RiskLevel
    factors: list[RiskFactor] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0 <= self.total_score <= 100:
            raise ValueError(f"total_score must be 0-100, got {self.total_score!r}")
        if not isinstance(self.level, RiskLevel):
            raise ValueError(f"level must be RiskLevel, got {self.level!r}")
        expected = _score_to_level(self.total_score)
        if self.level != expected:
            raise ValueError(
                f"level {self.level!r} inconsistent with score {self.total_score} -> {expected!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_score": self.total_score,
            "level": self.level.value,
            "factors": [f.to_dict() for f in self.factors],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskScore:
        return cls(
            total_score=float(data["total_score"]),
            level=RiskLevel(data["level"]),
            factors=[RiskFactor.from_dict(f) for f in data.get("factors", [])],
        )


@dataclass(frozen=True, slots=True)
class RiskResult:
    """Complete risk evaluation — explainable."""

    request_id: str
    trace_id: str
    score: RiskScore
    level: RiskLevel
    signals: list[RiskSignal] = field(default_factory=list)
    factors: list[RiskFactor] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _validate_uuid(self.request_id, "request_id")
        _validate_uuid(self.trace_id, "trace_id")
        if not isinstance(self.level, RiskLevel):
            raise ValueError(f"level must be RiskLevel, got {self.level!r}")
        if self.level != self.score.level:
            raise ValueError("level must match score.level")
        object.__setattr__(self, "evaluated_at", _ensure_tz(self.evaluated_at))
        if not self.reasons:
            raise ValueError("reasons must be non-empty — explainable")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "score": self.score.to_dict(),
            "level": self.level.value,
            "signals": [s.to_dict() for s in self.signals],
            "factors": [f.to_dict() for f in self.factors],
            "reasons": list(self.reasons),
            "evaluated_at": self.evaluated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskResult:
        return cls(
            request_id=data["request_id"],
            trace_id=data["trace_id"],
            score=RiskScore.from_dict(data["score"]),
            level=RiskLevel(data["level"]),
            signals=[RiskSignal.from_dict(s) for s in data.get("signals", [])],
            factors=[RiskFactor.from_dict(f) for f in data.get("factors", [])],
            reasons=data.get("reasons", []),
            evaluated_at=datetime.fromisoformat(data["evaluated_at"]),
        )
