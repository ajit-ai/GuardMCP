"""Policy domain models — Condition → Rule → Policy → Result.

No infrastructure dependencies. Depends only on guardmcp_core.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from guardmcp_core.types import GuardDecisionAction


class ConditionOperator(StrEnum):
    """Operator for a single condition."""

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    IN = "IN"
    NOT_IN = "NOT_IN"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    REGEX = "REGEX"
    EXISTS = "EXISTS"
    NOT_EXISTS = "NOT_EXISTS"
    GT = "GT"
    LT = "LT"


class RuleOperator(StrEnum):
    """How to combine conditions within a rule."""

    AND = "AND"
    OR = "OR"


def _validate_non_empty(value: str, name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _validate_uuid(value: str, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be valid UUID, got {value!r}") from exc


def _get_field(context: Any, field_path: str) -> Any:
    """Resolve dot-path against GuardContext.

    Supports: identity.principal_id, agent.model, tool.tool_name,
              arguments.<key>, request.arguments.<key>, environment.environment, etc.
    """
    # arguments is stored in request.arguments
    if field_path.startswith("arguments."):
        key = field_path.split(".", 1)[1]
        # context.request.arguments
        try:
            return context.request.arguments.get(key, None)
        except AttributeError:
            return None
    if field_path.startswith("request.arguments."):
        key = field_path.split(".", 2)[2]
        try:
            return context.request.arguments.get(key, None)
        except AttributeError:
            return None

    parts = field_path.split(".")
    cur: Any = context
    for part in parts:
        if cur is None:
            return None
        # handle dicts
        if isinstance(cur, dict):
            cur = cur.get(part)
            continue
        # handle enum value comparison — return raw value if enum
        cur = getattr(cur, part, None)
        # unwrap StrEnum to value for comparison
        if isinstance(cur, StrEnum):
            cur = cur.value
    return cur


@dataclass(frozen=True, slots=True)
class Condition:
    """Single predicate — field, operator, expected value."""

    field: str
    operator: ConditionOperator
    value: Any = None

    def __post_init__(self) -> None:
        _validate_non_empty(self.field, "field")
        if not isinstance(self.operator, ConditionOperator):
            raise ValueError(f"operator must be ConditionOperator, got {self.operator!r}")
        # value can be None for EXISTS/NOT_EXISTS
        if self.operator in {ConditionOperator.EXISTS, ConditionOperator.NOT_EXISTS}:
            if self.value is not None:
                raise ValueError(f"value must be None for {self.operator}, got {self.value!r}")
        elif self.operator in {
            ConditionOperator.IN,
            ConditionOperator.NOT_IN,
        } and not isinstance(self.value, (list, tuple, set)):
            raise ValueError(f"value must be list/tuple/set for {self.operator}")

    def evaluate(self, context: Any) -> bool:
        actual = _get_field(context, self.field)
        op = self.operator
        expected = self.value

        if op == ConditionOperator.EXISTS:
            return actual is not None
        if op == ConditionOperator.NOT_EXISTS:
            return actual is None
        if op == ConditionOperator.EQUALS:
            return bool(actual == expected)
        if op == ConditionOperator.NOT_EQUALS:
            return bool(actual != expected)
        if op == ConditionOperator.IN:
            return bool(actual in expected)
        if op == ConditionOperator.NOT_IN:
            return bool(actual not in expected)
        if op == ConditionOperator.CONTAINS:
            if actual is None or expected is None:
                return False
            return str(expected) in str(actual)
        if op == ConditionOperator.NOT_CONTAINS:
            if actual is None or expected is None:
                return True
            return str(expected) not in str(actual)
        if op == ConditionOperator.REGEX:
            if actual is None:
                return False
            return re.search(str(expected), str(actual)) is not None
        if op == ConditionOperator.GT:
            if actual is None or expected is None:
                return False
            return bool(actual > expected)
        if op == ConditionOperator.LT:
            if actual is None or expected is None:
                return False
            return bool(actual < expected)
        return False

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "operator": self.operator.value, "value": self.value}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Condition:
        return cls(
            field=data["field"],
            operator=ConditionOperator(data["operator"]),
            value=data.get("value"),
        )


@dataclass(frozen=True, slots=True)
class Rule:
    """Rule — conditions combined, produces an action."""

    id: str
    action: GuardDecisionAction
    conditions: list[Condition] = field(default_factory=list)
    operator: RuleOperator = RuleOperator.AND
    description: str = ""
    priority: int = 0
    restrictions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_non_empty(self.id, "id")
        if not isinstance(self.action, GuardDecisionAction):
            raise ValueError(f"action must be GuardDecisionAction, got {self.action!r}")
        if not isinstance(self.operator, RuleOperator):
            raise ValueError(f"operator must be RuleOperator, got {self.operator!r}")

    def matches(self, context: Any) -> bool:
        if not self.conditions:
            return True
        results = [c.evaluate(context) for c in self.conditions]
        if self.operator == RuleOperator.AND:
            return all(results)
        return any(results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action.value,
            "conditions": [c.to_dict() for c in self.conditions],
            "operator": self.operator.value,
            "description": self.description,
            "priority": self.priority,
            "restrictions": dict(self.restrictions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        return cls(
            id=data["id"],
            action=GuardDecisionAction(data["action"]),
            conditions=[Condition.from_dict(c) for c in data.get("conditions", [])],
            operator=RuleOperator(data.get("operator", "AND")),
            description=data.get("description", ""),
            priority=data.get("priority", 0),
            restrictions=data.get("restrictions", {}),
        )


@dataclass(frozen=True, slots=True)
class Policy:
    """Policy — ordered rules with identity."""

    id: str
    name: str
    rules: list[Rule] = field(default_factory=list)
    description: str = ""
    enabled: bool = True
    priority: int = 0

    def __post_init__(self) -> None:
        _validate_non_empty(self.id, "id")
        _validate_non_empty(self.name, "name")
        # validate uuid if id looks like uuid — allow non-uuid names
        import contextlib

        with contextlib.suppress(ValueError):
            _validate_uuid(self.id, "id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "rules": [r.to_dict() for r in self.rules],
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls(
            id=data["id"],
            name=data["name"],
            rules=[Rule.from_dict(r) for r in data.get("rules", [])],
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            priority=data.get("priority", 0),
        )


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """Result of policy evaluation — explainable."""

    action: GuardDecisionAction
    matched_policy_id: str | None = None
    matched_rule_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    restrictions: dict[str, Any] = field(default_factory=dict)
    evaluated_policies: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "matched_policy_id": self.matched_policy_id,
            "matched_rule_id": self.matched_rule_id,
            "reasons": list(self.reasons),
            "restrictions": dict(self.restrictions),
            "evaluated_policies": self.evaluated_policies,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyResult:
        return cls(
            action=GuardDecisionAction(data["action"]),
            matched_policy_id=data.get("matched_policy_id"),
            matched_rule_id=data.get("matched_rule_id"),
            reasons=data.get("reasons", []),
            restrictions=data.get("restrictions", {}),
            evaluated_policies=data.get("evaluated_policies", 0),
        )
