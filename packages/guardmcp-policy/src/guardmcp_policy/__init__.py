"""guardmcp-policy — modular policy architecture, no infra."""

from __future__ import annotations

from guardmcp_policy.evaluator import PolicyEvaluator
from guardmcp_policy.models import (
    Condition,
    ConditionOperator,
    Policy,
    PolicyResult,
    Rule,
    RuleOperator,
)

__version__ = "0.1.0"

__all__ = [
    "Condition",
    "ConditionOperator",
    "Policy",
    "PolicyEvaluator",
    "PolicyResult",
    "Rule",
    "RuleOperator",
    "__version__",
]
