"""Budget operation types."""

from __future__ import annotations

from enum import StrEnum


class BudgetOperation(StrEnum):
    """Operations for budget engine."""

    CHECK = "CHECK"
    RESERVE = "RESERVE"
    CONSUME = "CONSUME"
    RELEASE = "RELEASE"
    EXPIRE = "EXPIRE"
