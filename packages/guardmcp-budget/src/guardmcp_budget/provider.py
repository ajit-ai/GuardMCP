"""BudgetProvider — interface for persistence, in-memory for G5."""

from __future__ import annotations

from typing import Protocol

from guardmcp_budget.models import Budget, BudgetReservation


class BudgetProvider(Protocol):
    """Abstract budget store — future PG/Redis adapters."""

    def get_budget(self, budget_id: str) -> Budget | None: ...

    def save_budget(self, budget: Budget) -> None: ...

    def list_budgets(self, owner_id: str | None = None) -> list[Budget]: ...

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None: ...

    def save_reservation(self, reservation: BudgetReservation) -> None: ...

    def delete_reservation(self, reservation_id: str) -> None: ...

    def list_reservations(self, owner_id: str | None = None) -> list[BudgetReservation]: ...
