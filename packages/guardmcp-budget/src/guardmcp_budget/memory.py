"""In-memory budget provider — concurrency-safe, for dev/tests."""

from __future__ import annotations

import threading

from guardmcp_budget.models import Budget, BudgetReservation


class InMemoryBudgetProvider:
    """Thread-safe in-memory store. Satisfies BudgetProvider protocol."""

    def __init__(self) -> None:
        self._budgets: dict[str, Budget] = {}
        self._reservations: dict[str, BudgetReservation] = {}
        self._lock = threading.Lock()

    def get_budget(self, budget_id: str) -> Budget | None:
        with self._lock:
            return self._budgets.get(budget_id)

    def save_budget(self, budget: Budget) -> None:
        with self._lock:
            self._budgets[budget.budget_id] = budget

    def list_budgets(self, owner_id: str | None = None) -> list[Budget]:
        with self._lock:
            if owner_id is None:
                return list(self._budgets.values())
            return [b for b in self._budgets.values() if b.owner_id == owner_id]

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None:
        with self._lock:
            return self._reservations.get(reservation_id)

    def save_reservation(self, reservation: BudgetReservation) -> None:
        with self._lock:
            self._reservations[reservation.reservation_id] = reservation

    def delete_reservation(self, reservation_id: str) -> None:
        with self._lock:
            self._reservations.pop(reservation_id, None)

    def list_reservations(self, owner_id: str | None = None) -> list[BudgetReservation]:
        with self._lock:
            if owner_id is None:
                return list(self._reservations.values())
            return [r for r in self._reservations.values() if r.owner_id == owner_id]

    # test helper — not part of protocol
    def clear(self) -> None:
        with self._lock:
            self._budgets.clear()
            self._reservations.clear()
