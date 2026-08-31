"""BudgetService — CHECK, RESERVE, CONSUME, RELEASE, EXPIRE."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from guardmcp_core.types import BudgetType

from guardmcp_budget.models import Budget, BudgetReservation, BudgetResult
from guardmcp_budget.provider import BudgetProvider
from guardmcp_budget.types import BudgetOperation


class BudgetService:
    """Stateless service over a BudgetProvider. Handles validation and expiration."""

    def __init__(self, provider: BudgetProvider, default_ttl_seconds: int = 300) -> None:
        self._provider = provider
        self._default_ttl = default_ttl_seconds

    def create_budget(
        self, budget_type: BudgetType, owner_id: str, limit: int, window_seconds: int = 3600
    ) -> Budget:
        budget = Budget(
            budget_id=str(uuid.uuid4()),
            budget_type=budget_type,
            owner_id=owner_id,
            limit=limit,
            remaining=limit,
            window_seconds=window_seconds,
        )
        self._provider.save_budget(budget)
        return budget

    def check(self, budget_id: str, amount: int = 1) -> BudgetResult:
        budget = self._provider.get_budget(budget_id)
        if budget is None:
            raise ValueError(f"budget {budget_id} not found")
        success = budget.remaining >= amount
        reason = (
            "sufficient"
            if success
            else f"insufficient: remaining {budget.remaining} < requested {amount}"
        )
        return BudgetResult(
            success=success,
            budget_type=budget.budget_type,
            operation=BudgetOperation.CHECK.value,
            remaining=budget.remaining,
            requested=amount,
            reason=reason,
        )

    def reserve(
        self, budget_id: str, amount: int = 1, ttl_seconds: int | None = None
    ) -> BudgetResult:
        budget = self._provider.get_budget(budget_id)
        if budget is None:
            raise ValueError(f"budget {budget_id} not found")
        if amount <= 0:
            raise ValueError("amount must be positive")
        if budget.remaining < amount:
            return BudgetResult(
                success=False,
                budget_type=budget.budget_type,
                operation=BudgetOperation.RESERVE.value,
                remaining=budget.remaining,
                requested=amount,
                reason=f"insufficient: remaining {budget.remaining} < requested {amount}",
            )
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = datetime.now(UTC)
        reservation = BudgetReservation(
            reservation_id=str(uuid.uuid4()),
            budget_id=budget.budget_id,
            budget_type=budget.budget_type,
            owner_id=budget.owner_id,
            amount=amount,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )
        # deduct and persist
        updated = Budget(
            budget_id=budget.budget_id,
            budget_type=budget.budget_type,
            owner_id=budget.owner_id,
            limit=budget.limit,
            remaining=budget.remaining - amount,
            window_seconds=budget.window_seconds,
        )
        self._provider.save_budget(updated)
        self._provider.save_reservation(reservation)
        return BudgetResult(
            success=True,
            budget_type=budget.budget_type,
            operation=BudgetOperation.RESERVE.value,
            remaining=updated.remaining,
            requested=amount,
            reason="reserved",
            reservation_id=reservation.reservation_id,
        )

    def consume(self, reservation_id: str) -> BudgetResult:
        res = self._provider.get_reservation(reservation_id)
        if res is None:
            raise ValueError(f"reservation {reservation_id} not found")
        # consume just removes reservation (already deducted at reserve)
        self._provider.delete_reservation(reservation_id)
        budget = self._provider.get_budget(res.budget_id)
        remaining = budget.remaining if budget else 0
        return BudgetResult(
            success=True,
            budget_type=res.budget_type,
            operation=BudgetOperation.CONSUME.value,
            remaining=remaining,
            requested=res.amount,
            reason="consumed",
            reservation_id=reservation_id,
        )

    def release(self, reservation_id: str) -> BudgetResult:
        res = self._provider.get_reservation(reservation_id)
        if res is None:
            raise ValueError(f"reservation {reservation_id} not found")
        budget = self._provider.get_budget(res.budget_id)
        if budget is None:
            raise ValueError(f"budget {res.budget_id} not found")
        # return amount
        updated = Budget(
            budget_id=budget.budget_id,
            budget_type=budget.budget_type,
            owner_id=budget.owner_id,
            limit=budget.limit,
            remaining=min(budget.limit, budget.remaining + res.amount),
            window_seconds=budget.window_seconds,
        )
        self._provider.save_budget(updated)
        self._provider.delete_reservation(reservation_id)
        return BudgetResult(
            success=True,
            budget_type=res.budget_type,
            operation=BudgetOperation.RELEASE.value,
            remaining=updated.remaining,
            requested=res.amount,
            reason="released",
            reservation_id=reservation_id,
        )

    def expire(self, at: datetime | None = None) -> int:
        """Release all expired reservations. Returns count expired."""
        now = at or datetime.now(UTC)
        expired = [r for r in self._provider.list_reservations() if r.is_expired(at=now)]
        for r in expired:
            # release will return budget
            try:
                self.release(r.reservation_id)
            except ValueError:
                # budget gone — just delete reservation
                self._provider.delete_reservation(r.reservation_id)
        return len(expired)
