"""G5: Budget engine — CHECK, RESERVE, CONSUME, RELEASE, EXPIRE."""

from __future__ import annotations

import threading
import time

import pytest
from guardmcp_budget import BudgetOperation, BudgetService, InMemoryBudgetProvider
from guardmcp_core.types import BudgetType


def test_budget_check_and_reserve() -> None:
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.TOOL_CALL, owner_id="user_1", limit=5)

    # check
    r = svc.check(b.budget_id, amount=3)
    assert r.success
    assert r.remaining == 5

    r2 = svc.check(b.budget_id, amount=10)
    assert not r2.success

    # reserve
    res = svc.reserve(b.budget_id, amount=3)
    assert res.success
    assert res.remaining == 2
    assert res.reservation_id is not None

    # second reserve exceeding remaining
    res2 = svc.reserve(b.budget_id, amount=3)
    assert not res2.success
    assert res2.remaining == 2


def test_budget_consume_and_release() -> None:
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.NETWORK_CALL, owner_id="user_1", limit=10)
    res = svc.reserve(b.budget_id, amount=4)
    assert res.reservation_id is not None

    # consume — removes reservation, already deducted
    c = svc.consume(res.reservation_id)
    assert c.success
    assert c.remaining == 6
    assert provider.get_reservation(res.reservation_id) is None

    # reserve again and release — returns budget
    res2 = svc.reserve(b.budget_id, amount=2)
    assert res2.remaining == 4
    rel = svc.release(res2.reservation_id)
    assert rel.success
    assert rel.remaining == 6  # 4 +2
    assert provider.get_reservation(res2.reservation_id) is None


def test_budget_expire() -> None:
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider, default_ttl_seconds=1)
    b = svc.create_budget(BudgetType.TIME, owner_id="user_1", limit=5)
    res = svc.reserve(b.budget_id, amount=2, ttl_seconds=1)
    assert res.success
    assert svc.check(b.budget_id, amount=4).success is False  # 3 remaining
    time.sleep(1.2)
    expired = svc.expire()
    assert expired == 1
    # after expire, budget returned
    assert svc.check(b.budget_id, amount=5).success
    assert provider.list_reservations() == []


def test_budget_validation_and_serialization() -> None:
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.DATA, owner_id="user_1", limit=100, window_seconds=3600)
    assert b.to_dict()["budget_type"] == "data"
    from guardmcp_budget import Budget

    assert Budget.from_dict(b.to_dict()) == b

    res = svc.reserve(b.budget_id, amount=10, ttl_seconds=60)
    assert res.reservation_id is not None
    # reservation serialization
    r_obj = provider.get_reservation(res.reservation_id)
    assert r_obj is not None
    assert r_obj.to_dict()["budget_id"] == b.budget_id
    from guardmcp_budget import BudgetReservation

    assert BudgetReservation.from_dict(r_obj.to_dict()) == r_obj

    # result serialization
    assert res.to_dict()["operation"] == BudgetOperation.RESERVE.value
    from guardmcp_budget import BudgetResult

    assert BudgetResult.from_dict(res.to_dict()) == res


def test_budget_concurrency_safe() -> None:
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    b = svc.create_budget(BudgetType.TOOL_CALL, owner_id="user_1", limit=100)
    successes: list[bool] = []

    def reserve_one() -> None:
        r = svc.reserve(b.budget_id, amount=10)
        successes.append(r.success)

    threads = [threading.Thread(target=reserve_one) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(successes) == 5
    assert svc.check(b.budget_id, amount=1).remaining == 50


def test_budget_error_cases() -> None:
    provider = InMemoryBudgetProvider()
    svc = BudgetService(provider)
    with pytest.raises(ValueError, match="not found"):
        svc.check("00000000-0000-0000-0000-000000000000")
    b = svc.create_budget(BudgetType.COST, owner_id="user_1", limit=5)
    with pytest.raises(ValueError, match="amount must be positive"):
        svc.reserve(b.budget_id, amount=0)
    with pytest.raises(ValueError, match="not found"):
        svc.consume("00000000-0000-0000-0000-000000000000")
    with pytest.raises(ValueError, match="not found"):
        svc.release("00000000-0000-0000-0000-000000000000")


def test_budget_operation_enum() -> None:
    assert {op.value for op in BudgetOperation} == {
        "CHECK",
        "RESERVE",
        "CONSUME",
        "RELEASE",
        "EXPIRE",
    }
