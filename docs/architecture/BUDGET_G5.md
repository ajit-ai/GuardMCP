# G5 — Budget Engine

## Architecture

```
Budget (6 types) → BudgetProvider (Protocol) → InMemoryBudgetProvider (thread-safe dict + Lock) → BudgetService (CHECK/RESERVE/CONSUME/RELEASE/EXPIRE)
```

Future: `PostgreSQL`/`Redis` adapters via same `BudgetProvider` — no core change.

## Budget Types

`BudgetType` from `guardmcp_core.types`: `TOOL_CALL, NETWORK_CALL, TIME, DATA, PRIVILEGE, COST` (StrEnum).

## Models

- `Budget(budget_id UUID, budget_type, owner_id, limit, remaining, window_seconds)` — frozen, `remaining <= limit`, `to_dict/from_dict`
- `BudgetReservation(reservation_id UUID, budget_id UUID, budget_type, owner_id, amount>0, created_at, expires_at)` — `is_expired(at)`, TTL default 300s, `expires_at > created_at`
- `BudgetResult(success, budget_type, operation, remaining, requested, reason, reservation_id)` — explainable

## Provider

`BudgetProvider` Protocol: `get_budget, save_budget, list_budgets, get_reservation, save_reservation, delete_reservation, list_reservations`

`InMemoryBudgetProvider` — `dict[str,Budget]` + `dict[str,BudgetReservation]` + `threading.Lock`, `clear()` helper for tests.

## Service

`BudgetService(provider, default_ttl_seconds=300)`

- `create_budget(type, owner_id, limit, window)` → `Budget`
- `check(budget_id, amount) → BudgetResult` (no mutation)
- `reserve(budget_id, amount, ttl) → BudgetResult` (deducts `remaining`, creates reservation, `expires_at = now+ttl`)
- `consume(reservation_id) → BudgetResult` (deletes reservation, already deducted)
- `release(reservation_id) → BudgetResult` (returns amount to `remaining`, caps at `limit`, deletes reservation)
- `expire(at?) → int` (scans reservations, `release` expired, returns count)

Concurrency: all provider ops under `Lock`; service is stateless, handles validation (`amount>0`, `remaining >= amount`, budget exists).

## Files

- `packages/guardmcp-budget/src/guardmcp_budget/types.py` — `BudgetOperation`
- `packages/guardmcp-budget/src/guardmcp_budget/models.py` — `Budget, Reservation, Result`
- `packages/guardmcp-budget/src/guardmcp_budget/provider.py` — `BudgetProvider`
- `packages/guardmcp-budget/src/guardmcp_budget/memory.py` — `InMemoryBudgetProvider`
- `packages/guardmcp-budget/src/guardmcp_budget/service.py` — `BudgetService`
- `packages/guardmcp-budget/src/guardmcp_budget/__init__.py` — public API
- `packages/guardmcp-budget/pyproject.toml` — depends on `guardmcp-core`

## Tests

`tests/unit/test_budget.py` — 7 tests: check/reserve, consume/release, expire (TTL 1s + sleep), validation/serialization, concurrency (5 threads ×10), error cases, operation enum → 50 total.

## Bugs fixed in G5

- `ruff` TC001/TC002 (move imports to TYPE_CHECKING) — ignored via `ignore = ["TC001","TC002","TC003"]` in `pyproject.toml`
- `mypy` `unused-ignore` for `InMemoryBudgetProvider` isinstance assert → removed, and `BudgetProvider` unused import → removed
- `pytest` pythonpath missing `guardmcp-budget` → added all packages to `pyproject.toml:70`
