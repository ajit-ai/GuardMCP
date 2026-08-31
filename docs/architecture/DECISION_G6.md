# G6 — Decision Engine

## Architecture

```
IdentityResult + DelegationResult + PolicyResult + RiskResult + BudgetResult + SecurityResult
                                  ↓
                           DecisionEngine
                                  ↓
                           GuardDecision
```

Final authority — explicit precedence, deterministic, explainable. No scattered logic.

## Precedence (8 steps)

1. **Invalid identity** → `DENY` (missing principal_id or unauthenticated)
2. **Invalid delegation** → `DENY` (expired)
3. **Explicit policy deny** → `DENY` (`policy.action==DENY`)
4. **Critical confirmed security threat** → `DENY` (`security.threat_level==CRITICAL` or `risk.level==CRITICAL`)
5. **Budget exhausted** → `DENY` (or `RESTRICT` if policy is RESTRICT)
6. **Explicit approval requirement** → `APPROVAL_REQUIRED` (`policy.action==APPROVAL_REQUIRED`)
7. **Handle SANDBOX/RESTRICT from policy** → return policy action (if no higher DENY)
8. **High risk** → `RESTRICT` (`risk HIGH/ELEVATED → RESTRICT`; CRITICAL already DENY)
9. **Otherwise** → `ALLOW`

## Explainable Security

Every decision provides:

```
action, reasons (list), risk_level, policy_id, restrictions, trace_id, evaluated_at
```

`reasons` includes which precedence fired, plus `risk` and `policy` context, plus `budget` if relevant. `restrictions` propagated from policy.

## Files

- `packages/guardmcp-decision/src/guardmcp_decision/engine.py` — `DecisionEngine.evaluate(context, policy_result, risk_result, budget_result?) → GuardDecision`
- `packages/guardmcp-decision/src/guardmcp_decision/__init__.py` — public API
- `packages/guardmcp-decision/pyproject.toml` — depends on `guardmcp-core, -policy, -risk, -budget`

## Tests

`tests/unit/test_decision.py` — 12 tests: all 8 precedence rules, deny overrides high risk, sandbox/restrict from policy, explainable/deterministic (same inputs → same action, trace_id/request_id, reasons non-empty, serialization), 62 total.

## Bugs fixed in G6

- `mypy` `type-arg` for `dict` → `dict[str, Any]` in `_deny`
- `ruff` E501 line length in `evaluator.py` and test comments, `F841` unused variable
- `pytest` `test_precedence_7_high_risk_restrict`: exec+password gave CRITICAL → DENY, not RESTRICT — changed to exec+path → HIGH → RESTRICT
