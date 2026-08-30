# G3 — Policy Engine

## Architecture

```
Policy → Rule → Condition → PolicyEvaluator → PolicyResult
         ↓         ↓              ↓
       action   operator      reasons
```

Inputs: `identity, agent, tool, resource, environment, arguments` from `GuardContext` (no MCP transport).

## Condition

`field: str, operator: ConditionOperator, value: Any`

Operators: `EQUALS, NOT_EQUALS, IN, NOT_IN, CONTAINS, NOT_CONTAINS, REGEX, EXISTS, NOT_EXISTS, GT, LT`

Field path: `identity.principal_type`, `tool.tool_name`, `arguments.<key>`, `environment.environment`, etc. Resolved via `_get_field()` with `StrEnum` unwrapping.

Validated: non-empty field, correct operator/value combo (e.g., EXISTS needs None value).

## Rule

`id, action: GuardDecisionAction, conditions: list[Condition], operator: RuleOperator.AND/OR, priority, restrictions`

`matches(context)` → `all` (AND) or `any` (OR) of conditions. Empty conditions = always matches.

## Policy

`id, name, rules: list[Rule], enabled, priority, description`

Sorted by `priority desc` for evaluation.

## PolicyResult

`action, matched_policy_id, matched_rule_id, reasons, restrictions, evaluated_policies` — explainable.

## PolicyEvaluator

Stateless, no infra. Sorts enabled policies by `priority desc, id`, then rules by `priority desc, id`, first matching rule wins, otherwise `ALLOW` (G6 will apply secure defaults). Returns `PolicyResult` with `reasons=["policy 'X' rule 'Y' matched: ...", "conditions: [...]"]` and `restrictions` from rule.

## Files

- `packages/guardmcp-policy/src/guardmcp_policy/models.py` — Condition/Rule/Policy/Result
- `packages/guardmcp-policy/src/guardmcp_policy/evaluator.py` — PolicyEvaluator
- `packages/guardmcp-policy/src/guardmcp_policy/__init__.py` — public API
- `packages/guardmcp-policy/pyproject.toml` — depends on `guardmcp-core`

## Tests

`tests/unit/test_policy.py` — 9 tests: operators, all input types, AND/OR, all 5 actions, precedence, disabled, no-match default, empty conditions, serialization, restrictions.

## Bugs fixed in G3

- `mypy` Strict `no-any-return` for `actual in expected` — wrapped in `bool()` and fixed `type:ignore`.
- `ruff` SIM102/SIM105 (combine if, suppress) and E501 line length in `evaluator.py` and `models.py`.
- `Condition` IN/NOT_IN validation now correctly checks `list/tuple/set`.
