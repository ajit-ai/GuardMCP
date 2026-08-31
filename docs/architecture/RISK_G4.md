# G4 — Risk Engine

## Architecture

```
RiskSignal (7 categories) → RiskFactor (weighted) → RiskScore (total→level) → RiskResult (explainable)
                ↑ Provider (Protocol) → RiskEvaluator → reasons
```

Deterministic, no ML. Providers are optional extensions.

## RiskSignal

`signal_id (UUID), category (7), score 0-100, confidence 0-1, description, indicators, timestamp`

Categories: `IdentityRisk, DelegationRisk, AgentRisk, ToolRisk, ArgumentRisk, ResourceRisk, SecurityRisk`

## RiskFactor

`factor_id, name, category, weight 0-1, signals, score` — avg per category.

## RiskScore

`total_score, level (LOW/MODERATE/ELEVATED/HIGH/CRITICAL), factors` — validates `level == _score_to_level(total_score)` with thresholds `0-20 LOW, 21-40 MODERATE, 41-60 ELEVATED, 61-80 HIGH, 81-100 CRITICAL`.

## RiskResult

`request_id, trace_id, score, level, signals, factors, reasons, evaluated_at` — validates `level==score.level`, `reasons non-empty`.

## RiskEvaluator

`evaluate(context: GuardContext, extra_signals, providers) → RiskResult`

Generates 7 deterministic signals from context:

- Identity: unauthenticated 80, service 40, human 10
- Delegation: expired 100, long chain 60, wildcard 70, valid 15
- Agent: autonomous 60, model unknown 50, known 20
- Tool: sensitive 80, read 30, other 25
- Argument: sensitive keys 90, /etc/passwd 70, no args 10
- Resource: /etc/prod 60, database 50, low 15
- Security: threat level mapping CRITICAL 95…LOW 10, signals present 50

Aggregates per-category avg → factor, total = `max(factor.score)` (single high dominates), explains via `reasons: ["Total risk X → LEVEL", "Category: description (score)"]`.

Providers: `RiskSignalProvider.provide(context) → list[RiskSignal]` — try/except, failure adds 30-score signal, never corrupts core.

## Files

- `packages/guardmcp-risk/src/guardmcp_risk/models.py` — Signal/Factor/Score/Result
- `packages/guardmcp-risk/src/guardmcp_risk/provider.py` — Protocol
- `packages/guardmcp-risk/src/guardmcp_risk/evaluator.py` — evaluator
- `packages/guardmcp-risk/src/guardmcp_risk/__init__.py` — public API
- `packages/guardmcp-risk/pyproject.toml` — depends on `guardmcp-core`

## Tests

`tests/unit/test_risk.py` — 8 tests: signal validation, score level mapping, deterministic/explainable, levels trigger (unauth→HIGH, expired→CRITICAL, exec+password+critical→CRITICAL), provider extension, failure isolation, extra signals, result validation, factor serialization.

## Bugs fixed in G4

- `ruff` TC001 (move imports to TYPE_CHECKING), E501 line length in test comment.
- `mypy` no-any-return for `actual in expected` — fixed via `bool()` wrap.
- Scoring: `avg` diluted single high signal → changed to `max` for explainable HIGH/CRITICAL.
