"""Decision pipeline — Policy → Risk → Budget → Decision."""

from __future__ import annotations

from typing import Any

from guardmcp_budget import BudgetService
from guardmcp_core.context import GuardContext
from guardmcp_core.decision import GuardDecision
from guardmcp_policy import Policy, PolicyEvaluator
from guardmcp_risk import RiskEvaluator


class DecisionPipeline:
    """Composable pipeline — each stage has clear interface, no massive function."""

    def __init__(
        self,
        policy_evaluator: PolicyEvaluator | None = None,
        risk_evaluator: RiskEvaluator | None = None,
        budget_service: BudgetService | None = None,
        policies: list[Policy] | None = None,
    ) -> None:
        self._policy_eval = policy_evaluator or PolicyEvaluator()
        self._risk_eval = risk_evaluator or RiskEvaluator()
        self._budget_svc = budget_service
        self._policies: list[Policy] = policies or []

    def set_policies(self, policies: list[Policy]) -> None:
        self._policies = policies

    def evaluate(self, context: GuardContext) -> tuple[GuardDecision, dict[str, Any]]:
        """Run pipeline, return decision + intermediate results for audit."""
        # Policy
        policy_result = self._policy_eval.evaluate(context, self._policies)
        # Risk
        risk_result = self._risk_eval.evaluate(context)
        # Budget — check TOOL_CALL for owner
        budget_result = None
        if self._budget_svc is not None:
            # find budget for owner, or create on-the-fly with default limit 100
            budgets = self._budget_svc._provider.list_budgets(
                owner_id=context.identity.principal_id
            )
            # use first matching TOOL_CALL budget if exists
            budget = next((b for b in budgets if b.budget_type.value == "tool_call"), None)
            if budget is not None:
                budget_result = self._budget_svc.check(budget.budget_id, amount=1)

        from guardmcp_decision import DecisionEngine

        engine = DecisionEngine()
        decision = engine.evaluate(context, policy_result, risk_result, budget_result)

        intermediates: dict[str, Any] = {
            "policy_result": policy_result,
            "risk_result": risk_result,
            "budget_result": budget_result,
        }
        return decision, intermediates
