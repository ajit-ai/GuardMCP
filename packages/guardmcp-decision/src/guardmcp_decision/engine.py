"""DecisionEngine — final authority, explicit precedence, explainable."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from guardmcp_core.context import GuardContext
from guardmcp_core.decision import GuardDecision
from guardmcp_core.types import GuardDecisionAction, RiskLevel
from guardmcp_policy.models import PolicyResult
from guardmcp_risk.models import RiskResult

try:
    from guardmcp_budget.models import BudgetResult
except ImportError:  # budget not yet installed in some envs
    BudgetResult = Any  # type: ignore[misc,assignment]


class DecisionEngine:
    """Central orchestration — 8-step precedence, deterministic."""

    def evaluate(
        self,
        context: GuardContext,
        policy_result: PolicyResult,
        risk_result: RiskResult,
        budget_result: BudgetResult | None = None,
    ) -> GuardDecision:
        request_id = context.request.request_id
        trace_id = context.trace.trace_id
        now = datetime.now(UTC)

        # 1. Invalid identity → DENY
        if not context.identity.principal_id or not context.identity.principal_id.strip():
            return self._deny(
                request_id,
                trace_id,
                "invalid identity: missing principal_id",
                risk_result,
                policy_result,
                now,
            )
        if not context.identity.authenticated:
            return self._deny(
                request_id,
                trace_id,
                "invalid identity: unauthenticated",
                risk_result,
                policy_result,
                now,
            )

        # 2. Invalid delegation → DENY
        if context.delegation.is_expired():
            return self._deny(
                request_id, trace_id, "invalid delegation: expired", risk_result, policy_result, now
            )

        # 3. Explicit policy deny → DENY
        if policy_result.action == GuardDecisionAction.DENY:
            return self._deny(
                request_id,
                trace_id,
                f"policy deny: {policy_result.matched_policy_id}/{policy_result.matched_rule_id}",
                risk_result,
                policy_result,
                now,
                extra_reasons=policy_result.reasons,
                restrictions=policy_result.restrictions,
            )

        # 4. Critical confirmed security threat → DENY
        if context.security.threat_level == RiskLevel.CRITICAL:
            return self._deny(
                request_id,
                trace_id,
                "critical security threat: security.threat_level=CRITICAL",
                risk_result,
                policy_result,
                now,
            )
        if risk_result.level == RiskLevel.CRITICAL:
            return self._deny(
                request_id,
                trace_id,
                f"critical risk: total {risk_result.score.total_score} → CRITICAL",
                risk_result,
                policy_result,
                now,
            )

        # 5. Budget exhausted → DENY or RESTRICT
        if budget_result is not None and not budget_result.success:
            # if policy already says RESTRICT, respect it
            if policy_result.action == GuardDecisionAction.RESTRICT:
                return self._restrict(
                    request_id,
                    trace_id,
                    f"budget exhausted: {budget_result.reason}",
                    risk_result,
                    policy_result,
                    now,
                    budget_result,
                )
            return self._deny(
                request_id,
                trace_id,
                f"budget exhausted: {budget_result.reason}",
                risk_result,
                policy_result,
                now,
                budget_result=budget_result,
            )

        # 6. Explicit approval requirement → APPROVAL_REQUIRED
        if policy_result.action == GuardDecisionAction.APPROVAL_REQUIRED:
            return GuardDecision(
                request_id=request_id,
                trace_id=trace_id,
                action=GuardDecisionAction.APPROVAL_REQUIRED,
                reasons=[
                    f"approval required: policy {policy_result.matched_policy_id}",
                    *policy_result.reasons,
                ],
                risk_level=risk_result.level,
                policy_id=policy_result.matched_policy_id,
                restrictions=dict(policy_result.restrictions),
                evaluated_at=now,
            )

        # Handle SANDBOX and RESTRICT from policy (if no higher DENY)
        if policy_result.action == GuardDecisionAction.SANDBOX:
            return GuardDecision(
                request_id=request_id,
                trace_id=trace_id,
                action=GuardDecisionAction.SANDBOX,
                reasons=[
                    f"policy sandbox: {policy_result.matched_policy_id}",
                    *policy_result.reasons,
                ],
                risk_level=risk_result.level,
                policy_id=policy_result.matched_policy_id,
                restrictions=dict(policy_result.restrictions),
                evaluated_at=now,
            )
        if policy_result.action == GuardDecisionAction.RESTRICT:
            return GuardDecision(
                request_id=request_id,
                trace_id=trace_id,
                action=GuardDecisionAction.RESTRICT,
                reasons=[
                    f"policy restrict: {policy_result.matched_policy_id}",
                    *policy_result.reasons,
                ],
                risk_level=risk_result.level,
                policy_id=policy_result.matched_policy_id,
                restrictions=dict(policy_result.restrictions),
                evaluated_at=now,
            )

        # 7. High risk → RESTRICT or APPROVAL_REQUIRED according to policy
        if risk_result.level == RiskLevel.HIGH:
            return self._restrict(
                request_id,
                trace_id,
                f"high risk: {risk_result.score.total_score} → HIGH",
                risk_result,
                policy_result,
                now,
            )
        if risk_result.level == RiskLevel.ELEVATED:
            # treat elevated as restrict as well for safety
            return self._restrict(
                request_id,
                trace_id,
                f"elevated risk: {risk_result.score.total_score} → ELEVATED",
                risk_result,
                policy_result,
                now,
            )

        # 8. Otherwise → ALLOW
        return GuardDecision(
            request_id=request_id,
            trace_id=trace_id,
            action=GuardDecisionAction.ALLOW,
            reasons=[
                "allow: no blocking conditions",
                f"risk {risk_result.level.value}",
                f"policy {policy_result.action.value}",
            ],
            risk_level=risk_result.level,
            policy_id=policy_result.matched_policy_id,
            restrictions={},
            evaluated_at=now,
        )

    def _deny(
        self,
        request_id: str,
        trace_id: str,
        reason: str,
        risk_result: RiskResult,
        policy_result: PolicyResult,
        now: datetime,
        extra_reasons: list[str] | None = None,
        restrictions: dict[str, Any] | None = None,
        budget_result: Any | None = None,
    ) -> GuardDecision:
        reasons = [
            reason,
            f"risk {risk_result.level.value}",
            f"policy {policy_result.action.value}",
        ]
        if extra_reasons:
            reasons.extend(extra_reasons)
        if budget_result is not None and not getattr(budget_result, "success", True):
            reasons.append(f"budget {getattr(budget_result, 'reason', '')}")
        return GuardDecision(
            request_id=request_id,
            trace_id=trace_id,
            action=GuardDecisionAction.DENY,
            reasons=reasons,
            risk_level=risk_result.level,
            policy_id=policy_result.matched_policy_id,
            restrictions=dict(restrictions or {}),
            evaluated_at=now,
        )

    def _restrict(
        self,
        request_id: str,
        trace_id: str,
        reason: str,
        risk_result: RiskResult,
        policy_result: PolicyResult,
        now: datetime,
        budget_result: Any | None = None,
    ) -> GuardDecision:
        reasons = [
            reason,
            f"risk {risk_result.level.value}",
            f"policy {policy_result.action.value}",
        ]
        if budget_result is not None:
            reasons.append(f"budget {getattr(budget_result, 'reason', '')}")
        restrictions = dict(policy_result.restrictions) or {"mode": "restricted"}
        return GuardDecision(
            request_id=request_id,
            trace_id=trace_id,
            action=GuardDecisionAction.RESTRICT,
            reasons=reasons,
            risk_level=risk_result.level,
            policy_id=policy_result.matched_policy_id,
            restrictions=restrictions,
            evaluated_at=now,
        )
