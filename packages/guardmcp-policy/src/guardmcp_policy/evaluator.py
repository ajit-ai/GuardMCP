"""PolicyEvaluator — evaluates GuardContext against policies."""

from __future__ import annotations

from typing import Any

from guardmcp_core.types import GuardDecisionAction

from guardmcp_policy.models import Policy, PolicyResult


class PolicyEvaluator:
    """Stateless evaluator — no infra dependencies.

    Precedence: highest priority policy first, within policy highest priority rule first.
    First matching rule wins. If no match, returns ALLOW (default secure? — G6 will handle DENY).
    """

    def evaluate(self, context: Any, policies: list[Policy]) -> PolicyResult:
        enabled = [p for p in policies if p.enabled]
        # sort by priority desc, then by id for determinism
        enabled.sort(key=lambda p: (-p.priority, p.id))
        evaluated = 0

        for policy in enabled:
            # rules sorted by priority desc
            rules = sorted(policy.rules, key=lambda r: (-r.priority, r.id))
            for rule in rules:
                evaluated += 1
                if rule.matches(context):
                    desc = rule.description or rule.action.value
                    reasons = [f"policy '{policy.name}' rule '{rule.id}' matched: {desc}"]
                    # include condition details
                    if rule.conditions:
                        conds = [f"{c.field}:{c.operator.value}" for c in rule.conditions]
                        reasons.append(f"conditions: {conds}")
                    return PolicyResult(
                        action=rule.action,
                        matched_policy_id=policy.id,
                        matched_rule_id=rule.id,
                        reasons=reasons,
                        restrictions=dict(rule.restrictions),
                        evaluated_policies=evaluated,
                    )

        # no match — default ALLOW (G6 will apply secure defaults)
        return PolicyResult(
            action=GuardDecisionAction.ALLOW,
            matched_policy_id=None,
            matched_rule_id=None,
            reasons=["no policy matched — default ALLOW"],
            restrictions={},
            evaluated_policies=evaluated,
        )
