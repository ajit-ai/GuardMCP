"""RiskEvaluator — deterministic, explainable, no ML."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from guardmcp_core.types import RiskLevel

from guardmcp_risk.models import (
    RiskFactor,
    RiskResult,
    RiskScore,
    RiskSignal,
    RiskSignalCategory,
    _score_to_level,
)

if TYPE_CHECKING:
    from guardmcp_risk.provider import RiskSignalProvider


def _new_signal(
    category: RiskSignalCategory,
    score: float,
    description: str,
    indicators: list[str] | None = None,
    confidence: float = 0.9,
) -> RiskSignal:
    return RiskSignal(
        signal_id=str(uuid.uuid4()),
        category=category,
        score=score,
        confidence=confidence,
        description=description,
        indicators=indicators or [],
    )


class RiskEvaluator:
    """Deterministic risk engine — 7 categories, weighted scoring, explanations.

    No ML. Providers are optional extensions.
    """

    def evaluate(
        self,
        context: Any,
        extra_signals: list[RiskSignal] | None = None,
        providers: list[RiskSignalProvider] | None = None,
    ) -> RiskResult:
        request_id = context.request.request_id
        trace_id = context.trace.trace_id
        signals: list[RiskSignal] = []

        # 1. IdentityRisk
        if not context.identity.authenticated:
            signals.append(
                _new_signal(
                    RiskSignalCategory.IDENTITY_RISK,
                    80,
                    "Unauthenticated principal",
                    [context.identity.principal_id],
                )
            )
        elif context.identity.principal_type.value == "service":
            signals.append(
                _new_signal(
                    RiskSignalCategory.IDENTITY_RISK,
                    40,
                    "Service principal",
                    [context.identity.principal_id],
                )
            )
        else:
            signals.append(
                _new_signal(
                    RiskSignalCategory.IDENTITY_RISK,
                    10,
                    "Authenticated human principal",
                    confidence=0.95,
                )
            )

        # 2. DelegationRisk
        if context.delegation.is_expired():
            signals.append(
                _new_signal(
                    RiskSignalCategory.DELEGATION_RISK,
                    100,
                    "Delegation expired",
                    [context.delegation.delegator],
                )
            )
        elif len(context.delegation.delegation_chain) > 3:
            signals.append(
                _new_signal(
                    RiskSignalCategory.DELEGATION_RISK,
                    60,
                    "Long delegation chain",
                    [str(len(context.delegation.delegation_chain))],
                )
            )
        elif "*" in context.delegation.scope:
            signals.append(
                _new_signal(
                    RiskSignalCategory.DELEGATION_RISK,
                    70,
                    "Wildcard delegation scope",
                    context.delegation.scope,
                )
            )
        else:
            signals.append(
                _new_signal(
                    RiskSignalCategory.DELEGATION_RISK, 15, "Valid delegation", confidence=0.9
                )
            )

        # 3. AgentRisk
        if context.agent.agent_type.value == "autonomous":
            signals.append(
                _new_signal(
                    RiskSignalCategory.AGENT_RISK, 60, "Autonomous agent", [context.agent.agent_id]
                )
            )
        elif not context.agent.model:
            signals.append(
                _new_signal(
                    RiskSignalCategory.AGENT_RISK,
                    50,
                    "Agent model unknown",
                    [context.agent.agent_id],
                )
            )
        else:
            signals.append(
                _new_signal(
                    RiskSignalCategory.AGENT_RISK, 20, "Known assistant agent", confidence=0.85
                )
            )

        # 4. ToolRisk
        sensitive_tools = {"exec", "file_write", "network", "admin", "delete"}
        tname = context.tool.tool_name.lower()
        if tname in sensitive_tools or context.tool.category.lower() == "sensitive":
            signals.append(
                _new_signal(RiskSignalCategory.TOOL_RISK, 80, f"Sensitive tool: {tname}", [tname])
            )
        elif "read" in tname:
            signals.append(
                _new_signal(
                    RiskSignalCategory.TOOL_RISK, 30, f"Read-only tool: {tname}", confidence=0.8
                )
            )
        else:
            signals.append(
                _new_signal(RiskSignalCategory.TOOL_RISK, 25, f"Tool: {tname}", confidence=0.7)
            )

        # 5. ArgumentRisk
        args = context.request.arguments or {}
        arg_keys = set(args.keys())
        sensitive_keys = {"password", "secret", "key", "token", "credential"}
        if arg_keys & sensitive_keys:
            signals.append(
                _new_signal(
                    RiskSignalCategory.ARGUMENT_RISK,
                    90,
                    "Sensitive argument keys",
                    list(arg_keys & sensitive_keys),
                )
            )
        elif any("/etc" in str(v) or "passwd" in str(v).lower() for v in args.values()):
            signals.append(
                _new_signal(
                    RiskSignalCategory.ARGUMENT_RISK,
                    70,
                    "Suspicious argument value",
                    [str(v) for v in args.values()][:2],
                )
            )
        elif not args:
            signals.append(
                _new_signal(RiskSignalCategory.ARGUMENT_RISK, 10, "No arguments", confidence=0.9)
            )
        else:
            signals.append(
                _new_signal(
                    RiskSignalCategory.ARGUMENT_RISK, 20, "Normal arguments", confidence=0.75
                )
            )

        # 6. ResourceRisk
        uri = context.resource.uri or ""
        rtype = context.resource.resource_type.lower()
        if "/etc" in uri or "prod" in uri.lower():
            signals.append(
                _new_signal(
                    RiskSignalCategory.RESOURCE_RISK, 60, f"Sensitive resource uri: {uri}", [uri]
                )
            )
        elif rtype == "database":
            signals.append(
                _new_signal(RiskSignalCategory.RESOURCE_RISK, 50, "Database resource", [rtype])
            )
        else:
            signals.append(
                _new_signal(
                    RiskSignalCategory.RESOURCE_RISK, 15, "Low risk resource", confidence=0.8
                )
            )

        # 7. SecurityRisk
        threat = context.security.threat_level
        if threat == RiskLevel.CRITICAL:
            signals.append(
                _new_signal(
                    RiskSignalCategory.SECURITY_RISK, 95, "Critical threat level", [threat.value]
                )
            )
        elif threat == RiskLevel.HIGH:
            signals.append(
                _new_signal(
                    RiskSignalCategory.SECURITY_RISK, 70, "High threat level", [threat.value]
                )
            )
        elif threat == RiskLevel.ELEVATED:
            signals.append(
                _new_signal(RiskSignalCategory.SECURITY_RISK, 45, "Elevated threat", [threat.value])
            )
        elif threat == RiskLevel.MODERATE:
            signals.append(
                _new_signal(RiskSignalCategory.SECURITY_RISK, 30, "Moderate threat", [threat.value])
            )
        else:
            signals.append(
                _new_signal(RiskSignalCategory.SECURITY_RISK, 10, "Low threat", confidence=0.9)
            )
        if context.security.signals:
            signals.append(
                _new_signal(
                    RiskSignalCategory.SECURITY_RISK,
                    50,
                    "Security signals present",
                    context.security.signals,
                )
            )

        # extra signals + providers
        if extra_signals:
            signals.extend(extra_signals)
        if providers:
            for p in providers:
                try:
                    signals.extend(p.provide(context))
                except Exception:
                    # provider failure must not corrupt core — log and continue
                    signals.append(
                        _new_signal(
                            RiskSignalCategory.SECURITY_RISK,
                            30,
                            f"Provider {type(p).__name__} failed",
                            confidence=0.5,
                        )
                    )

        # aggregate into factors (one per category)
        factors: list[RiskFactor] = []
        reasons: list[str] = []
        category_scores: dict[RiskSignalCategory, list[float]] = {c: [] for c in RiskSignalCategory}
        for s in signals:
            category_scores[s.category].append(s.score)

        for cat, scores in category_scores.items():
            if not scores:
                continue
            avg = sum(scores) / len(scores)
            factor = RiskFactor(
                factor_id=str(uuid.uuid4()),
                name=cat.value,
                category=cat,
                weight=1.0,
                signals=[s for s in signals if s.category == cat],
                score=round(avg, 2),
            )
            factors.append(factor)
            # explanation
            top = max([s for s in signals if s.category == cat], key=lambda x: x.score)
            reasons.append(f"{cat.value}: {top.description} (score {top.score})")

        # total score — max factor (single high signal dominates, explainable)
        total = round(max(f.score for f in factors), 2) if factors else 0.0
        level = _score_to_level(total)
        reasons.insert(
            0,
            f"Total risk {total} → {level.value} ({len(signals)} signals, {len(factors)} factors)",
        )

        score = RiskScore(total_score=total, level=level, factors=factors)

        return RiskResult(
            request_id=request_id,
            trace_id=trace_id,
            score=score,
            level=level,
            signals=signals,
            factors=factors,
            reasons=reasons,
            evaluated_at=datetime.now(UTC),
        )
