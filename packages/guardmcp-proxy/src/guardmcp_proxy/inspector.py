"""Post-execution controls — classify, inspect, redact, block."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Protocol

from guardmcp_core.context import GuardContext
from guardmcp_core.decision import GuardDecision


class InspectionAction(StrEnum):
    """Post-execution action."""

    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class InspectionResult:
    """Result of post-execution inspection."""

    action: InspectionAction
    original_result: dict[str, Any]
    redacted_result: dict[str, Any] | None = None
    reasons: list[str] = field(default_factory=list)
    blocked_keys: list[str] = field(default_factory=list)

    @property
    def result(self) -> dict[str, Any]:
        """Final result to return — redacted if REDACT, else original."""
        if self.action == InspectionAction.REDACT and self.redacted_result is not None:
            return self.redacted_result
        return self.original_result


class Redactor(Protocol):
    """Extension point — redact sensitive data."""

    def redact(self, data: dict[str, Any]) -> dict[str, Any]: ...


class BasicRedactor:
    """Redacts sensitive keys — replaces values with '***'."""

    SENSITIVE_KEYS: ClassVar[set[str]] = {
        "password",
        "secret",
        "token",
        "credential",
        "key",
        "passwd",
    }

    def redact(self, data: dict[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = {}
        for k, v in data.items():
            if k.lower() in self.SENSITIVE_KEYS:
                redacted[k] = "***"
            elif isinstance(v, dict):
                redacted[k] = self.redact(v)
            elif isinstance(v, str) and any(s in v.lower() for s in self.SENSITIVE_KEYS):
                redacted[k] = "***"
            else:
                redacted[k] = v
        return redacted


class ResultInspector(Protocol):
    """Inspect tool result — classify and decide ALLOW/REDACT/BLOCK."""

    def inspect(
        self, result: dict[str, Any], context: GuardContext, decision: GuardDecision
    ) -> InspectionResult: ...


class BasicResultInspector:
    """Basic classifier — no advanced DLP, just extension points."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        self._redactor = redactor or BasicRedactor()

    def inspect(
        self, result: dict[str, Any], context: GuardContext, decision: GuardDecision
    ) -> InspectionResult:
        # 1. Classify: check for sensitive output
        sensitive_keys = {"password", "secret", "token", "credential", "key", "passwd"}
        found_sensitive: list[str] = []
        for k in result:
            if k.lower() in sensitive_keys:
                found_sensitive.append(k)
        # check values
        for v in result.values():
            if isinstance(v, str) and ("/etc/passwd" in v or "passwd" in v.lower()):
                found_sensitive.append("passwd_value")

        # 2. Check for block — malicious or explicit block
        if any(
            "malicious" in str(v).lower() or "exploit" in str(v).lower() for v in result.values()
        ):
            return InspectionResult(
                action=InspectionAction.BLOCK,
                original_result=result,
                redacted_result=None,
                reasons=["blocked: malicious content detected"],
                blocked_keys=found_sensitive,
            )

        # 3. Check sensitive → REDACT
        if found_sensitive:
            redacted = self._redactor.redact(result)
            return InspectionResult(
                action=InspectionAction.REDACT,
                original_result=result,
                redacted_result=redacted,
                reasons=[f"redacted sensitive keys: {found_sensitive}"],
                blocked_keys=found_sensitive,
            )

        # 4. Check decision restrictions — if decision was RESTRICT, ensure we don't leak
        if decision.action.value in {"RESTRICT", "SANDBOX"} and len(str(result)) > 10000:
            # large data in restricted mode → redact
            return InspectionResult(
                action=InspectionAction.REDACT,
                original_result=result,
                redacted_result={
                    "output": "[redacted: large restricted output]",
                    "original_keys": list(result.keys()),
                },
                reasons=["redacted: large output in restricted mode"],
            )

        # 5. Otherwise ALLOW
        return InspectionResult(
            action=InspectionAction.ALLOW,
            original_result=result,
            reasons=["allow: no sensitive output"],
        )
