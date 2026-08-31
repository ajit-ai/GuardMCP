"""RiskSignalProvider — extension point for future signals."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from guardmcp_risk.models import RiskSignal


class RiskSignalProvider(Protocol):
    """Provider interface — future RiskSignalProvider extensions.

    Implementations must be deterministic and not depend on ML.
    """

    def provide(self, context: Any) -> list[RiskSignal]:
        """Return signals for the given GuardContext."""
        ...
