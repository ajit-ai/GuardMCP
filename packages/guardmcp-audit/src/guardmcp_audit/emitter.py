"""EventEmitter — abstraction for audit sink."""

from __future__ import annotations

from typing import Protocol

from guardmcp_audit.event import AuditEvent


class EventEmitter(Protocol):
    """Abstract emitter — future Kafka/PG adapters."""

    def emit(self, event: AuditEvent) -> None:
        """Emit an audit event — must not raise for business logic."""
        ...

    def emit_many(self, events: list[AuditEvent]) -> None:
        """Emit batch — default loops emit."""
        ...
