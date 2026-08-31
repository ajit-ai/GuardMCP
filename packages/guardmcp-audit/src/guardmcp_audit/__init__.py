"""guardmcp-audit — domain events, emitter abstraction, in-memory sink."""

from __future__ import annotations

from guardmcp_audit.emitter import EventEmitter
from guardmcp_audit.event import AuditEvent
from guardmcp_audit.memory import InMemoryEventSink
from guardmcp_audit.types import AuditEventType

__version__ = "0.1.0"

__all__ = ["AuditEvent", "AuditEventType", "EventEmitter", "InMemoryEventSink", "__version__"]
