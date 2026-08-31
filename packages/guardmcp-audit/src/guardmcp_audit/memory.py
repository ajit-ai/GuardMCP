"""InMemoryEventSink — thread-safe, for dev/tests."""

from __future__ import annotations

import threading

from guardmcp_audit.event import AuditEvent
from guardmcp_audit.types import AuditEventType


class InMemoryEventSink:
    """In-memory sink — satisfies EventEmitter, stores ordered events."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def emit_many(self, events: list[AuditEvent]) -> None:
        with self._lock:
            self._events.extend(events)

    def list_events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)

    def filter_by_request(self, request_id: str) -> list[AuditEvent]:
        with self._lock:
            return [e for e in self._events if e.request_id == request_id]

    def filter_by_type(self, event_type: AuditEventType) -> list[AuditEvent]:
        with self._lock:
            return [e for e in self._events if e.event_type == event_type]

    def filter_by_trace(self, trace_id: str) -> list[AuditEvent]:
        with self._lock:
            return [e for e in self._events if e.trace_id == trace_id]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def count(self) -> int:
        with self._lock:
            return len(self._events)
