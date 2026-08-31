"""G7: Audit events — model, emitter, lifecycle."""

from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime

import pytest
from guardmcp_audit import AuditEvent, AuditEventType, InMemoryEventSink


def _uuid() -> str:
    return str(uuid.uuid4())


def test_audit_event_validation_and_serialization() -> None:
    req_id = _uuid()
    trace_id = _uuid()
    ev = AuditEvent(
        event_id=_uuid(),
        timestamp=datetime.now(UTC),
        request_id=req_id,
        trace_id=trace_id,
        event_type=AuditEventType.REQUEST_RECEIVED,
        metadata={"tool": "test_tool"},
    )
    d = ev.to_dict()
    assert d["event_type"] == "REQUEST_RECEIVED"
    assert datetime.fromisoformat(d["timestamp"]).tzinfo is not None
    back = AuditEvent.from_dict(json.loads(json.dumps(d)))
    assert back == ev
    # factory
    ev2 = AuditEvent.create(
        req_id, trace_id, AuditEventType.DECISION_MADE, metadata={"action": "ALLOW"}
    )
    assert ev2.request_id == req_id
    assert ev2.event_type == AuditEventType.DECISION_MADE

    with pytest.raises(ValueError, match="event_id must be valid UUID"):
        AuditEvent(
            event_id="bad",
            timestamp=datetime.now(UTC),
            request_id=req_id,
            trace_id=trace_id,
            event_type=AuditEventType.REQUEST_RECEIVED,
        )

    # immutability
    with pytest.raises((AttributeError, TypeError)):
        ev.event_type = AuditEventType.TOOL_STARTED  # type: ignore[misc]


def test_all_event_types_exist() -> None:
    expected = {
        "REQUEST_RECEIVED",
        "IDENTITY_RESOLVED",
        "DELEGATION_VALIDATED",
        "POLICY_EVALUATED",
        "RISK_CALCULATED",
        "BUDGET_RESERVED",
        "SECURITY_CHECKED",
        "DECISION_MADE",
        "TOOL_STARTED",
        "TOOL_COMPLETED",
        "TOOL_FAILED",
        "RESULT_INSPECTED",
        "REQUEST_COMPLETED",
    }
    assert {e.value for e in AuditEventType} == expected


def test_in_memory_sink_basic() -> None:
    sink = InMemoryEventSink()
    req_id = _uuid()
    trace_id = _uuid()
    e1 = AuditEvent.create(req_id, trace_id, AuditEventType.REQUEST_RECEIVED)
    e2 = AuditEvent.create(req_id, trace_id, AuditEventType.DECISION_MADE)
    sink.emit(e1)
    sink.emit_many([e2])
    assert sink.count() == 2
    assert len(sink.list_events()) == 2
    assert len(sink.filter_by_request(req_id)) == 2
    assert len(sink.filter_by_type(AuditEventType.DECISION_MADE)) == 1
    assert len(sink.filter_by_trace(trace_id)) == 2
    sink.clear()
    assert sink.count() == 0


def test_lifecycle_emission() -> None:
    # Simulate full lifecycle: 13 events in order
    sink = InMemoryEventSink()
    req_id = _uuid()
    trace_id = _uuid()
    lifecycle = [
        AuditEventType.REQUEST_RECEIVED,
        AuditEventType.IDENTITY_RESOLVED,
        AuditEventType.DELEGATION_VALIDATED,
        AuditEventType.POLICY_EVALUATED,
        AuditEventType.RISK_CALCULATED,
        AuditEventType.BUDGET_RESERVED,
        AuditEventType.SECURITY_CHECKED,
        AuditEventType.DECISION_MADE,
        AuditEventType.TOOL_STARTED,
        AuditEventType.TOOL_COMPLETED,
        AuditEventType.RESULT_INSPECTED,
        AuditEventType.REQUEST_COMPLETED,
    ]
    for et in lifecycle:
        sink.emit(AuditEvent.create(req_id, trace_id, et, metadata={"step": et.value}))
    assert sink.count() == len(lifecycle)
    # order preserved
    events = sink.list_events()
    assert [e.event_type for e in events] == lifecycle
    # filtering
    assert (
        sink.filter_by_type(AuditEventType.POLICY_EVALUATED)[0].metadata["step"]
        == "POLICY_EVALUATED"
    )


def test_concurrency_safe() -> None:
    sink = InMemoryEventSink()
    req_id = _uuid()
    trace_id = _uuid()

    def emit_many() -> None:
        for _ in range(20):
            sink.emit(AuditEvent.create(req_id, trace_id, AuditEventType.TOOL_STARTED))

    threads = [threading.Thread(target=emit_many) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sink.count() == 100


def test_event_metadata_and_duration() -> None:
    req_id = _uuid()
    trace_id = _uuid()
    ev = AuditEvent.create(
        req_id,
        trace_id,
        AuditEventType.TOOL_COMPLETED,
        metadata={"output": "ok"},
        actor="agent_1",
        duration_ms=123,
    )
    assert ev.metadata["output"] == "ok"
    assert ev.actor == "agent_1"
    assert ev.duration_ms == 123
    # serialization with duration
    back = AuditEvent.from_dict(ev.to_dict())
    assert back.duration_ms == 123
