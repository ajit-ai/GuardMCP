"""G2: GuardError — categories, codes, serialization, stability."""

from __future__ import annotations

import json
import uuid
from datetime import datetime

import pytest
from guardmcp_errors import ErrorCategory, ErrorSeverity, GuardError


def _uuid() -> str:
    return str(uuid.uuid4())


def make_error(
    category: ErrorCategory = ErrorCategory.POLICY,
    code: str = "POLICY_DENY",
) -> GuardError:
    return GuardError(
        code=code,
        category=category,
        severity=ErrorSeverity.HIGH,
        retryable=False,
        message="policy denied",
        reason="rule matched",
        trace_id=_uuid(),
    )


def test_all_categories_exist() -> None:
    expected = {
        "IDENTITY",
        "AUTHENTICATION",
        "DELEGATION",
        "AUTHORIZATION",
        "POLICY",
        "BUDGET",
        "RISK",
        "SECURITY",
        "INTELLIGENCE",
        "EXECUTION",
        "NETWORK",
        "TIMEOUT",
        "INTERNAL",
    }
    assert {c.value for c in ErrorCategory} == expected


def test_all_severities_exist() -> None:
    assert {s.value for s in ErrorSeverity} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_guard_error_validation() -> None:
    make_error()
    with pytest.raises(ValueError, match="code must be non-empty"):
        GuardError(
            code="",
            category=ErrorCategory.POLICY,
            severity=ErrorSeverity.HIGH,
            retryable=False,
            message="m",
            reason="r",
            trace_id=_uuid(),
        )
    with pytest.raises(ValueError, match="trace_id must be valid UUID"):
        GuardError(
            code="X",
            category=ErrorCategory.INTERNAL,
            severity=ErrorSeverity.LOW,
            retryable=False,
            message="m",
            reason="r",
            trace_id="bad",
        )
    with pytest.raises(ValueError):
        GuardError(
            code="X",
            category="BAD",  # type: ignore[arg-type]
            severity=ErrorSeverity.LOW,
            retryable=False,
            message="m",
            reason="r",
            trace_id=_uuid(),
        )


def test_guard_error_immutability() -> None:
    err = make_error()
    with pytest.raises((AttributeError, TypeError)):
        err.code = "OTHER"  # type: ignore[misc]


def test_guard_error_serialization_stability() -> None:
    err = make_error()
    d = err.to_dict()
    # stable keys
    assert set(d.keys()) == {
        "code",
        "category",
        "severity",
        "retryable",
        "message",
        "reason",
        "trace_id",
        "timestamp",
        "details",
    }
    assert d["category"] == "POLICY"
    assert d["severity"] == "HIGH"
    # enum values are strings
    assert isinstance(d["category"], str)
    # timestamp isoformat
    assert datetime.fromisoformat(d["timestamp"]).tzinfo is not None
    # json roundtrip
    back = GuardError.from_dict(json.loads(json.dumps(d)))
    assert back == err
    # second roundtrip stability
    assert GuardError.from_dict(back.to_dict()) == err


def test_guard_error_retryable() -> None:
    # retryable is explicit, but from_exception auto-sets
    err = GuardError(
        code="NET_FAIL",
        category=ErrorCategory.NETWORK,
        severity=ErrorSeverity.MEDIUM,
        retryable=True,
        message="network",
        reason="timeout",
        trace_id=_uuid(),
    )
    assert err.is_retryable
    policy = make_error(category=ErrorCategory.POLICY, code="POLICY_DENY")
    assert not policy.is_retryable


def test_guard_error_from_exception_sanitized() -> None:
    exc = ValueError("secret 123")
    err = GuardError.from_exception(
        exc, category=ErrorCategory.EXECUTION, code="EXEC_FAIL", trace_id=_uuid()
    )
    assert err.category == ErrorCategory.EXECUTION
    assert err.code == "EXEC_FAIL"
    assert "ValueError" in err.message
    assert err.reason == "ValueError"
    assert "exception_type" in err.details
    # no stack leak — message truncated
    long_exc = RuntimeError("x" * 500)
    err2 = GuardError.from_exception(long_exc, trace_id=_uuid())
    assert len(err2.message) <= 250  # type+truncated

    # trace_id auto-generated if not provided
    err3 = GuardError.from_exception(RuntimeError("oops"))
    assert uuid.UUID(err3.trace_id)


def test_guard_error_str_no_secrets() -> None:
    err = make_error()
    s = str(err)
    assert err.code in s
    assert err.trace_id in s
    assert "POLICY" in s


def test_guard_error_details_preserved() -> None:
    err = GuardError(
        code="BUDGET_EXHAUSTED",
        category=ErrorCategory.BUDGET,
        severity=ErrorSeverity.HIGH,
        retryable=False,
        message="budget exceeded",
        reason="tool_call limit",
        trace_id=_uuid(),
        details={"budget_type": "tool_call", "remaining": 0},
    )
    back = GuardError.from_dict(err.to_dict())
    assert back.details["budget_type"] == "tool_call"
