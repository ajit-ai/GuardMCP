"""Error categories and severity — domain enums, no infra."""

from __future__ import annotations

from enum import StrEnum


class ErrorCategory(StrEnum):
    """Structured error categories — 13 as per spec."""

    IDENTITY = "IDENTITY"
    AUTHENTICATION = "AUTHENTICATION"
    DELEGATION = "DELEGATION"
    AUTHORIZATION = "AUTHORIZATION"
    POLICY = "POLICY"
    BUDGET = "BUDGET"
    RISK = "RISK"
    SECURITY = "SECURITY"
    INTELLIGENCE = "INTELLIGENCE"
    EXECUTION = "EXECUTION"
    NETWORK = "NETWORK"
    TIMEOUT = "TIMEOUT"
    INTERNAL = "INTERNAL"


class ErrorSeverity(StrEnum):
    """Error severity — for observability and retry decisions."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
