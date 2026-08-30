"""guardmcp-errors — structured error protocol, no infra dependencies."""

from __future__ import annotations

from guardmcp_errors.error import GuardError
from guardmcp_errors.types import ErrorCategory, ErrorSeverity

__version__ = "0.1.0"

__all__ = ["ErrorCategory", "ErrorSeverity", "GuardError", "__version__"]
