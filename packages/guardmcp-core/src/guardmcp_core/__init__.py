"""GuardMCP Core - placeholder for G0 foundation.

Domain models (GuardContext, GuardRequest, etc.) will be implemented in G1.
This module intentionally exposes only the package version to keep G0 minimal and dependency-free.

Architecture: Domain layer must not depend on FastAPI, PostgreSQL,
Redis, MCP transport, or OpenTelemetry.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
