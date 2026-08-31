"""MCP Router — forwards allowed requests to backend MCP server."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Backend handler type: (tool_name, arguments) -> dict result
BackendHandler = Callable[[str, dict[str, Any]], dict[str, Any]]


class MCPRouter:
    """Routes to backend — pluggable, no domain pollution."""

    def __init__(self, backend: BackendHandler | None = None) -> None:
        self._backend = backend or self._echo_backend

    @staticmethod
    def _echo_backend(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Default mock backend — echoes tool call."""
        return {
            "tool": tool_name,
            "arguments": arguments,
            "output": f"executed {tool_name}",
            "status": "ok",
        }

    def route(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._backend(tool_name, arguments)
