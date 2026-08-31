"""guardmcp-proxy — MCP interception, context, decision pipeline, routing, audit."""

from __future__ import annotations

from guardmcp_proxy.context_builder import ContextBuilder
from guardmcp_proxy.pipeline import DecisionPipeline
from guardmcp_proxy.proxy import GuardMCPProxy
from guardmcp_proxy.router import MCPRouter

__version__ = "0.1.0"

__all__ = ["ContextBuilder", "DecisionPipeline", "GuardMCPProxy", "MCPRouter", "__version__"]
