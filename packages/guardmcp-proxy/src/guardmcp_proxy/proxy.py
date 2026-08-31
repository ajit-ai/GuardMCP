"""GuardMCP Proxy — intercepts, decides, enforces, audits."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from guardmcp_audit import AuditEventType, InMemoryEventSink
from guardmcp_audit.event import AuditEvent
from guardmcp_core.types import GuardDecisionAction

from guardmcp_proxy.context_builder import ContextBuilder
from guardmcp_proxy.pipeline import DecisionPipeline
from guardmcp_proxy.router import MCPRouter


class GuardMCPProxy:
    """MCP Client → Proxy → Context → Decision Pipeline → Router → MCP Server

    Responsibilities:
      1. Intercept MCP request
      2. Construct GuardContext
      3. Evaluate decision pipeline
      4. Enforce GuardDecision
      5. Execute permitted request
      6. Inspect result (basic)
      7. Emit audit events
      8. Return response
    """

    def __init__(
        self,
        pipeline: DecisionPipeline | None = None,
        router: MCPRouter | None = None,
        sink: InMemoryEventSink | None = None,
        context_builder: ContextBuilder | None = None,
    ) -> None:
        self._pipeline = pipeline or DecisionPipeline()
        self._router = router or MCPRouter()
        self._sink = sink or InMemoryEventSink()
        self._builder = context_builder or ContextBuilder()

    @property
    def sink(self) -> InMemoryEventSink:
        return self._sink

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle a single MCP request — returns guard-aware response."""
        start = datetime.now(UTC)
        # 1. Intercept — validate
        tool_name = request.get("tool_name") or request.get("tool")
        if not tool_name:
            return self._error_response(request, "missing tool_name", GuardDecisionAction.DENY)

        # 2. Construct GuardContext
        context = self._builder.build(request)
        self._emit(context, AuditEventType.REQUEST_RECEIVED, {"tool": tool_name})
        self._emit(
            context, AuditEventType.IDENTITY_RESOLVED, {"principal": context.identity.principal_id}
        )
        self._emit(
            context,
            AuditEventType.DELEGATION_VALIDATED,
            {"delegator": context.delegation.delegator},
        )

        # 3. Decision pipeline
        decision, intermediates = self._pipeline.evaluate(context)
        policy_result = intermediates["policy_result"]
        risk_result = intermediates["risk_result"]
        budget_result = intermediates.get("budget_result")

        self._emit(context, AuditEventType.POLICY_EVALUATED, {"action": policy_result.action.value})
        self._emit(
            context,
            AuditEventType.RISK_CALCULATED,
            {"level": risk_result.level.value, "score": risk_result.score.total_score},
        )
        if budget_result is not None:
            self._emit(context, AuditEventType.BUDGET_RESERVED, {"success": budget_result.success})
        self._emit(
            context,
            AuditEventType.SECURITY_CHECKED,
            {"threat": context.security.threat_level.value},
        )
        self._emit(
            context,
            AuditEventType.DECISION_MADE,
            {"action": decision.action.value, "reasons": decision.reasons},
        )

        # 4. Enforce
        if decision.action == GuardDecisionAction.DENY:
            self._emit(context, AuditEventType.TOOL_FAILED, {"reason": "denied"})
            self._emit(
                context,
                AuditEventType.REQUEST_COMPLETED,
                {"status": "denied"},
                duration_ms=self._elapsed(start),
            )
            return self._decision_response(decision, context, allowed=False)

        if decision.action == GuardDecisionAction.APPROVAL_REQUIRED:
            self._emit(
                context,
                AuditEventType.REQUEST_COMPLETED,
                {"status": "approval_required"},
                duration_ms=self._elapsed(start),
            )
            return self._decision_response(
                decision, context, allowed=False, status="approval_required"
            )

        if decision.action in {GuardDecisionAction.RESTRICT, GuardDecisionAction.SANDBOX}:
            # proceed but with restrictions
            self._emit(
                context, AuditEventType.TOOL_STARTED, {"tool": tool_name, "restricted": True}
            )
            try:
                result = self._router.route(tool_name, context.request.arguments)
                # 6. Inspect — basic redaction if needed
                if decision.restrictions:
                    result = {**result, "_restrictions": decision.restrictions}
                self._emit(context, AuditEventType.TOOL_COMPLETED, {"tool": tool_name})
                self._emit(context, AuditEventType.RESULT_INSPECTED, {"restricted": True})
                self._emit(
                    context,
                    AuditEventType.REQUEST_COMPLETED,
                    {"status": "completed_restricted"},
                    duration_ms=self._elapsed(start),
                )
                return self._decision_response(decision, context, allowed=True, result=result)
            except Exception as exc:
                self._emit(context, AuditEventType.TOOL_FAILED, {"error": str(exc)})
                self._emit(
                    context,
                    AuditEventType.REQUEST_COMPLETED,
                    {"status": "failed"},
                    duration_ms=self._elapsed(start),
                )
                return self._decision_response(decision, context, allowed=False, error=str(exc))

        # ALLOW
        self._emit(context, AuditEventType.TOOL_STARTED, {"tool": tool_name})
        try:
            result = self._router.route(tool_name, context.request.arguments)
            self._emit(context, AuditEventType.TOOL_COMPLETED, {"tool": tool_name})
            self._emit(context, AuditEventType.RESULT_INSPECTED, {})
            self._emit(
                context,
                AuditEventType.REQUEST_COMPLETED,
                {"status": "completed"},
                duration_ms=self._elapsed(start),
            )
            return self._decision_response(decision, context, allowed=True, result=result)
        except Exception as exc:
            self._emit(context, AuditEventType.TOOL_FAILED, {"error": str(exc)})
            self._emit(
                context,
                AuditEventType.REQUEST_COMPLETED,
                {"status": "failed"},
                duration_ms=self._elapsed(start),
            )
            return self._decision_response(decision, context, allowed=False, error=str(exc))

    def _emit(
        self,
        context: Any,
        event_type: AuditEventType,
        metadata: dict[str, Any] | None = None,
        duration_ms: int | None = None,
    ) -> None:
        self._sink.emit(
            AuditEvent.create(
                request_id=context.request.request_id,
                trace_id=context.trace.trace_id,
                event_type=event_type,
                metadata=metadata or {},
                duration_ms=duration_ms,
            )
        )

    def _elapsed(self, start: datetime) -> int:
        return int((datetime.now(UTC) - start).total_seconds() * 1000)

    def _decision_response(
        self,
        decision: Any,
        context: Any,
        allowed: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        base: dict[str, Any] = {
            "request_id": context.request.request_id,
            "trace_id": context.trace.trace_id,
            "allowed": allowed,
            "action": decision.action.value,
            "reasons": decision.reasons,
            "status": status or ("allowed" if allowed else "denied"),
        }
        if result is not None:
            base["result"] = result
        if error is not None:
            base["error"] = error
        if decision.restrictions:
            base["restrictions"] = decision.restrictions
        return base

    def _error_response(
        self, request: dict[str, Any], message: str, action: GuardDecisionAction
    ) -> dict[str, Any]:
        return {
            "request_id": str(request.get("request_id") or uuid.uuid4()),
            "trace_id": str(request.get("trace_id") or uuid.uuid4()),
            "allowed": False,
            "action": action.value,
            "reasons": [message],
            "status": "error",
            "error": message,
        }
