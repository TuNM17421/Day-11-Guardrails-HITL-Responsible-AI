"""
Production Defense-in-Depth pipeline helpers for Assignment 11.

This module adds the missing production-oriented layers required by the
assignment:
1. Rate limiting (per-user sliding window)
2. Audit logging (input, output, layer blocked, latency)
3. Monitoring and alerts (block rate, rate-limit hits, judge fail rate)

These components are framework-agnostic in design, but the rate limiter and
logger are implemented as ADK plugins so they can be attached directly to the
protected banking agent used elsewhere in the project.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

from google.genai import types
from google.adk.plugins import base_plugin

from guardrails.input_guardrails import InputGuardrailPlugin
from guardrails.output_guardrails import OutputGuardrailPlugin


def _extract_text(content: types.Content | None) -> str:
    """Extract plain text from a Google GenAI content object."""
    text = ""
    if content and getattr(content, "parts", None):
        for part in content.parts:
            if hasattr(part, "text") and part.text:
                text += part.text
    return text


def _make_message(text: str) -> types.Content:
    """Create a model response content object from plain text."""
    return types.Content(role="model", parts=[types.Part.from_text(text=text)])


class AuditLogPlugin(base_plugin.BasePlugin):
    """Audit logger for every user interaction.

    Why it is needed:
    - Security teams need a trail of what the user asked, what the system
      returned, which layer blocked it, and how long the request took.
    - This catches monitoring and compliance gaps that simple filtering does not.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs: list[dict] = []

    def _new_entry(self, user_id: str, input_text: str) -> dict:
        """Create a new audit entry for an incoming request."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "input_text": input_text,
            "output_text": "",
            "blocked": False,
            "blocked_layer": None,
            "latency_ms": None,
            "_start": time.perf_counter(),
        }

    def record_block(self, user_id: str, input_text: str, blocked_layer: str, output_text: str):
        """Record an early block from the rate limiter or input guardrails."""
        if self.logs and self.logs[-1].get("input_text") == input_text and not self.logs[-1].get("output_text"):
            entry = self.logs[-1]
        else:
            entry = self._new_entry(user_id, input_text)
            self.logs.append(entry)

        entry["blocked"] = True
        entry["blocked_layer"] = blocked_layer
        entry["output_text"] = output_text
        entry["latency_ms"] = round((time.perf_counter() - entry["_start"]) * 1000, 2)

    def mark_last_entry(self, *, blocked: bool | None = None, blocked_layer: str | None = None, output_text: str | None = None):
        """Update the most recent log entry with final response metadata."""
        if not self.logs:
            return
        entry = self.logs[-1]
        if blocked is not None:
            entry["blocked"] = blocked
        if blocked_layer is not None:
            entry["blocked_layer"] = blocked_layer
        if output_text is not None:
            entry["output_text"] = output_text

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Record the input and request start time. This never blocks."""
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        input_text = _extract_text(user_message)
        self.logs.append(self._new_entry(user_id, input_text))
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        """Record the model output and latency. This never modifies the response."""
        if not self.logs:
            return llm_response

        entry = self.logs[-1]
        output_text = ""
        if hasattr(llm_response, "content"):
            output_text = _extract_text(llm_response.content)

        entry["output_text"] = output_text
        entry["latency_ms"] = round((time.perf_counter() - entry["_start"]) * 1000, 2)
        return llm_response

    def export_json(self, filepath: str = "security_audit.json") -> str:
        """Export the audit log to a JSON file for the assignment deliverable."""
        clean_logs = []
        for entry in self.logs:
            clean_entry = {k: v for k, v in entry.items() if k != "_start"}
            clean_logs.append(clean_entry)

        path = Path(filepath)
        with path.open("w", encoding="utf-8") as f:
            json.dump(clean_logs, f, indent=2, ensure_ascii=False)
        return str(path)


class RateLimitPlugin(base_plugin.BasePlugin):
    """Sliding-window rate limiter.

    Why it is needed:
    - This blocks abusive bursts of requests from the same user.
    - It catches denial-of-service and brute-force style probing that content
      filters alone would miss.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60, audit_logger: AuditLogPlugin | None = None):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.audit_logger = audit_logger
        self.user_windows: dict[str, deque[float]] = defaultdict(deque)
        self.total_count = 0
        self.blocked_count = 0

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Block users who exceed the allowed request rate in a time window."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        input_text = _extract_text(user_message)
        now = time.time()
        window = self.user_windows[user_id]

        while window and (now - window[0]) > self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait_time = max(1, int(self.window_seconds - (now - window[0])))
            message = (
                f"Rate limit exceeded for user '{user_id}'. "
                f"Please wait about {wait_time} seconds before trying again."
            )
            if self.audit_logger is not None:
                self.audit_logger.record_block(
                    user_id=user_id,
                    input_text=input_text,
                    blocked_layer="rate_limiter",
                    output_text=message,
                )
            return _make_message(message)

        window.append(now)
        return None


class MonitoringAlert:
    """Simple monitoring dashboard for the defense layers.

    Why it is needed:
    - A secure system needs metrics and alerts, not just rules.
    - This helps detect spikes in attacks, judge failures, or abuse patterns.
    """

    def __init__(
        self,
        rate_limiter: RateLimitPlugin,
        input_guard: InputGuardrailPlugin,
        output_guard: OutputGuardrailPlugin,
        audit_log: AuditLogPlugin,
        block_rate_threshold: float = 0.40,
        judge_fail_threshold: float = 0.20,
    ):
        self.rate_limiter = rate_limiter
        self.input_guard = input_guard
        self.output_guard = output_guard
        self.audit_log = audit_log
        self.block_rate_threshold = block_rate_threshold
        self.judge_fail_threshold = judge_fail_threshold

    def metrics(self) -> dict:
        """Compute current security metrics across the pipeline."""
        total_requests = max(self.input_guard.total_count, self.rate_limiter.total_count, len(self.audit_log.logs), 1)
        total_blocks = self.rate_limiter.blocked_count + self.input_guard.blocked_count + self.output_guard.blocked_count
        judge_fail_rate = self.output_guard.judge_fail_count / max(self.output_guard.total_count, 1)

        return {
            "total_requests": total_requests,
            "total_blocks": total_blocks,
            "block_rate": total_blocks / total_requests,
            "rate_limit_hits": self.rate_limiter.blocked_count,
            "judge_fail_rate": judge_fail_rate,
            "redactions": self.output_guard.redacted_count,
            "audit_events": len(self.audit_log.logs),
        }

    def check_metrics(self) -> dict:
        """Return metrics plus alert messages when thresholds are exceeded."""
        metrics = self.metrics()
        alerts = []

        if metrics["block_rate"] >= self.block_rate_threshold:
            alerts.append("High overall block rate detected.")
        if metrics["rate_limit_hits"] > 0:
            alerts.append("Rate-limit hits observed from at least one user.")
        if metrics["judge_fail_rate"] >= self.judge_fail_threshold:
            alerts.append("LLM judge fail rate exceeded threshold.")

        metrics["alerts"] = alerts
        return metrics


def build_production_plugins(use_llm_judge: bool = True, max_requests: int = 10, window_seconds: int = 60):
    """Build the full production defense stack for the protected agent.

    Returns:
        Tuple of (plugins, monitor, audit_log)
    """
    audit_log = AuditLogPlugin()
    rate_limiter = RateLimitPlugin(
        max_requests=max_requests,
        window_seconds=window_seconds,
        audit_logger=audit_log,
    )
    input_guard = InputGuardrailPlugin(audit_logger=audit_log)
    output_guard = OutputGuardrailPlugin(
        use_llm_judge=use_llm_judge,
        audit_logger=audit_log,
    )
    monitor = MonitoringAlert(rate_limiter, input_guard, output_guard, audit_log)

    plugins = [audit_log, rate_limiter, input_guard, output_guard]
    return plugins, monitor, audit_log
