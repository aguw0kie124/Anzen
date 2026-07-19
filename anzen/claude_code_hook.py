"""Claude Code → Anzen bridge (PostToolUse hook).

Claude Code runs this after every tool call, passing a JSON event on stdin
(session_id, tool_name, tool_input, tool_response, cwd, ...). We convert the
event into one OpenInference-convention OTLP/JSON span and POST it to a
running `anzen serve` collector.

Design constraints (this fires on *every* tool call of a live session):
- **stdlib only** — no anzen/pydantic/opentelemetry imports; fast to start.
- **fail-safe** — any error (collector down, bad JSON, timeout) is swallowed
  and we exit 0, so Claude Code is never blocked or slowed meaningfully.

Invoked as: python3 -m anzen.claude_code_hook
Endpoint override: ANZEN_ENDPOINT (default http://127.0.0.1:4318)
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.request

DEFAULT_ENDPOINT = "http://127.0.0.1:4318"
TIMEOUT_SECONDS = 1.5
MAX_FIELD_BYTES = 20_000


def _clip(text: str) -> str:
    return text if len(text) <= MAX_FIELD_BYTES else text[:MAX_FIELD_BYTES] + "…[truncated]"


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def build_payload(event: dict) -> dict:
    """Turn one PostToolUse event into an OpenInference OTLP/JSON payload."""
    session_id = str(event.get("session_id") or "claude-code-unknown")
    tool_name = str(event.get("tool_name") or "unknown_tool")
    tool_input = _clip(_as_text(event.get("tool_input")))
    tool_response = _clip(_as_text(event.get("tool_response")))

    now_nanos = int(time.time() * 1e9)

    def attr(key: str, value: str) -> dict:
        return {"key": key, "value": {"stringValue": value}}

    span = {
        "name": tool_name,
        "traceId": secrets.token_hex(16),
        "spanId": secrets.token_hex(8),
        "startTimeUnixNano": str(now_nanos),
        "endTimeUnixNano": str(now_nanos),
        "attributes": [
            attr("openinference.span.kind", "TOOL"),
            attr("tool.name", tool_name),
            attr("tool.parameters", tool_input),
            attr("input.value", tool_input),
            attr("output.value", tool_response),
        ],
    }
    resource_attrs = [
        attr("service.name", "claude-code"),
        attr("session.id", session_id),
    ]
    cwd = event.get("cwd")
    if cwd:
        resource_attrs.append(attr("claude_code.cwd", str(cwd)))

    return {
        "resourceSpans": [{
            "resource": {"attributes": resource_attrs},
            "scopeSpans": [{
                "scope": {"name": "anzen.claude_code_hook"},
                "spans": [span],
            }],
        }]
    }


def send(payload: dict, endpoint: str) -> None:
    request = urllib.request.Request(
        f"{endpoint}/v1/traces",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS):
        pass


def main() -> int:
    try:
        event = json.load(sys.stdin)
        if event.get("hook_event_name") not in (None, "PostToolUse"):
            return 0  # wired to an unexpected event; capture nothing
        payload = build_payload(event)
        endpoint = os.environ.get("ANZEN_ENDPOINT", DEFAULT_ENDPOINT).rstrip("/")
        send(payload, endpoint)
    except Exception:
        pass  # never disturb Claude Code — no output, no failure
    return 0


if __name__ == "__main__":
    sys.exit(main())
