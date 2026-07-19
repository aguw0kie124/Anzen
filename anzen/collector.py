"""OTLP/HTTP trace receiver and OpenInference span normalization.

Accepts `POST /v1/traces` in both OTLP encodings (protobuf and JSON) on a
plain-stdlib HTTP server, and normalizes **OpenInference** spans — the
OpenTelemetry-based convention that AI agent frameworks (LangChain,
LlamaIndex, CrewAI, the OpenAI/Anthropic SDK instrumentations) actually emit
— into anzen Actions. Anything unrecognized is preserved as an `unknown`
action with its full raw attributes; nothing is dropped.

Ingestion is deliberately just: receive → normalize → store. Compliance
scanning is a separate, manual step (`anzen scan`).
"""

from __future__ import annotations

import base64
import binascii
import json
import string
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from typing import Any

from .store import Action, ActionType, Session, Store

NANOS = 1e9

# openinference.span.kind → anzen action type
_KIND_MAP = {
    "TOOL": ActionType.tool_call,
    "LLM": ActionType.llm_call,
    "AGENT": ActionType.agent_invoke,
}

_HEX = set(string.hexdigits)


def _decode_id(value: str) -> str:
    """Return a span/trace id as lowercase hex.

    OTLP/JSON sends ids hex-encoded; the protobuf→dict path yields base64.
    """
    if not value:
        return ""
    if len(value) in (16, 32) and all(c in _HEX for c in value):
        return value.lower()
    try:
        return base64.b64decode(value).hex()
    except (binascii.Error, ValueError):
        return value


def _flatten_value(value: dict[str, Any] | None) -> Any:
    """Collapse an OTLP AnyValue into a plain Python value."""
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])
    if "doubleValue" in value:
        return value["doubleValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "bytesValue" in value:
        return value["bytesValue"]
    if "arrayValue" in value:
        return [_flatten_value(v) for v in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return _attrs_to_dict(value["kvlistValue"].get("values", []))
    return value


def _attrs_to_dict(attributes: list[dict[str, Any]]) -> dict[str, Any]:
    return {a["key"]: _flatten_value(a.get("value")) for a in attributes if "key" in a}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str)


def normalize_span(
    span: dict[str, Any], resource_attrs: dict[str, Any]
) -> tuple[Session, Action]:
    """Map one OpenInference OTLP span dict to a (session delta, action) pair."""
    attrs = _attrs_to_dict(span.get("attributes", []))
    trace_id = _decode_id(span.get("traceId", ""))

    session_id = str(
        resource_attrs.get("session.id")
        or attrs.get("session.id")
        or trace_id
        or "unknown-session"
    )
    agent_name = str(resource_attrs.get("service.name") or "unknown-agent")

    start = float(span.get("startTimeUnixNano", 0)) / NANOS or time.time()
    end = float(span.get("endTimeUnixNano", 0)) / NANOS or start

    kind = str(attrs.get("openinference.span.kind", "")).upper()
    action_type = _KIND_MAP.get(kind, ActionType.unknown)

    input_ = _as_text(attrs.get("input.value"))
    output = _as_text(attrs.get("output.value"))
    name = str(span.get("name", ""))
    input_tokens = 0
    output_tokens = 0

    if action_type == ActionType.tool_call:
        name = str(attrs.get("tool.name") or name)
        input_ = _as_text(attrs.get("tool.parameters")) or input_
    elif action_type == ActionType.llm_call:
        name = str(attrs.get("llm.model_name") or name)
        input_ = input_ or _as_text(attrs.get("llm.input_messages"))
        output = output or _as_text(attrs.get("llm.output_messages"))
        input_tokens = int(attrs.get("llm.token_count.prompt", 0) or 0)
        output_tokens = int(attrs.get("llm.token_count.completion", 0) or 0)

    status_code = (span.get("status") or {}).get("code", 0)
    status = "error" if status_code in (2, "STATUS_CODE_ERROR") else "ok"

    session = Session(
        id=session_id,
        agent_name=agent_name,
        started_at=start,
        ended_at=end,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    action = Action(
        session_id=session_id,
        span_id=_decode_id(span.get("spanId", "")) or f"{trace_id}:{name}:{start}",
        timestamp=start,
        action_type=action_type,
        name=name,
        input=input_,
        output=output,
        status=status,
        raw_attributes={"span": span, "resource": resource_attrs},
    )
    return session, action


def ingest_payload(store: Store, payload: dict[str, Any]) -> set[str]:
    """Normalize and persist one ExportTraceServiceRequest dict. Returns touched session ids."""
    touched: set[str] = set()
    for resource_spans in payload.get("resourceSpans", []):
        resource_attrs = _attrs_to_dict(
            (resource_spans.get("resource") or {}).get("attributes", [])
        )
        for scope_spans in resource_spans.get("scopeSpans", []):
            for span in scope_spans.get("spans", []):
                session, action = normalize_span(span, resource_attrs)
                # session row must exist before the action (FK), but token
                # totals should only accrue on the first delivery of a span.
                token_delta = (session.input_tokens, session.output_tokens)
                session.input_tokens = session.output_tokens = 0
                store.upsert_session(session)
                inserted = store.insert_action(action)
                if inserted is not None and token_delta != (0, 0):
                    session.input_tokens, session.output_tokens = token_delta
                    store.upsert_session(session)
                touched.add(session.id)
    return touched


def decode_body(body: bytes, content_type: str) -> dict[str, Any]:
    """Decode an OTLP request body (JSON or protobuf) into a plain dict."""
    if "json" in content_type:
        return json.loads(body)
    message = ExportTraceServiceRequest()
    message.ParseFromString(body)
    return MessageToDict(message)


class _CollectorHandler(BaseHTTPRequestHandler):
    """One POST endpoint (/v1/traces) + a health check. Injected: `store`."""

    store: Store  # set by make_server

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if self.path != "/v1/traces":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            payload = decode_body(body, self.headers.get("Content-Type", ""))
            ingest_payload(self.store, payload)
        except Exception as exc:  # malformed payloads must not kill the server
            self.send_error(400, explain=str(exc))
            return
        # OTLP/HTTP success: empty ExportTraceServiceResponse
        data = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path != "/healthz":
            self.send_error(404)
            return
        data = b'{"status": "ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # keep the console quiet; the CLI prints what matters


def make_server(store: Store, host: str = "127.0.0.1", port: int = 4318) -> ThreadingHTTPServer:
    """Build the collector server (call `.serve_forever()` to run it)."""
    handler = type("CollectorHandler", (_CollectorHandler,), {"store": store})
    return ThreadingHTTPServer((host, port), handler)
