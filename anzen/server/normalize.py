"""Claude Code native telemetry → Anzen records.

Claude Code (and Cowork) export their activity as OpenTelemetry **log
records** — one record per event (`tool_result`, `tool_decision`,
`user_prompt`, `mcp_server_connection`, ...), with the event's fields as
record attributes and identity (`session.id`, `user.email`,
`organization.id`, ...) on the record and/or resource. See
https://code.claude.com/docs/en/monitoring-usage for the schema.

`normalize_log_record` maps one record to a `Normalized` bundle:
session delta, endpoint sighting, optional action, inventory items, and an
optional permission decision to merge onto an earlier tool action.
Unrecognized events are preserved as `system_event` actions with their full
raw attributes — nothing is dropped.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from pydantic import BaseModel, Field

from ..store import Action, ActionType, Endpoint, InventoryItem, Session

NANOS = 1e9

# Known event names (with or without a "claude_code." prefix).
_PREFIX = "claude_code."


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
        return attrs_to_dict(value["kvlistValue"].get("values", []))
    return value


def attrs_to_dict(attributes: list[dict[str, Any]]) -> dict[str, Any]:
    return {a["key"]: _flatten_value(a.get("value")) for a in attributes if "key" in a}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str)


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class Decision(BaseModel):
    """A `tool_decision` event, to be merged onto its tool action by tool_use_id."""

    session_id: str
    tool_use_id: str
    decision: str
    source: str


class Normalized(BaseModel):
    """Everything one log record contributes to the store."""

    session: Session
    endpoint: Endpoint | None = None
    action: Action | None = None
    inventory: list[InventoryItem] = Field(default_factory=list)
    decision: Decision | None = None


def _event_name(record: dict[str, Any], attrs: dict[str, Any]) -> str:
    name = (
        record.get("eventName")
        or attrs.get("event.name")
        or attrs.get("event_name")
        or _as_text(_flatten_value(record.get("body")))
    )
    name = str(name)
    return name[len(_PREFIX):] if name.startswith(_PREFIX) else name


def _span_id(event: str, session_id: str, timestamp: float, attrs: dict[str, Any]) -> str:
    """Deterministic id so re-delivered records stay idempotent (UNIQUE(session_id, span_id))."""
    natural = attrs.get("tool_use_id") or attrs.get("request_id")
    if natural:
        return f"{event}:{natural}"
    digest = hashlib.sha1(
        json.dumps([event, session_id, timestamp, attrs], sort_keys=True, default=str).encode()
    ).hexdigest()[:16]
    return f"{event}:{digest}"


def normalize_log_record(
    record: dict[str, Any], resource_attrs: dict[str, Any]
) -> Normalized:
    attrs = {**resource_attrs, **attrs_to_dict(record.get("attributes", []))}
    event = _event_name(record, attrs)
    timestamp = (
        _as_float(record.get("timeUnixNano") or record.get("observedTimeUnixNano")) / NANOS
        or time.time()
    )

    session_id = str(attrs.get("session.id") or "unknown-session")
    agent_name = str(resource_attrs.get("service.name") or "claude-code")

    session = Session(
        id=session_id,
        agent_name=agent_name,
        started_at=timestamp,
        ended_at=timestamp,
        user_email=_as_text(attrs.get("user.email")),
        user_id=_as_text(attrs.get("user.id")),
        org_id=_as_text(attrs.get("organization.id")),
        hostname=_as_text(attrs.get("host.name")),
        terminal_type=_as_text(attrs.get("terminal.type")),
        app_version=_as_text(attrs.get("app.version")),
        department=_as_text(attrs.get("department")),
    )
    # An endpoint is only meaningful with identity to key on; records that
    # carry none (e.g. a bare tool_decision) would otherwise create a phantom
    # row keyed on empty strings.
    endpoint = None
    if session.user_email or session.hostname:
        endpoint = Endpoint(
            agent_type=agent_name,
            user_email=session.user_email,
            hostname=session.hostname,
            app_version=session.app_version,
            terminal_type=session.terminal_type,
            first_seen=timestamp,
            last_seen=timestamp,
        )

    def action(
        action_type: ActionType,
        name: str,
        input_: str = "",
        output: str = "",
        status: str = "ok",
    ) -> Action:
        return Action(
            session_id=session_id,
            span_id=_span_id(event, session_id, timestamp, attrs),
            timestamp=timestamp,
            action_type=action_type,
            name=name,
            input=input_,
            output=output,
            status=status,
            prompt_id=_as_text(attrs.get("prompt.id")),
            tool_use_id=_as_text(attrs.get("tool_use_id")),
            cost_usd=_as_float(attrs.get("cost_usd")),
            duration_ms=_as_float(attrs.get("duration_ms")),
            raw_attributes={"event": event, "attributes": attrs},
        )

    result = Normalized(session=session, endpoint=endpoint)

    if event == "user_prompt":
        result.action = action(ActionType.prompt, "user_prompt", input_=_as_text(attrs.get("prompt")))

    elif event == "assistant_response":
        result.action = action(
            ActionType.response, _as_text(attrs.get("model")) or "assistant_response",
            output=_as_text(attrs.get("response")),
        )

    elif event == "tool_result":
        success = attrs.get("success")
        failed = success in (False, "false", "False")
        result.action = action(
            ActionType.tool_call,
            _as_text(attrs.get("tool_name")) or "unknown_tool",
            input_=_as_text(attrs.get("tool_input")) or _as_text(attrs.get("tool_parameters")),
            status="error" if failed else "ok",
        )
        result.action.decision_source = _as_text(attrs.get("decision_source"))

    elif event == "tool_decision":
        result.decision = Decision(
            session_id=session_id,
            tool_use_id=_as_text(attrs.get("tool_use_id")),
            decision=_as_text(attrs.get("decision")),
            source=_as_text(attrs.get("source")),
        )

    elif event in ("api_request", "api_error"):
        session.input_tokens = _as_int(attrs.get("input_tokens"))
        session.output_tokens = _as_int(attrs.get("output_tokens"))
        session.cost_usd = _as_float(attrs.get("cost_usd"))
        result.action = action(
            ActionType.llm_call,
            _as_text(attrs.get("model")) or event,
            status="error" if event == "api_error" else "ok",
        )

    elif event == "permission_mode_changed":
        mode = _as_text(attrs.get("to_mode"))
        session.permission_mode = mode
        if endpoint is not None:
            endpoint.permission_mode_latest = mode
        result.action = action(
            ActionType.system_event, "permission_mode_changed",
            input_=_as_text(attrs.get("from_mode")), output=mode,
        )

    elif event == "mcp_server_connection":
        result.inventory.append(InventoryItem(
            kind="mcp_server",
            name=_as_text(attrs.get("server_name")) or "unknown-mcp-server",
            scope=_as_text(attrs.get("server_scope")),
            transport=_as_text(attrs.get("transport_type")),
            status=_as_text(attrs.get("status")),
            first_seen=timestamp,
            last_seen=timestamp,
            user_emails=[session.user_email] if session.user_email else [],
        ))
        result.action = action(
            ActionType.system_event, "mcp_server_connection",
            output=_as_text(attrs.get("status")),
        )

    elif event in ("plugin_loaded", "plugin_installed"):
        result.inventory.append(InventoryItem(
            kind="plugin",
            name=_as_text(attrs.get("plugin.name")) or "unknown-plugin",
            scope=_as_text(attrs.get("plugin.scope")),
            version=_as_text(attrs.get("plugin.version")),
            marketplace=_as_text(attrs.get("marketplace.name")),
            status="installed" if event == "plugin_installed" else "loaded",
            first_seen=timestamp,
            last_seen=timestamp,
            user_emails=[session.user_email] if session.user_email else [],
        ))

    elif event == "skill_activated":
        result.inventory.append(InventoryItem(
            kind="skill",
            name=_as_text(attrs.get("skill.name")) or "unknown-skill",
            scope=_as_text(attrs.get("skill.source")),
            marketplace=_as_text(attrs.get("marketplace.name")),
            status="activated",
            first_seen=timestamp,
            last_seen=timestamp,
            user_emails=[session.user_email] if session.user_email else [],
        ))

    elif event == "hook_registered":
        result.inventory.append(InventoryItem(
            kind="hook",
            name=_as_text(attrs.get("hook_name"))
            or f"{_as_text(attrs.get('hook_event'))}:{_as_text(attrs.get('hook_source'))}",
            scope=_as_text(attrs.get("hook_source")),
            status="registered",
            first_seen=timestamp,
            last_seen=timestamp,
            user_emails=[session.user_email] if session.user_email else [],
        ))

    else:
        # unrecognized event — preserved verbatim, never dropped
        result.action = action(ActionType.system_event, event or "unknown_event")

    return result


def iter_log_records(payload: dict[str, Any]):
    """Yield (record, resource_attrs) pairs from an ExportLogsServiceRequest dict."""
    for resource_logs in payload.get("resourceLogs", []):
        resource_attrs = attrs_to_dict(
            (resource_logs.get("resource") or {}).get("attributes", [])
        )
        for scope_logs in resource_logs.get("scopeLogs", []):
            for record in scope_logs.get("logRecords", []):
                yield record, resource_attrs
