"""Claude Code OTLP log records → Anzen records (pure normalization, no server)."""

import json

from anzen.server.normalize import iter_log_records, normalize_log_record
from anzen.store import ActionType


def _record(event: str, attrs: dict, time_ns: int = 1700000000000000000) -> dict:
    def any_value(v):
        if isinstance(v, bool):
            return {"boolValue": v}
        if isinstance(v, int):
            return {"intValue": str(v)}
        if isinstance(v, float):
            return {"doubleValue": v}
        return {"stringValue": str(v)}

    return {
        "timeUnixNano": str(time_ns),
        "attributes": [
            {"key": "event.name", "value": {"stringValue": f"claude_code.{event}"}},
            *({"key": k, "value": any_value(v)} for k, v in attrs.items()),
        ],
    }


_IDENTITY = {
    "session.id": "sess-1",
    "user.email": "dev@co.com",
    "user.id": "u-1",
    "organization.id": "org-1",
    "terminal.type": "vscode",
    "app.version": "2.0.1",
}


def test_tool_result_becomes_tool_call():
    rec = _record("tool_result", {
        **_IDENTITY,
        "tool_name": "Bash",
        "tool_input": json.dumps({"command": "ls -la"}),
        "tool_use_id": "tu-1",
        "prompt.id": "p-1",
        "success": True,
        "duration_ms": 42.0,
        "decision_source": "config",
    })
    n = normalize_log_record(rec, {"service.name": "claude-code"})
    a = n.action
    assert a.action_type is ActionType.tool_call
    assert a.name == "Bash"
    assert "ls -la" in a.input
    assert a.tool_use_id == "tu-1" and a.prompt_id == "p-1"
    assert a.status == "ok"
    assert a.duration_ms == 42.0
    assert a.decision_source == "config"
    assert a.span_id == "tool_result:tu-1"  # natural id → idempotent re-delivery
    assert n.session.id == "sess-1"
    assert n.session.user_email == "dev@co.com"
    assert n.endpoint.agent_type == "claude-code"
    assert n.endpoint.user_email == "dev@co.com"


def test_tool_result_failure_is_error_status():
    rec = _record("tool_result", {**_IDENTITY, "tool_name": "Bash", "success": False})
    assert normalize_log_record(rec, {}).action.status == "error"


def test_tool_decision_yields_decision_not_action():
    rec = _record("tool_decision", {
        **_IDENTITY, "tool_name": "Bash", "tool_use_id": "tu-1",
        "decision": "accept", "source": "config",
    })
    n = normalize_log_record(rec, {})
    assert n.action is None
    assert n.decision.tool_use_id == "tu-1"
    assert n.decision.decision == "accept"
    assert n.decision.source == "config"


def test_user_prompt_and_api_request():
    prompt = normalize_log_record(
        _record("user_prompt", {**_IDENTITY, "prompt": "fix the bug", "prompt.id": "p-1"}), {}
    )
    assert prompt.action.action_type is ActionType.prompt
    assert prompt.action.input == "fix the bug"

    api = normalize_log_record(
        _record("api_request", {
            **_IDENTITY, "model": "claude-opus-4-8", "cost_usd": 0.12,
            "input_tokens": 900, "output_tokens": 120, "request_id": "req-1",
        }), {}
    )
    assert api.action.action_type is ActionType.llm_call
    assert api.action.name == "claude-opus-4-8"
    assert api.session.input_tokens == 900 and api.session.output_tokens == 120
    assert api.session.cost_usd == 0.12
    assert api.action.span_id == "api_request:req-1"


def test_permission_mode_changed_updates_posture():
    n = normalize_log_record(
        _record("permission_mode_changed", {**_IDENTITY, "from_mode": "default",
                                            "to_mode": "bypassPermissions"}), {}
    )
    assert n.session.permission_mode == "bypassPermissions"
    assert n.endpoint.permission_mode_latest == "bypassPermissions"
    assert n.action.action_type is ActionType.system_event


def test_mcp_connection_and_plugin_feed_inventory():
    mcp = normalize_log_record(
        _record("mcp_server_connection", {
            **_IDENTITY, "server_name": "github", "transport_type": "stdio",
            "server_scope": "project", "status": "connected",
        }), {}
    )
    [item] = mcp.inventory
    assert (item.kind, item.name, item.transport) == ("mcp_server", "github", "stdio")
    assert item.user_emails == ["dev@co.com"]

    plugin = normalize_log_record(
        _record("plugin_loaded", {
            **_IDENTITY, "plugin.name": "linter", "plugin.version": "1.2.0",
            "marketplace.name": "official",
        }), {}
    )
    [item] = plugin.inventory
    assert (item.kind, item.name, item.version) == ("plugin", "linter", "1.2.0")


def test_record_without_identity_creates_no_endpoint():
    """A bare tool_decision must not create a phantom endpoint keyed on empty strings."""
    n = normalize_log_record(
        _record("tool_decision", {"session.id": "sess-1", "tool_use_id": "tu-1",
                                  "decision": "accept", "source": "config"}), {}
    )
    assert n.endpoint is None


def test_unknown_event_preserved_as_system_event():
    n = normalize_log_record(_record("some_future_event", _IDENTITY), {})
    assert n.action.action_type is ActionType.system_event
    assert n.action.name == "some_future_event"
    assert n.action.raw_attributes["event"] == "some_future_event"


def test_iter_log_records_walks_resource_batches():
    payload = {
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "claude-code"}},
            ]},
            "scopeLogs": [{"logRecords": [
                _record("user_prompt", _IDENTITY),
                _record("tool_result", {**_IDENTITY, "tool_name": "Read"}),
            ]}],
        }]
    }
    pairs = list(iter_log_records(payload))
    assert len(pairs) == 2
    assert all(res["service.name"] == "claude-code" for _, res in pairs)
