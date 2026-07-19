"""Claude Code hook: payload shape, pipeline integration, install/uninstall."""

import json

from anzen.claude_code_hook import build_payload
from anzen.collector import ingest_payload, normalize_span
from anzen.rules import load_rules, scan_actions
from anzen.store import ActionType, Store


def _event(tool_name, tool_input, tool_response, session="cc-sess-1"):
    return {
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "cwd": "/Users/dev/project",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_response": tool_response,
    }


def _first_span(payload):
    rs = payload["resourceSpans"][0]
    return rs["scopeSpans"][0]["spans"][0], rs["resource"]["attributes"]


def test_payload_is_openinference_shaped():
    payload = build_payload(_event("Bash", {"command": "ls -la"}, "total 42"))
    span, resource = _first_span(payload)
    attrs = {a["key"]: a["value"]["stringValue"] for a in span["attributes"]}
    res = {a["key"]: a["value"]["stringValue"] for a in resource}
    assert attrs["openinference.span.kind"] == "TOOL"
    assert attrs["tool.name"] == "Bash"
    assert json.loads(attrs["tool.parameters"]) == {"command": "ls -la"}
    assert attrs["output.value"] == "total 42"
    assert res["service.name"] == "claude-code"
    assert res["session.id"] == "cc-sess-1"
    assert len(span["traceId"]) == 32 and len(span["spanId"]) == 16


def test_payload_normalizes_to_tool_action():
    payload = build_payload(_event("Read", {"file_path": "/app/.env"}, "SECRET=1"))
    span, resource = _first_span(payload)
    resource_attrs = {a["key"]: a["value"]["stringValue"] for a in resource}
    session, action = normalize_span(span, resource_attrs)
    assert session.id == "cc-sess-1"
    assert session.agent_name == "claude-code"
    assert action.action_type is ActionType.tool_call
    assert action.name == "Read"
    assert "/app/.env" in action.input
    assert action.output == "SECRET=1"


def test_hook_events_trigger_expected_rules():
    rules = load_rules()
    cases = {
        "SEC-002": _event("Read", {"file_path": "/app/.env"}, "DATABASE_URL=postgres://x"),
        "DST-001": _event("Bash", {"command": "rm -rf /tmp/build"}, "ok"),
        "SEC-001": _event("Bash", {"command": "env"}, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
    }
    for expected_rule, event in cases.items():
        payload = build_payload(event)
        span, resource = _first_span(payload)
        resource_attrs = {a["key"]: a["value"]["stringValue"] for a in resource}
        _, action = normalize_span(span, resource_attrs)
        action.id = 1
        fired = {f.rule_id for f in scan_actions([action], rules)}
        assert expected_rule in fired, f"{expected_rule} did not fire; got {fired}"


def test_payload_ingests_via_store(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    payload = build_payload(_event("Bash", {"command": "echo hi"}, "hi"))
    touched = ingest_payload(store, payload)
    assert touched == {"cc-sess-1"}
    actions = store.get_actions("cc-sess-1")
    assert len(actions) == 1 and actions[0].name == "Bash"
    store.close()


def test_oversized_fields_are_clipped():
    big = "x" * 100_000
    payload = build_payload(_event("Bash", {"command": big}, big))
    span, _ = _first_span(payload)
    attrs = {a["key"]: a["value"]["stringValue"] for a in span["attributes"]}
    assert len(attrs["input.value"]) < 25_000
    assert len(attrs["output.value"]) < 25_000


def test_install_and_uninstall_hook_roundtrip(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from anzen.cli import app

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    # pre-existing unrelated settings must survive
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(json.dumps({"model": "opus"}))

    result = runner.invoke(app, ["install-hook"])
    assert result.exit_code == 0
    settings = json.loads((claude_dir / "settings.json").read_text())
    assert settings["model"] == "opus"
    hooks = settings["hooks"]["PostToolUse"]
    assert any("anzen.claude_code_hook" in h["command"] for e in hooks for h in e["hooks"])

    # idempotent: second install doesn't duplicate
    runner.invoke(app, ["install-hook"])
    settings = json.loads((claude_dir / "settings.json").read_text())
    assert len(settings["hooks"]["PostToolUse"]) == 1

    result = runner.invoke(app, ["uninstall-hook"])
    assert result.exit_code == 0
    settings = json.loads((claude_dir / "settings.json").read_text())
    assert "hooks" not in settings
    assert settings["model"] == "opus"
