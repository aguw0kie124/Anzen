"""End-to-end: OTLP log ingest → rule scan → read API, via FastAPI TestClient."""

import json

import pytest
from fastapi.testclient import TestClient

from anzen.rules import load_rules
from anzen.server.app import create_app
from anzen.store import Store


def _log_payload(session_id: str, event: str, attrs: dict, time_ns: int = 1700000000000000000) -> dict:
    def any_value(v):
        if isinstance(v, bool):
            return {"boolValue": v}
        if isinstance(v, int):
            return {"intValue": str(v)}
        return {"stringValue": str(v)}

    attrs = {"session.id": session_id, **attrs}
    return {
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "claude-code"}},
            ]},
            "scopeLogs": [{"logRecords": [{
                "timeUnixNano": str(time_ns),
                "attributes": [
                    {"key": "event.name", "value": {"stringValue": f"claude_code.{event}"}},
                    *({"key": k, "value": any_value(v)} for k, v in attrs.items()),
                ],
            }]}],
        }]
    }


@pytest.fixture()
def client(tmp_path):
    store = Store(str(tmp_path / "anzen.db"))
    app = create_app(store, load_rules(), api_keys=None)
    yield TestClient(app), store
    store.close()


@pytest.fixture()
def authed_client(tmp_path):
    store = Store(str(tmp_path / "anzen.db"))
    app = create_app(store, load_rules(), api_keys={"secret-key"})
    yield TestClient(app), store
    store.close()


def test_health(client):
    c, _ = client
    assert c.get("/healthz").status_code == 200


def test_ingest_tool_call_appears_in_session(client):
    c, store = client
    payload = _log_payload("sess-1", "tool_result", {
        "tool_name": "Bash", "tool_use_id": "tu-1",
        "tool_input": json.dumps({"command": "rm -rf /tmp/x"}),
    })
    resp = c.post("/v1/logs", json=payload)
    assert resp.status_code == 200

    detail = c.get("/api/sessions/sess-1").json()
    assert detail["session"]["id"] == "sess-1"
    assert len(detail["actions"]) == 1
    assert detail["actions"][0]["name"] == "Bash"
    assert any(f["rule_id"] == "DST-001" for f in detail["findings"])


def test_duplicate_delivery_is_idempotent(client):
    c, store = client
    payload = _log_payload("sess-dup", "tool_result", {"tool_name": "Read", "tool_use_id": "tu-1"})
    c.post("/v1/logs", json=payload)
    c.post("/v1/logs", json=payload)  # re-delivery
    session = store.get_session("sess-dup")
    assert session.action_count == 1


def test_tool_decision_merges_onto_tool_result(client):
    c, store = client
    c.post("/v1/logs", json=_log_payload("sess-2", "tool_result", {
        "tool_name": "Bash", "tool_use_id": "tu-9",
    }))
    c.post("/v1/logs", json=_log_payload("sess-2", "tool_decision", {
        "tool_use_id": "tu-9", "decision": "accept", "source": "config",
    }))
    action = store.get_actions("sess-2")[0]
    assert (action.decision, action.decision_source) == ("accept", "config")


def test_mcp_connection_appears_in_inventory(client):
    c, _ = client
    c.post("/v1/logs", json=_log_payload("sess-3", "mcp_server_connection", {
        "server_name": "github", "transport_type": "stdio", "status": "connected",
    }))
    inventory = c.get("/api/inventory").json()
    assert any(i["name"] == "github" and i["kind"] == "mcp_server" for i in inventory)


def test_inventory_review_patch(client):
    c, _ = client
    c.post("/v1/logs", json=_log_payload("sess-4", "mcp_server_connection", {"server_name": "slack"}))
    item = c.get("/api/inventory").json()[0]
    assert item["approved"] is None
    resp = c.patch(f"/api/inventory/{item['id']}", json={"approved": True})
    assert resp.status_code == 200
    assert c.get("/api/inventory").json()[0]["approved"] is True


def test_findings_feed_filters_by_severity(client):
    c, _ = client
    c.post("/v1/logs", json=_log_payload("sess-5", "tool_result", {
        "tool_name": "Bash", "tool_input": json.dumps({"command": "sudo rm -rf /"}),
    }))
    all_findings = c.get("/api/findings").json()
    assert len(all_findings) >= 1
    high = c.get("/api/findings", params={"severity": "high"}).json()
    assert all(f["severity"] == "high" for f in high)


def test_report_export(client):
    c, _ = client
    c.post("/v1/logs", json=_log_payload("sess-6", "user_prompt", {"prompt": "hi"}))
    resp = c.get("/api/sessions/sess-6/report.md")
    assert resp.status_code == 200
    assert "Anzen Audit Report" in resp.text


def test_unknown_session_404(client):
    c, _ = client
    assert c.get("/api/sessions/does-not-exist").status_code == 404
    assert c.get("/api/sessions/does-not-exist/report.md").status_code == 404


def test_malformed_body_returns_400(client):
    c, _ = client
    resp = c.post("/v1/logs", content=b"not json", headers={"Content-Type": "application/json"})
    assert resp.status_code == 400
    assert c.get("/healthz").status_code == 200  # server survives


# -- auth ---------------------------------------------------------------

def test_missing_bearer_rejected(authed_client):
    c, _ = authed_client
    resp = c.post("/v1/logs", json=_log_payload("s", "user_prompt", {}))
    assert resp.status_code == 401
    assert c.get("/api/stats").status_code == 401


def test_wrong_bearer_rejected(authed_client):
    c, _ = authed_client
    resp = c.get("/api/stats", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


def test_correct_bearer_accepted(authed_client):
    c, _ = authed_client
    headers = {"Authorization": "Bearer secret-key"}
    assert c.post("/v1/logs", json=_log_payload("s", "user_prompt", {}), headers=headers).status_code == 200
    assert c.get("/api/stats", headers=headers).status_code == 200


def test_healthz_never_requires_auth(authed_client):
    c, _ = authed_client
    assert c.get("/healthz").status_code == 200
