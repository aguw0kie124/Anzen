"""Full ingestion pipeline against the real stdlib server: emit → collect → store."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from anzen.collector import make_server
from anzen.rules import load_rules
from anzen.store import ActionType, Store


def _serve(store, **kwargs):
    srv = make_server(store, host="127.0.0.1", port=0, **kwargs)  # ephemeral port
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv


@pytest.fixture()
def server(tmp_path):
    store = Store(str(tmp_path / "anzen.db"))
    srv = _serve(store)
    yield store, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()
    store.close()


@pytest.fixture()
def scanning_server(tmp_path):
    """A collector built with the rule pack — the `anzen serve`/`anzen up` configuration."""
    store = Store(str(tmp_path / "anzen.db"))
    srv = _serve(store, rules=load_rules())
    yield store, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()
    store.close()


def _post(url: str, data: bytes, content_type: str) -> int:
    req = urllib.request.Request(url, data=data, headers={"Content-Type": content_type})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status


def test_health(server):
    _, base = server
    with urllib.request.urlopen(f"{base}/healthz", timeout=5) as resp:
        assert resp.status == 200


def test_openinference_json_ingest(server):
    store, base = server
    payload = {
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "my-agent"}},
                {"key": "session.id", "value": {"stringValue": "sess-json"}},
            ]},
            "scopeSpans": [{"spans": [{
                "name": "run_bash",
                "spanId": "0011223344556677",
                "traceId": "00112233445566778899aabbccddeeff",
                "startTimeUnixNano": "1700000000000000000",
                "endTimeUnixNano": "1700000000500000000",
                "attributes": [
                    {"key": "openinference.span.kind", "value": {"stringValue": "TOOL"}},
                    {"key": "tool.name", "value": {"stringValue": "run_bash"}},
                    {"key": "tool.parameters", "value": {"stringValue": '{"command": "rm -rf /tmp/x"}'}},
                    {"key": "output.value", "value": {"stringValue": "done"}},
                ],
            }]}],
        }]
    }
    status = _post(f"{base}/v1/traces", json.dumps(payload).encode(), "application/json")
    assert status == 200

    session = store.get_session("sess-json")
    assert session is not None
    assert session.agent_name == "my-agent"
    actions = store.get_actions("sess-json")
    assert len(actions) == 1
    assert actions[0].action_type is ActionType.tool_call
    assert actions[0].name == "run_bash"
    assert "rm -rf" in actions[0].input


def test_openinference_protobuf_ingest_via_sdk(server):
    """The real path: OTel SDK spans with OpenInference attrs, protobuf-encoded."""
    store, base = server
    from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider(
        resource=Resource.create({"service.name": "sdk-agent", "session.id": "sess-pb"})
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")

    with tracer.start_as_current_span("read_file") as span:
        span.set_attribute("openinference.span.kind", "TOOL")
        span.set_attribute("tool.name", "read_file")
        span.set_attribute("tool.parameters", '{"path": "/app/.env"}')
        span.set_attribute("output.value", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    with tracer.start_as_current_span("llm") as span:
        span.set_attribute("openinference.span.kind", "LLM")
        span.set_attribute("llm.model_name", "claude-opus-4-8")
        span.set_attribute("llm.token_count.prompt", 100)
        span.set_attribute("llm.token_count.completion", 20)

    body = encode_spans(exporter.get_finished_spans()).SerializeToString()
    status = _post(f"{base}/v1/traces", body, "application/x-protobuf")
    assert status == 200

    session = store.get_session("sess-pb")
    assert session is not None
    assert session.action_count == 2
    assert session.input_tokens == 100 and session.output_tokens == 20
    by_name = {a.name: a for a in store.get_actions("sess-pb")}
    assert by_name["read_file"].action_type is ActionType.tool_call
    assert "AKIA" in by_name["read_file"].output
    assert by_name["claude-opus-4-8"].action_type is ActionType.llm_call


def test_malformed_payload_returns_400_and_server_survives(server):
    _, base = server
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _post(f"{base}/v1/traces", b"not json at all", "application/json")
    assert exc_info.value.code == 400
    # server still alive
    with urllib.request.urlopen(f"{base}/healthz", timeout=5) as resp:
        assert resp.status == 200


def test_duplicate_span_delivery_is_idempotent(server):
    store, base = server
    payload = {
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "session.id", "value": {"stringValue": "sess-dup"}},
            ]},
            "scopeSpans": [{"spans": [{
                "name": "t",
                "spanId": "0011223344556677",
                "traceId": "00112233445566778899aabbccddeeff",
                "startTimeUnixNano": "1700000000000000000",
                "attributes": [
                    {"key": "openinference.span.kind", "value": {"stringValue": "LLM"}},
                    {"key": "llm.token_count.prompt", "value": {"intValue": "50"}},
                ],
            }]}],
        }]
    }
    body = json.dumps(payload).encode()
    _post(f"{base}/v1/traces", body, "application/json")
    _post(f"{base}/v1/traces", body, "application/json")  # re-delivery

    session = store.get_session("sess-dup")
    assert session.action_count == 1        # span stored once
    assert session.input_tokens == 50       # tokens not double-counted


def _risky_payload(session_id: str, command: str = "rm -rf /tmp/x") -> bytes:
    return json.dumps({
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "risky-agent"}},
                {"key": "session.id", "value": {"stringValue": session_id}},
            ]},
            "scopeSpans": [{"spans": [{
                "name": "run_bash",
                "spanId": "aa11223344556677",
                "traceId": "aa112233445566778899aabbccddeeff",
                "startTimeUnixNano": "1700000000000000000",
                "attributes": [
                    {"key": "openinference.span.kind", "value": {"stringValue": "TOOL"}},
                    {"key": "tool.name", "value": {"stringValue": "run_bash"}},
                    {"key": "tool.parameters", "value": {"stringValue": json.dumps({"command": command})}},
                ],
            }]}],
        }]
    }).encode()


def test_auto_scan_on_ingest(scanning_server):
    """Findings exist the moment the action arrives — no manual `anzen scan`."""
    store, base = scanning_server
    _post(f"{base}/v1/traces", _risky_payload("sess-auto"), "application/json")

    findings = store.get_findings("sess-auto")
    assert any(f.rule_id == "DST-001" for f in findings)
    assert findings[0].action_id is not None  # linked to the stored action


def test_auto_scan_duplicate_delivery_no_duplicate_findings(scanning_server):
    store, base = scanning_server
    body = _risky_payload("sess-auto-dup")
    _post(f"{base}/v1/traces", body, "application/json")
    _post(f"{base}/v1/traces", body, "application/json")  # re-delivery

    findings = [f for f in store.get_findings("sess-auto-dup") if f.rule_id == "DST-001"]
    assert len(findings) == 1


def test_manual_rescan_after_auto_scan_no_duplicates(scanning_server):
    from anzen.rules import scan_session

    store, base = scanning_server
    _post(f"{base}/v1/traces", _risky_payload("sess-rescan"), "application/json")
    auto = store.get_findings("sess-rescan")
    scan_session(store, "sess-rescan", load_rules())  # manual `anzen scan`
    assert len(store.get_findings("sess-rescan")) == len(auto)


def test_agents_rollup(scanning_server):
    store, base = scanning_server
    _post(f"{base}/v1/traces", _risky_payload("sess-agents"), "application/json")

    agents = store.list_agents()
    assert len(agents) == 1
    a = agents[0]
    assert a["agent_name"] == "risky-agent"
    assert a["sessions"] == 1 and a["actions"] == 1
    assert a["finding_counts"].get("high") or a["finding_counts"].get("critical")
