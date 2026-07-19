"""OpenInference span normalization and the generic fallback."""

from anzen.collector import normalize_span
from anzen.store import ActionType


def _span(name, attributes, span_id="0011223344556677", trace_id="00112233445566778899aabbccddeeff"):
    return {
        "name": name,
        "spanId": span_id,
        "traceId": trace_id,
        "startTimeUnixNano": "1700000000000000000",
        "endTimeUnixNano": "1700000000500000000",
        "attributes": [{"key": k, "value": v} for k, v in attributes.items()],
    }


def _s(text):
    return {"stringValue": text}


def test_tool_span_mapped():
    span = _span(
        "run_bash",
        {
            "openinference.span.kind": _s("TOOL"),
            "tool.name": _s("run_bash"),
            "tool.parameters": _s('{"command": "ls"}'),
            "output.value": _s("a\nb"),
        },
    )
    session, action = normalize_span(span, {"session.id": "sess-1", "service.name": "svc"})
    assert action.action_type is ActionType.tool_call
    assert action.name == "run_bash"
    assert action.input == '{"command": "ls"}'
    assert action.output == "a\nb"
    assert session.id == "sess-1"
    assert session.agent_name == "svc"


def test_tool_span_falls_back_to_input_value():
    span = _span(
        "search",
        {
            "openinference.span.kind": _s("TOOL"),
            "tool.name": _s("search"),
            "input.value": _s("query text"),
            "output.value": _s("results"),
        },
    )
    _, action = normalize_span(span, {})
    assert action.input == "query text"


def test_llm_span_and_token_usage():
    span = _span(
        "llm",
        {
            "openinference.span.kind": _s("LLM"),
            "llm.model_name": _s("claude-opus-4-8"),
            "input.value": _s("prompt here"),
            "output.value": _s("completion here"),
            "llm.token_count.prompt": {"intValue": "1200"},
            "llm.token_count.completion": {"intValue": "340"},
        },
    )
    session, action = normalize_span(span, {})
    assert action.action_type is ActionType.llm_call
    assert action.name == "claude-opus-4-8"
    assert action.input == "prompt here"
    assert session.input_tokens == 1200
    assert session.output_tokens == 340


def test_agent_span_mapped():
    span = _span("root", {"openinference.span.kind": _s("AGENT"), "input.value": _s("task")})
    _, action = normalize_span(span, {})
    assert action.action_type is ActionType.agent_invoke
    assert action.input == "task"


def test_unknown_span_preserved_with_raw():
    span = _span("mystery.operation", {"custom.attr": _s("value")})
    _, action = normalize_span(span, {})
    assert action.action_type is ActionType.unknown
    assert action.raw_attributes["span"]["name"] == "mystery.operation"


def test_chain_kind_is_unknown_but_captured():
    span = _span(
        "chain step",
        {"openinference.span.kind": _s("CHAIN"), "input.value": _s("x"), "output.value": _s("y")},
    )
    _, action = normalize_span(span, {})
    assert action.action_type is ActionType.unknown
    assert action.input == "x"
    assert action.output == "y"


def test_session_falls_back_to_trace_id():
    span = _span("t", {"openinference.span.kind": _s("TOOL")})
    session, _ = normalize_span(span, {})
    assert session.id == "00112233445566778899aabbccddeeff"


def test_base64_span_id_decoded_to_hex():
    # protobuf->dict path yields base64-encoded ids
    span = _span("t", {"openinference.span.kind": _s("TOOL")}, span_id="ABEiM0RVZnc=")
    _, action = normalize_span(span, {})
    assert action.span_id == "0011223344556677"
