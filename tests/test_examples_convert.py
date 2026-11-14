import pytest

from convert import (
    blocked_side_effects,
    from_anthropic_content,
    to_anthropic_messages,
    to_anthropic_tools,
)
from phantom_redteam.protocol import Message, ToolCall, ToolSpec


def test_tools_shape():
    spec = ToolSpec(name="read_file", description="Read", parameters={"type": "object"})
    assert to_anthropic_tools([spec]) == [
        {"name": "read_file", "description": "Read", "input_schema": {"type": "object"}}
    ]


def _convo():
    return [
        Message(role="user", content="hi"),
        Message(
            role="assistant",
            content="checking",
            tool_calls=[
                ToolCall(id="a", name="read_file", arguments={"path": "x"}),
                ToolCall(id="b", name="read_file", arguments={"path": "y"}),
            ],
        ),
        Message(role="tool", content="one", tool_call_id="a"),
        Message(role="tool", content="two", tool_call_id="b"),
    ]


def test_consecutive_tool_results_merged():
    out = to_anthropic_messages(_convo(), wrap_untrusted=False)
    assert [m["role"] for m in out] == ["user", "assistant", "user"]
    assert out[0]["content"] == [{"type": "text", "text": "hi"}]
    assert out[1]["content"][0] == {"type": "text", "text": "checking"}
    assert out[1]["content"][1] == {
        "type": "tool_use", "id": "a", "name": "read_file", "input": {"path": "x"}
    }
    results = out[2]["content"]
    assert [b["type"] for b in results] == ["tool_result", "tool_result"]
    assert [b["tool_use_id"] for b in results] == ["a", "b"]
    assert [b["content"] for b in results] == ["one", "two"]


def test_wrap_untrusted():
    out = to_anthropic_messages(_convo(), wrap_untrusted=True)
    assert out[2]["content"][0]["content"] == (
        "<untrusted_tool_output>\none\n</untrusted_tool_output>"
    )


def test_from_content_text_and_tool_use():
    resp = from_anthropic_content(
        [
            {"type": "text", "text": "Hello"},
            {"type": "text", "text": "world"},
            {"type": "tool_use", "id": "t1", "name": "web_search", "input": {"q": "k"}},
        ]
    )
    assert resp.content == "Hello\nworld"
    assert resp.tool_calls == [ToolCall(id="t1", name="web_search", arguments={"q": "k"})]
    assert from_anthropic_content([{"type": "text", "text": "done"}]).is_final


def test_blocked_side_effects():
    send = ToolCall(id="1", name="send_email", arguments={})
    read = ToolCall(id="2", name="read_file", arguments={})
    assert blocked_side_effects("Summarise my unread emails", [send, read]) == [send]
    assert blocked_side_effects("Forward this to Bob", [send]) == []
    assert blocked_side_effects("Delete it", [ToolCall(name="run_shell")]) != []
    assert blocked_side_effects("anything", [read]) == []


def test_autopilot_agent_prompt():
    for module in ("fastapi", "uvicorn", "anthropic"):
        pytest.importorskip(module)
    import autopilot_agent

    assert "action items" in autopilot_agent.SYSTEM_PROMPT
