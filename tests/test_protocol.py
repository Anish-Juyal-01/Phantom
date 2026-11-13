import pytest
from pydantic import ValidationError

from kestrel_redteam.protocol import (
    AgentRequest,
    AgentResponse,
    Message,
    ToolCall,
)


@pytest.mark.parametrize(
    "data",
    [{"content": "hi"}, {"content": "hi", "tool_calls": None}, {"content": "hi", "tool_calls": []}],
)
def test_response_without_tool_calls_is_final(data):
    assert AgentResponse.model_validate(data).is_final is True


def test_response_with_tool_call_not_final():
    resp = AgentResponse.model_validate({"tool_calls": [{"name": "read_inbox"}]})
    assert resp.is_final is False
    assert resp.tool_calls[0].arguments == {}
    assert resp.tool_calls[0].id is None


def test_arguments_json_string_parsed():
    call = ToolCall.model_validate({"name": "read_email", "arguments": '{"id": "2"}'})
    assert call.arguments == {"id": "2"}


@pytest.mark.parametrize("bad", ["not json", "[1,2]"])
def test_arguments_bad_string_rejected(bad):
    with pytest.raises(ValidationError):
        ToolCall.model_validate({"name": "x", "arguments": bad})


@pytest.mark.parametrize("empty", ["", None])
def test_arguments_empty_becomes_dict(empty):
    assert ToolCall.model_validate({"name": "x", "arguments": empty}).arguments == {}


def test_request_payload_drops_none():
    req = AgentRequest(messages=[Message(role="user", content="x")], tools=[])
    assert req.to_payload()["messages"][0] == {"role": "user", "content": "x"}


def test_missing_tool_calls_is_empty_list():
    assert AgentResponse.model_validate({"content": "hi"}).tool_calls == []


def test_response_with_json_string_arguments():
    resp = AgentResponse.model_validate(
        {"tool_calls": [{"id": "c1", "name": "read_email", "arguments": "{\"id\": \"2\"}"}]}
    )
    assert resp.tool_calls[0].arguments == {"id": "2"}
