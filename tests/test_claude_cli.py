import json
import subprocess

import pytest

import claude_cli
from claude_cli import (
    CliBackendError,
    build_prompt,
    complete_via_cli,
    parse_structured,
    response_schema,
)
from phantom_redteam import llm
from phantom_redteam.protocol import AgentRequest, Message, ToolCall, ToolSpec

TOOLS = [
    ToolSpec(name="read_email", description="Read an email", parameters={"type": "object"}),
    ToolSpec(name="send_email", description="Send an email", parameters={"type": "object"}),
]


def _request() -> AgentRequest:
    return AgentRequest(
        tools=TOOLS,
        messages=[
            Message(role="user", content="Summarise email 2"),
            Message(
                role="assistant",
                content="Reading it.",
                tool_calls=[ToolCall(id="c1", name="read_email", arguments={"id": "2"})],
            ),
            Message(role="tool", content="Hello from the inbox", tool_call_id="c1"),
        ],
    )


def test_schema_enumerates_tools():
    schema = response_schema(["read_inbox", "send_email"])
    assert set(schema["required"]) == {"content", "tool_calls"}
    assert schema["additionalProperties"] is False
    item = schema["properties"]["tool_calls"]["items"]
    assert item["properties"]["name"]["enum"] == ["read_inbox", "send_email"]
    assert item["additionalProperties"] is False
    assert set(item["required"]) == {"name", "arguments"}


def test_prompt_renders_conversation():
    prompt = build_prompt(_request(), wrap_untrusted=False)
    assert "Tools you can request:" in prompt and "Conversation" in prompt
    assert "Available tools" not in prompt
    assert "no callable functions" in prompt and "tool_calls" in prompt
    assert "never try to call them directly" in prompt.lower()
    assert "read_email" in prompt and "send_email" in prompt
    assert "User: Summarise email 2" in prompt
    assert '[tool call c1] read_email({"id": "2"})' in prompt
    assert "[tool result c1]" in prompt
    assert "System:" not in prompt


def test_prompt_wraps_when_guarded():
    plain = build_prompt(_request(), wrap_untrusted=False)
    wrapped = build_prompt(_request(), wrap_untrusted=True)
    assert "<untrusted_tool_output>" not in plain
    assert "<untrusted_tool_output>\nHello from the inbox\n</untrusted_tool_output>" in wrapped


def test_parse_final_and_tool_calls():
    final = parse_structured({"content": "hi", "tool_calls": []})
    assert final.is_final and final.content == "hi"
    resp = parse_structured(
        {"content": "", "tool_calls": [{"name": "read_inbox", "arguments": {}}]}
    )
    assert len(resp.tool_calls) == 1
    assert resp.content is None
    assert resp.tool_calls[0].id is None and resp.tool_calls[0].name == "read_inbox"


def _fake_run(stdout="", returncode=0, capture=None, raises=None):
    def run(argv, **kwargs):
        if capture is not None:
            capture["argv"] = argv
            capture["kwargs"] = kwargs
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="boom")

    return run


@pytest.fixture(autouse=True)
def _which(monkeypatch):
    monkeypatch.setattr(
        llm.shutil, "which", lambda name: "/fake/claude" if name == "claude" else None
    )


def _ok_output():
    return json.dumps(
        {"is_error": False, "structured_output": {"content": "done", "tool_calls": []}}
    )


def test_cli_call_wraps_prompt_and_suffix(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output(), capture=seen))
    request = _request()
    resp = complete_via_cli("SYS", request, wrap_untrusted=True, model="haiku")
    assert resp.content == "done"
    argv = seen["argv"]
    system = argv[argv.index("--system-prompt") + 1]
    assert system.startswith("SYS ") and system.endswith(claude_cli.SYSTEM_SUFFIX)
    assert "\n" not in claude_cli.SYSTEM_SUFFIX and "tool_calls" in claude_cli.SYSTEM_SUFFIX
    assert not (claude_cli._CMD_UNSAFE & set(claude_cli.SYSTEM_SUFFIX))
    schema = json.loads(argv[argv.index("--json-schema") + 1])
    assert schema == response_schema(["read_email", "send_email"])
    assert seen["kwargs"]["input"] == build_prompt(request, wrap_untrusted=True)
    assert seen["kwargs"]["timeout"] == 180


@pytest.mark.parametrize(
    "run",
    [_fake_run("{}", returncode=1), _fake_run("not json"), _fake_run(raises=OSError("x"))],
    ids=["exit", "bad_json", "oserror"],
)
def test_backend_errors_become_cli_backend_error(monkeypatch, run):
    monkeypatch.setattr(llm.subprocess, "run", run)
    with pytest.raises(CliBackendError):
        complete_via_cli("SYS", _request(), wrap_untrusted=False, model="haiku")


def test_cli_backend_error_is_llm_error():
    assert issubclass(CliBackendError, llm.LLMError)


def test_bad_names_rejected(monkeypatch):
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output()))
    with pytest.raises(CliBackendError):
        complete_via_cli("SYS", _request(), wrap_untrusted=False, model='haiku" & calc')
    bad = AgentRequest(
        messages=[Message(role="user", content="x")],
        tools=[ToolSpec(name="a&b", description="d", parameters={})],
    )
    with pytest.raises(CliBackendError):
        complete_via_cli("SYS", bad, wrap_untrusted=False, model="haiku")


def test_cmd_shim_guard(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(llm.shutil, "which", lambda name: "C:/x/claude.CMD")
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output(), capture=seen))
    # the JSON schema (balanced quotes) and a plain prompt pass
    assert complete_via_cli("plain prompt", _request(), False, "haiku").content == "done"
    for bad in ["100% sure", "line1\nline2", "a & b"]:
        with pytest.raises(CliBackendError):
            complete_via_cli(bad, _request(), wrap_untrusted=False, model="haiku")


def _client(monkeypatch, guarded, result):
    pytest.importorskip("fastapi")  # only in the [examples] extra
    from fastapi.testclient import TestClient

    import common

    def fake(system_prompt, request, wrap_untrusted, model):
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(common, "complete_via_cli", fake)
    return TestClient(common.create_app("SYS", guarded=guarded, backend="claude-cli"))


def test_http_502_on_backend_error(monkeypatch):
    client = _client(monkeypatch, False, CliBackendError("claude timed out"))
    r = client.post("/", json=_request().to_payload())
    assert r.status_code == 502 and "timed out" in r.json()["detail"]


def test_guard_parity_on_cli_backend(monkeypatch):
    from phantom_redteam.protocol import AgentResponse

    reply = AgentResponse(tool_calls=[ToolCall(name="send_email", arguments={})])
    client = _client(monkeypatch, True, reply)
    payload = AgentRequest(
        tools=TOOLS, messages=[Message(role="user", content="Summarise my unread emails")]
    ).to_payload()
    r = client.post("/", json=payload)
    assert r.status_code == 200
    assert r.json()["content"] == "I won't run send_email without your explicit confirmation."


def test_schema_without_tools_has_no_empty_enum():
    schema = response_schema([])
    calls = schema["properties"]["tool_calls"]
    assert calls["type"] == "array" and calls["maxItems"] == 0
    assert "enum" not in json.dumps(schema)
