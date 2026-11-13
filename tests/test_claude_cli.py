import json
import os
import subprocess
from pathlib import Path

import pytest

import claude_cli
from claude_cli import (
    CliBackendError,
    build_prompt,
    complete_via_cli,
    parse_structured,
    response_schema,
)
from kestrel_redteam.protocol import AgentRequest, Message, ToolCall, ToolSpec

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
        claude_cli.shutil, "which", lambda name: "/fake/claude" if name == "claude" else None
    )


def _ok_output():
    return json.dumps(
        {"is_error": False, "structured_output": {"content": "done", "tool_calls": []}}
    )


def test_cli_argv_is_locked_down(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(claude_cli.subprocess, "run", _fake_run(_ok_output(), capture=seen))
    request = _request()
    resp = complete_via_cli("SYS", request, wrap_untrusted=True, model="haiku")
    assert resp.content == "done"
    argv = seen["argv"]
    assert argv[0] == "/fake/claude"
    assert "-p" in argv
    for flag, value in [
        ("--tools", ""),
        ("--setting-sources", ""),
        ("--output-format", "json"),
        ("--model", "haiku"),
    ]:
        assert argv[argv.index(flag) + 1] == value
    system = argv[argv.index("--system-prompt") + 1]
    assert system.startswith("SYS ") and system.endswith(claude_cli.SYSTEM_SUFFIX)
    assert "\n" not in claude_cli.SYSTEM_SUFFIX and "tool_calls" in claude_cli.SYSTEM_SUFFIX
    assert not (claude_cli._CMD_UNSAFE & set(claude_cli.SYSTEM_SUFFIX))
    assert "--strict-mcp-config" in argv and "--no-session-persistence" in argv
    assert "--json-schema" in argv
    cwd = Path(seen["kwargs"]["cwd"])
    assert cwd.is_dir()
    assert not str(cwd.resolve()).startswith(str(Path(__file__).resolve().parents[1]))
    assert seen["kwargs"]["input"] == build_prompt(request, wrap_untrusted=True)
    assert seen["kwargs"]["timeout"] == 180


@pytest.mark.parametrize(
    "run",
    [
        _fake_run("{}", returncode=1),
        _fake_run(json.dumps({"is_error": True, "structured_output": {}})),
        _fake_run(json.dumps({"is_error": False})),
        _fake_run("not json"),
        _fake_run(raises=subprocess.TimeoutExpired("claude", 180)),
        _fake_run(raises=FileNotFoundError("claude")),
        _fake_run(raises=PermissionError("denied")),
    ],
    ids=["exit", "is_error", "no_structured", "bad_json", "timeout", "not_found", "permission"],
)
def test_cli_errors_raise(monkeypatch, run):
    monkeypatch.setattr(claude_cli.subprocess, "run", run)
    with pytest.raises(CliBackendError):
        complete_via_cli("SYS", _request(), wrap_untrusted=False, model="haiku")


def test_missing_executable_raises(monkeypatch):
    monkeypatch.setattr(claude_cli.shutil, "which", lambda name: None)
    with pytest.raises(CliBackendError):
        complete_via_cli("SYS", _request(), wrap_untrusted=False, model="haiku")


def test_workdir_failure_raises(monkeypatch):
    monkeypatch.setattr(claude_cli, "_workdir", [])

    def boom(prefix):
        raise OSError("disk full")

    monkeypatch.setattr(claude_cli.tempfile, "mkdtemp", boom)
    monkeypatch.setattr(claude_cli.subprocess, "run", _fake_run(_ok_output()))
    with pytest.raises(CliBackendError):
        complete_via_cli("SYS", _request(), wrap_untrusted=False, model="haiku")


def test_decodes_with_replace(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(claude_cli.subprocess, "run", _fake_run(_ok_output(), capture=seen))
    complete_via_cli("SYS", _request(), wrap_untrusted=False, model="haiku")
    assert seen["kwargs"]["errors"] == "replace"


def test_bad_names_rejected(monkeypatch):
    monkeypatch.setattr(claude_cli.subprocess, "run", _fake_run(_ok_output()))
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
    monkeypatch.setattr(claude_cli.shutil, "which", lambda name: "C:/x/claude.CMD")
    monkeypatch.setattr(claude_cli.subprocess, "run", _fake_run(_ok_output(), capture=seen))
    # the JSON schema (balanced quotes) and a plain prompt pass
    assert complete_via_cli("plain prompt", _request(), False, "haiku").content == "done"
    for bad in ["100% sure", "line1\nline2", "a & b"]:
        with pytest.raises(CliBackendError):
            complete_via_cli(bad, _request(), wrap_untrusted=False, model="haiku")


def test_system_prompt_not_checked_for_exe(monkeypatch):
    # non-.cmd executables take any prompt text
    monkeypatch.setattr(claude_cli.subprocess, "run", _fake_run(_ok_output()))
    assert complete_via_cli("100% & more\n", _request(), False, "haiku").content == "done"


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
    from kestrel_redteam.protocol import AgentResponse

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
