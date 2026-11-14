import builtins
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from fake_llm import FakeLLM
from phantom_redteam import llm
from phantom_redteam.llm import (
    AnthropicLLM,
    ClaudeCliLLM,
    LLMError,
    make_llm,
    run_claude_cli,
)

SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


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
    return json.dumps({"is_error": False, "structured_output": {"x": "done"}})


def test_cli_argv_locked_down(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output(), capture=seen))
    out = run_claude_cli("SYS", "the prompt", SCHEMA, "haiku")
    assert out == {"x": "done"}
    argv = seen["argv"]
    assert argv[0] == "/fake/claude" and "-p" in argv
    for flag, value in [
        ("--tools", ""),
        ("--setting-sources", ""),
        ("--output-format", "json"),
        ("--model", "haiku"),
        ("--system-prompt", "SYS"),
        ("--json-schema", json.dumps(SCHEMA)),
    ]:
        assert argv[argv.index(flag) + 1] == value
    assert "--strict-mcp-config" in argv and "--no-session-persistence" in argv
    cwd = Path(seen["kwargs"]["cwd"])
    assert cwd.is_dir()
    assert not str(cwd.resolve()).startswith(str(Path(__file__).resolve().parents[1]))
    assert seen["kwargs"]["input"] == "the prompt"
    assert seen["kwargs"]["timeout"] == 240
    assert seen["kwargs"]["errors"] == "replace"


@pytest.mark.parametrize(
    "run",
    [
        _fake_run("{}", returncode=1),
        _fake_run(json.dumps({"is_error": True, "structured_output": {}})),
        _fake_run(json.dumps({"is_error": False})),
        _fake_run("not json"),
        _fake_run("[1]"),
        _fake_run(raises=subprocess.TimeoutExpired("claude", 240)),
        _fake_run(raises=FileNotFoundError("claude")),
        _fake_run(raises=PermissionError("denied")),
    ],
    ids=[
        "exit", "is_error", "no_structured", "bad_json", "not_object",
        "timeout", "not_found", "permission",
    ],
)
def test_cli_errors_raise_llmerror(monkeypatch, run):
    monkeypatch.setattr(llm.subprocess, "run", run)
    with pytest.raises(LLMError):
        run_claude_cli("SYS", "p", SCHEMA, "haiku")


def test_missing_executable_and_bad_model(monkeypatch):
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output()))
    with pytest.raises(LLMError):
        run_claude_cli("SYS", "p", SCHEMA, 'haiku" & calc')
    monkeypatch.setattr(llm.shutil, "which", lambda name: None)
    with pytest.raises(LLMError):
        run_claude_cli("SYS", "p", SCHEMA, "haiku")


def test_workdir_failure_raises(monkeypatch):
    monkeypatch.setattr(llm, "_workdir", [])

    def boom(prefix):
        raise OSError("disk full")

    monkeypatch.setattr(llm.tempfile, "mkdtemp", boom)
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output()))
    with pytest.raises(LLMError):
        run_claude_cli("SYS", "p", SCHEMA, "haiku")


def test_cmd_guard(monkeypatch):
    monkeypatch.setattr(llm.shutil, "which", lambda name: "C:/x/claude.CMD")
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output()))
    assert run_claude_cli("plain prompt", "p", SCHEMA, "haiku") == {"x": "done"}
    for bad in ["100% sure", "line1\nline2", "a & b"]:
        with pytest.raises(LLMError):
            run_claude_cli(bad, "p", SCHEMA, "haiku")


def test_non_cmd_exe_takes_any_system_text(monkeypatch):
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output()))
    assert run_claude_cli("100% & more\n", "p", SCHEMA, "haiku") == {"x": "done"}


def test_claude_cli_llm_delegates(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output(), capture=seen))
    backend = ClaudeCliLLM()
    assert backend.name == "claude-cli:sonnet"
    assert backend.complete_json("S", "P", SCHEMA) == {"x": "done"}
    assert seen["argv"][seen["argv"].index("--model") + 1] == "sonnet"


class _Messages:
    def __init__(self, blocks, error=None):
        self.blocks, self.error, self.kwargs = blocks, error, None

    def create(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return SimpleNamespace(content=self.blocks)


def _client(blocks, error=None):
    return SimpleNamespace(messages=_Messages(blocks, error))


@pytest.mark.parametrize("as_dict", [False, True], ids=["sdk_object", "dict"])
def test_anthropic_backend_forced_tool(as_dict):
    text = {"type": "text", "text": "hmm"}
    tool = {"type": "tool_use", "name": "respond", "input": {"x": "y"}}
    blocks = [text, tool] if as_dict else [
        SimpleNamespace(**text), SimpleNamespace(**tool)
    ]
    client = _client(blocks)
    backend = AnthropicLLM(client=client)
    assert backend.name == "anthropic:claude-sonnet-5-5"
    assert backend.complete_json("SYS", "PROMPT", SCHEMA) == {"x": "y"}
    kw = client.messages.kwargs
    assert kw["model"] == "claude-sonnet-5-5" and kw["max_tokens"] == 4096
    assert kw["system"] == "SYS"
    assert kw["messages"] == [{"role": "user", "content": "PROMPT"}]
    assert kw["tools"] == [
        {"name": "respond", "description": "Return the answer", "input_schema": SCHEMA}
    ]
    assert kw["tool_choice"] == {"type": "tool", "name": "respond"}


def test_anthropic_api_error_and_no_tool_block():
    with pytest.raises(LLMError):
        AnthropicLLM(client=_client([], error=RuntimeError("rate limited"))).complete_json(
            "S", "P", SCHEMA
        )
    with pytest.raises(LLMError):
        AnthropicLLM(client=_client([{"type": "text", "text": "no"}])).complete_json(
            "S", "P", SCHEMA
        )


def test_anthropic_missing_package(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("no anthropic")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(LLMError, match=r"phantom-redteam\[ai\]"):
        AnthropicLLM().complete_json("S", "P", SCHEMA)


@pytest.mark.parametrize(
    "api_key, claude, expected",
    [
        ("sk-test", "/fake/claude", "anthropic:claude-sonnet-5-5"),
        (None, "/fake/claude", "claude-cli:sonnet"),
        (None, None, None),
    ],
    ids=["api_key", "cli_only", "nothing"],
)
def test_make_llm_auto(monkeypatch, api_key, claude, expected):
    if api_key:
        monkeypatch.setenv("ANTHROPIC_API_KEY", api_key)
    else:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(llm, "find_claude", lambda: claude)
    if expected is None:
        with pytest.raises(LLMError, match="No LLM backend"):
            make_llm("auto", None)
    else:
        assert make_llm("auto", None).name == expected


def test_make_llm_explicit_backend_and_model():
    assert make_llm("claude-cli", "haiku").name == "claude-cli:haiku"
    assert make_llm("anthropic", "m1").name == "anthropic:m1"
    assert make_llm("anthropic", None).name == "anthropic:claude-sonnet-5-5"


def test_fake_llm():
    boom = ValueError("x")
    fake = FakeLLM([{"a": 1}, boom])
    assert fake.complete_json("s", "p", {}) == {"a": 1}
    with pytest.raises(ValueError):
        fake.complete_json("s2", "p2", {})
    with pytest.raises(AssertionError):
        fake.complete_json("s3", "p3", {})
    assert [c[0] for c in fake.calls] == ["s", "s2", "s3"]
    assert FakeLLM(lambda s, p, sc: {"echo": p}).complete_json("s", "hi", {}) == {"echo": "hi"}


def test_anthropic_client_construction_error(monkeypatch):
    import sys

    def boom(*a, **k):
        raise RuntimeError("bad env")

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=boom))
    with pytest.raises(LLMError, match="client"):
        AnthropicLLM().complete_json("S", "P", SCHEMA)


def test_anthropic_import_non_importerror(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise RuntimeError("broken install")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(LLMError, match="broken install"):
        AnthropicLLM().complete_json("S", "P", SCHEMA)


def test_cli_unserializable_schema(monkeypatch):
    monkeypatch.setattr(llm, "find_claude", lambda: "claude")
    monkeypatch.setattr(llm.subprocess, "run", _fake_run(_ok_output()))
    with pytest.raises(LLMError):
        run_claude_cli("S", "p", {"x": object()}, "haiku")


# --- OpenAI-compatible backend ---------------------------------------------

import httpx  # noqa: E402

from phantom_redteam.llm import OpenAICompatLLM  # noqa: E402


def _ok(content):
    return {"choices": [{"message": {"content": content}}]}


def test_openai_compat_request_shape():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=_ok('{"x": "hi"}'))

    transport = httpx.MockTransport(handler)
    keyed = OpenAICompatLLM("m1", "http://local.test/v1/", api_key="sekret", transport=transport)
    assert keyed.name == "openai-compatible:m1"
    assert keyed.complete_json("SYS", "PROMPT", SCHEMA) == {"x": "hi"}
    keyless = OpenAICompatLLM("m1", "http://local.test/v1", transport=transport)
    keyless.complete_json("SYS", "PROMPT", SCHEMA)

    req = seen[0]
    assert str(req.url) == "http://local.test/v1/chat/completions"
    assert req.headers["authorization"] == "Bearer sekret"
    assert "authorization" not in seen[1].headers
    body = json.loads(req.content)
    assert body["model"] == "m1"
    assert body["response_format"] == {"type": "json_object"}
    assert body["temperature"] == 0.9
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][0]["content"].startswith("SYS")
    assert json.dumps(SCHEMA) in body["messages"][0]["content"]
    assert body["messages"][1] == {"role": "user", "content": "PROMPT"}


def test_openai_compat_parses_fenced_json():
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, json=_ok('```json\n{"x": "fenced"}\n```'))
    )
    out = OpenAICompatLLM("m", "http://local.test/v1", transport=transport).complete_json(
        "s", "p", SCHEMA
    )
    assert out == {"x": "fenced"}


def _connect_error(request):
    raise httpx.ConnectError("refused", request=request)


@pytest.mark.parametrize(
    "handler, fragment",
    [
        (lambda r: httpx.Response(500, text="server exploded"), "500"),
        (lambda r: httpx.Response(200, json=_ok("not json at all")), "valid JSON"),
        (lambda r: httpx.Response(200, json={"id": "x"}), "choices"),
        (lambda r: httpx.Response(200, json=_ok("[1, 2]")), "object"),
        (_connect_error, "could not reach"),
    ],
)
def test_openai_compat_errors(handler, fragment):
    model = OpenAICompatLLM("m", "http://local.test/v1", transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError, match=fragment):
        model.complete_json("s", "p", SCHEMA)


def test_make_llm_openai_compat_requirements(monkeypatch):
    with pytest.raises(LLMError, match="needs --attacker-model and --base-url"):
        make_llm("openai-compatible", "m")
    with pytest.raises(LLMError, match="needs --attacker-model and --base-url"):
        make_llm("openai-compatible", None, base_url="http://x/v1")
    monkeypatch.delenv("PHANTOM_TEST_KEY", raising=False)
    with pytest.raises(LLMError, match="PHANTOM_TEST_KEY"):
        make_llm("openai-compatible", "m", "http://x/v1", "PHANTOM_TEST_KEY")
    monkeypatch.setenv("PHANTOM_TEST_KEY", "k")
    built = make_llm("openai-compatible", "m", "http://x/v1", "PHANTOM_TEST_KEY")
    assert isinstance(built, OpenAICompatLLM) and built.api_key == "k"
    assert make_llm("openai-compatible", "m", "http://x/v1").api_key is None


def test_openai_compat_redacts_url_and_key(monkeypatch):
    from phantom_redteam.llm import redact_url

    assert redact_url("http://user:pw@host:1/v1?key=x#f") == "http://host:1/v1"
    url = "http://user:pw123@local.test/v1?key=qsecret"
    model = OpenAICompatLLM(
        "m", url, api_key="KEYVALUE", transport=httpx.MockTransport(_connect_error)
    )
    assert "KEYVALUE" not in model.name
    with pytest.raises(LLMError) as err:
        model.complete_json("s", "p", SCHEMA)
    for secret in ("pw123", "qsecret", "KEYVALUE"):
        assert secret not in str(err.value)
    assert "http://local.test/v1" in str(err.value)

    monkeypatch.setenv("PHANTOM_TEST_KEY", "KEYVALUE")
    bad = OpenAICompatLLM(
        "m", url, api_key="KEYVALUE",
        transport=httpx.MockTransport(lambda r: httpx.Response(500, text="boom")),
    )
    with pytest.raises(LLMError) as err2:
        bad.complete_json("s", "p", SCHEMA)
    assert "KEYVALUE" not in str(err2.value)


def test_openai_compat_invalid_url_is_llm_error():
    model = OpenAICompatLLM(
        "m", "http://exa mple.com:bad/v1", transport=httpx.MockTransport(lambda r: httpx.Response(200))
    )
    with pytest.raises(LLMError):
        model.complete_json("s", "p", SCHEMA)


@pytest.mark.parametrize("url", ["ftp://x/v1", "localhost:11434/v1", "http:///v1", "http://h:99999999/v1"])
def test_make_llm_rejects_bad_base_url(url):
    with pytest.raises(LLMError, match="http"):
        make_llm("openai-compatible", "m", url)


def test_provider_error_body_truncated_and_key_masked():
    body = "bad key sk-abcdef123456789 " + "x" * 500
    model = OpenAICompatLLM(
        "m", "http://local.test/v1", transport=httpx.MockTransport(lambda r: httpx.Response(401, text=body))
    )
    with pytest.raises(LLMError) as err:
        model.complete_json("s", "p", SCHEMA)
    msg = str(err.value)
    assert "abcdef123456789" not in msg
    assert "sk-…" in msg
    assert len(msg) < 160
