"""LLM backends used by the AI attacker and judge.

Three backends sit behind one `LLM` protocol: the locally logged-in Claude Code CLI
(locked down so injected text cannot run anything), the Anthropic API, and any
OpenAI-compatible chat endpoint (Ollama, LM Studio, other providers).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Literal, Protocol

import httpx
from urllib.parse import urlsplit, urlunsplit

DEFAULT_CLI_MODEL = "sonnet"
DEFAULT_API_MODEL = "claude-sonnet-5-5"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:-]+$")
# On Windows the claude shim is a .cmd file, so cmd.exe re-parses argv: these characters
# can expand variables, chain commands or truncate arguments. Refuse them rather than guess.
_CMD_UNSAFE = set("%^&|<>\r\n")

_workdir: list[str] = []  # one empty temp dir per process, created on first use


class LLMError(RuntimeError):
    pass


class LLM(Protocol):
    name: str

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict: ...


def find_claude() -> str | None:
    return shutil.which("claude") or shutil.which("claude.cmd")


def _empty_workdir() -> str:
    if not _workdir:
        _workdir.append(tempfile.mkdtemp(prefix="phantom-cli-"))
    return _workdir[0]


def run_claude_cli(
    system: str, prompt: str, schema: dict, model: str, timeout: float = 240
) -> dict:
    exe = find_claude()
    if exe is None:
        raise LLMError("claude executable not found on PATH")
    if not _SAFE_NAME.match(model):
        raise LLMError(f"unsafe model name: {model!r}")
    try:
        schema_json = json.dumps(schema)
    except (TypeError, ValueError) as exc:
        raise LLMError(f"schema is not JSON-serializable: {exc}") from exc
    argv = [
        exe, "-p",
        "--model", model,
        "--tools", "",
        "--strict-mcp-config",
        "--no-session-persistence",
        "--setting-sources", "",
        "--system-prompt", system,
        "--json-schema", schema_json,
        "--output-format", "json",
    ]
    if exe.lower().endswith((".cmd", ".bat")):
        for arg in argv[1:]:
            if _CMD_UNSAFE & set(arg):
                raise LLMError("argument contains characters unsafe for a .cmd shim")
    try:
        proc = subprocess.run(
            argv,
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=_empty_workdir(),
        )
    except subprocess.TimeoutExpired as exc:
        raise LLMError(f"claude timed out after {timeout}s") from exc
    except OSError as exc:
        raise LLMError(f"could not run claude: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()[:200]
        raise LLMError(f"claude exited with code {proc.returncode}: {detail}")
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise LLMError("claude output was not valid JSON") from exc
    if not isinstance(result, dict):
        raise LLMError("claude output was not a JSON object")
    if result.get("is_error"):
        raise LLMError(f"claude reported an error: {str(result.get('result'))[:200]}")
    structured = result.get("structured_output")
    if not isinstance(structured, dict):
        raise LLMError("claude output had no structured_output")
    return structured


class ClaudeCliLLM:
    def __init__(self, model: str = DEFAULT_CLI_MODEL):
        self.model = model
        self.name = f"claude-cli:{model}"

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
        return run_claude_cli(system, prompt, schema, self.model)


def _field(block, key: str):
    if isinstance(block, dict):
        return block.get(key)
    return getattr(block, key, None)


class AnthropicLLM:
    def __init__(self, model: str = DEFAULT_API_MODEL, client=None):
        self.model = model
        self.name = f"anthropic:{model}"
        self._client = client

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise LLMError("install phantom-redteam[ai]") from exc
            except Exception as exc:
                raise LLMError(f"could not import anthropic: {exc}") from exc
            try:
                self._client = anthropic.Anthropic()
            except Exception as exc:
                raise LLMError(f"could not create Anthropic client: {exc}") from exc
        return self._client

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
        client = self._get_client()
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": prompt}],
                tools=[
                    {"name": "respond", "description": "Return the answer", "input_schema": schema}
                ],
                tool_choice={"type": "tool", "name": "respond"},
            )
        except Exception as exc:  # SDK raises many error types; all map to LLMError
            raise LLMError(f"Anthropic API error: {exc}") from exc
        for block in getattr(response, "content", None) or []:
            if _field(block, "type") == "tool_use":
                data = _field(block, "input")
                if isinstance(data, dict):
                    return data
        raise LLMError("Anthropic response had no tool_use block")


_KEY_LIKE = re.compile(r"\b(sk|key)-[A-Za-z0-9_-]{6,}")
_ERROR_BODY_CHARS = 120


def _mask_keys(text: str) -> str:
    return _KEY_LIKE.sub(lambda m: f"{m.group(1)}-…", text)


def _short_body(text: str) -> str:
    """A provider error body, truncated and with anything key-shaped masked."""
    return _mask_keys(text[:_ERROR_BODY_CHARS * 2])[:_ERROR_BODY_CHARS]


_FENCE = re.compile(r"^```[A-Za-z0-9_-]*\s*\n(.*?)\n?```$", re.DOTALL)


def redact_url(url: str) -> str:
    """Drop userinfo, query and fragment so secrets in a URL never reach output."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = host + (f":{parts.port}" if parts.port else "")
    except ValueError:
        return "<unparseable url>"
    if not parts.scheme or not netloc:
        return "<unparseable url>"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


class OpenAICompatLLM:
    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 240,
        transport: httpx.BaseTransport | None = None,
    ):
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.transport = transport
        self.name = f"openai-compatible:{model}"

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system
                    + "\nRespond with a single JSON object that matches this JSON Schema: "
                    + json.dumps(schema),
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.9,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                response = client.post(url, json=body, headers=headers)
        except httpx.InvalidURL as exc:
            raise LLMError(f"invalid base URL {redact_url(self.base_url)}: {exc}") from exc
        except httpx.HTTPError as exc:
            detail = str(exc).replace(self.base_url, redact_url(self.base_url))
            raise LLMError(f"could not reach {redact_url(self.base_url)}: {detail}") from exc
        if not response.is_success:
            raise LLMError(f"HTTP {response.status_code}: {_short_body(response.text)}")
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("response had no choices[0].message.content") from exc
        if not isinstance(content, str):
            raise LLMError("response content was not text")
        text = content.strip()
        fenced = _FENCE.match(text)
        if fenced:
            text = fenced.group(1)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError("model output was not valid JSON") from exc
        if not isinstance(data, dict):
            raise LLMError("model output was not a JSON object")
        return data


def make_llm(
    backend: Literal["auto", "claude-cli", "anthropic", "openai-compatible"],
    model: str | None,
    base_url: str | None = None,
    api_key_env: str | None = None,
) -> LLM:
    if backend == "openai-compatible":
        if not model or not base_url:
            raise LLMError("openai-compatible needs --attacker-model and --base-url")
        try:
            parts = urlsplit(base_url)
            valid = parts.scheme in ("http", "https") and bool(parts.hostname)
            parts.port  # noqa: B018 - raises ValueError on a bad port
        except ValueError:
            valid = False
        if not valid:
            raise LLMError("--base-url must be an http(s) URL with a host")
        api_key = None
        if api_key_env:
            api_key = os.environ.get(api_key_env)
            if not api_key:
                raise LLMError(f"environment variable {api_key_env} is not set")
        return OpenAICompatLLM(model, base_url, api_key)
    if backend == "auto":
        if os.environ.get("ANTHROPIC_API_KEY"):
            backend = "anthropic"
        elif find_claude():
            backend = "claude-cli"
        else:
            raise LLMError("No LLM backend: install the Claude Code CLI or set ANTHROPIC_API_KEY")
    if backend == "anthropic":
        return AnthropicLLM(model or DEFAULT_API_MODEL)
    if backend == "claude-cli":
        return ClaudeCliLLM(model or DEFAULT_CLI_MODEL)
    raise LLMError(f"unknown backend: {backend!r}")
