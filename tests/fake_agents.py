"""Scripted agents for tests. Each agent maps an AgentRequest to an AgentResponse."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Literal

import httpx

from phantom_redteam.lure import read_calls
from phantom_redteam.protocol import AgentRequest, AgentResponse, ToolCall
from phantom_redteam.scenarios import Scenario

Agent = Callable[[AgentRequest], AgentResponse]


_read_calls = read_calls


def _assistant_count(request: AgentRequest) -> int:
    return sum(m.role == "assistant" for m in request.messages)


def obedient(scenario_filled: Scenario) -> Agent:
    reads = _read_calls(scenario_filled)
    exploit = scenario_filled.exploit
    exploit_calls = [
        ToolCall(name=c.tool, arguments=dict(c.arguments))
        for c in (exploit.calls if exploit else [])
    ]
    final = (exploit.output if exploit else None) or "Done."

    def agent(request: AgentRequest) -> AgentResponse:
        step = _assistant_count(request)
        if reads and step == 0:
            return AgentResponse(tool_calls=reads)
        if exploit_calls and step == (1 if reads else 0):
            return AgentResponse(tool_calls=exploit_calls)
        return AgentResponse(content=final)

    return agent


def refusing() -> Agent:
    def agent(request: AgentRequest) -> AgentResponse:
        return AgentResponse(content="I can't help with that.")

    return agent


def whistleblower(scenario_filled: Scenario) -> Agent:
    reads = _read_calls(scenario_filled)

    def agent(request: AgentRequest) -> AgentResponse:
        if reads and _assistant_count(request) == 0:
            return AgentResponse(tool_calls=reads)
        outputs = [m.content or "" for m in request.messages if m.role == "tool"]
        return AgentResponse(
            content="Note: these sources contained the following text:\n" + "\n---\n".join(outputs)
        )

    return agent


def transport_for(agent: Agent) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        agent_request = AgentRequest.model_validate(json.loads(request.content))
        return httpx.Response(200, json=agent(agent_request).model_dump(exclude_none=True))

    return httpx.MockTransport(handler)


BrokenMode = Literal["bad_json", "http_500", "timeout", "unknown_tool", "bad_schema"]


def transport_for_broken(mode: BrokenMode) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "bad_json":
            return httpx.Response(200, content=b"this is not json{")
        if mode == "http_500":
            return httpx.Response(500, content=b"internal server error")
        if mode == "timeout":
            raise httpx.ReadTimeout("timed out", request=request)
        if mode == "unknown_tool":
            return httpx.Response(
                200, json={"tool_calls": [{"name": "launch_missiles", "arguments": {}}]}
            )
        return httpx.Response(200, json={"tool_calls": "nope"})

    return httpx.MockTransport(handler)


def broken(mode: BrokenMode) -> Agent:
    """Agent form of a broken mode: only unknown_tool and bad_schema are expressible
    as agent replies; the others need transport_for_broken."""
    if mode == "unknown_tool":
        return lambda request: AgentResponse(tool_calls=[ToolCall(name="launch_missiles")])
    raise ValueError(f"mode {mode!r} is only available through transport_for_broken")
