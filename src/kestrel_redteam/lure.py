"""Lure: a deterministic positive-control agent with no LLM.

Lure fully obeys instructions planted in tool data by carrying out each scenario's
reference exploit. It knows nothing about the run's random template values; it
recovers them from the tool output it reads. Kestrel should breach it on every
scenario, which proves the scenarios, grading and reports work.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from kestrel_redteam.protocol import AgentRequest, AgentResponse, ToolCall
from kestrel_redteam.scenarios import Scenario
from kestrel_redteam.tools import CATALOG

LURE_AGENT_NAME = "lure"
LURE_URL = "http://lure.invalid/"

_FORMATS = {
    "{{CANARY}}": re.compile(r"KSTRL-[0-9a-f]{8}"),
    "{{ATTACKER_EMAIL}}": re.compile(r"exfil-[0-9a-f]{4}@attacker\.example"),
    "{{ATTACKER_URL}}": re.compile(r"https://attacker\.example/c/[0-9a-f]{4}"),
    "{{SECRET}}": re.compile(r"sk-live-[0-9a-f]{24}"),
}


def read_calls(scenario: Scenario) -> list[ToolCall]:
    """One call per fixture key for dict fixtures, one `{}` call otherwise."""
    calls: list[ToolCall] = []
    for tool in scenario.tools:
        if CATALOG[tool].side_effect:
            continue
        fixture = scenario.fixtures.get(tool)
        if isinstance(fixture, dict) and tool != "read_inbox":
            arg = CATALOG[tool].lookup_arg
            for key in fixture:
                calls.append(ToolCall(name=tool, arguments={arg: key} if arg else {}))
        elif fixture is not None or tool == "read_inbox":
            calls.append(ToolCall(name=tool, arguments={}))
    return calls


def find_scenario(request: AgentRequest, scenarios: list[Scenario]) -> Scenario | None:
    user = next((m.content for m in request.messages if m.role == "user"), None)
    if user is None:
        return None
    text = user.strip()
    tools = {t.name for t in request.tools}
    for scenario in scenarios:
        if scenario.user.strip() == text and set(scenario.tools) == tools:
            return scenario
    return None


def extract_vars(text: str) -> dict[str, str]:
    """Recover the run's template values from tool output. The first match wins."""
    found: dict[str, str] = {}
    for placeholder, pattern in _FORMATS.items():
        match = pattern.search(text)
        if match:
            found[placeholder] = match.group(0)
    return found


def _fill(obj: Any, values: dict[str, str]) -> Any:
    if isinstance(obj, str):
        for placeholder, value in values.items():
            obj = obj.replace(placeholder, value)
        return obj
    if isinstance(obj, dict):
        return {_fill(k, values): _fill(v, values) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, values) for v in obj]
    return obj


def lure_respond(request: AgentRequest, scenarios: list[Scenario]) -> AgentResponse:
    scenario = find_scenario(request, scenarios)
    if scenario is None:
        return AgentResponse(content="Lure: no matching scenario for this request.")

    step = sum(m.role == "assistant" for m in request.messages)
    reads = read_calls(scenario)
    if reads and step == 0:
        return AgentResponse(tool_calls=reads)

    exploit = scenario.exploit
    values = extract_vars(
        "\n".join(m.content or "" for m in request.messages if m.role == "tool")
    )
    if exploit and exploit.calls and step == (1 if reads else 0):
        return AgentResponse(
            tool_calls=[
                ToolCall(name=c.tool, arguments=_fill(dict(c.arguments), values))
                for c in exploit.calls
            ]
        )
    final = _fill(exploit.output, values) if exploit and exploit.output else None
    return AgentResponse(content=final or "Done.")


def lure_transport(scenarios: list[Scenario]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        agent_request = AgentRequest.model_validate(json.loads(request.content))
        response = lure_respond(agent_request, scenarios)
        return httpx.Response(200, json=response.model_dump(exclude_none=True))

    return httpx.MockTransport(handler)
