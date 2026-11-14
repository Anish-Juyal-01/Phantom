"""Drives the agent under test through a scenario and grades the run."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass

from phantom_redteam.agent_client import AgentClient, AgentError
from phantom_redteam.grader import check_breach, check_utility
from phantom_redteam.protocol import AgentRequest, Message
from phantom_redteam.results import RunOutcome, ScenarioResult
from phantom_redteam.scenarios import Scenario, TemplateVars, fill, new_template_vars
from phantom_redteam.tools import execute_tool, tool_specs


@dataclass
class RunConfig:
    repeat: int = 1
    concurrency: int = 4
    max_steps: int = 8


async def run_scenario_once(
    client: AgentClient,
    scenario: Scenario,
    max_steps: int,
    vars: TemplateVars | None = None,
) -> RunOutcome:
    vars = vars or new_template_vars()
    filled = fill(scenario, vars)
    specs = tool_specs(filled.tools)
    messages = [Message(role="user", content=filled.user)]
    final_output: str | None = None
    error: str | None = None
    error_kind: str | None = None
    call_counter = 0
    start = time.monotonic()

    try:
        for _ in range(max_steps):
            response = await client.step(AgentRequest(messages=messages, tools=specs))
            messages.append(
                Message(
                    role="assistant",
                    content=response.content,
                    tool_calls=response.tool_calls or None,
                )
            )
            if response.is_final:
                final_output = response.content or ""
                break
            for call in response.tool_calls:
                call_counter += 1
                if call.id is None:
                    call.id = f"call_{call_counter}"
                if call.name not in filled.tools:
                    error = f"Agent called unknown tool '{call.name}'"
                    error_kind = "protocol"
                    break
                messages.append(
                    Message(
                        role="tool",
                        content=execute_tool(call.name, call.arguments, filled.fixtures),
                        tool_call_id=call.id,
                    )
                )
            if error is not None:
                break
    except AgentError as exc:
        error, error_kind = exc.message, exc.kind

    matches = check_breach(filled, messages, final_output)
    if matches:
        status = "breached"
    elif error is not None:
        status = "error"
    else:
        status = "resisted"
    return RunOutcome(
        status=status,
        messages=messages,
        final_output=final_output,
        matches=matches,
        utility=check_utility(filled, final_output) if error is None else None,
        error=error,
        error_kind=error_kind,
        duration_s=time.monotonic() - start,
        vars=asdict(vars),
    )


async def run_suite(
    client: AgentClient,
    scenarios: list[Scenario],
    config: RunConfig,
    on_result: Callable[[ScenarioResult], None] | None = None,
    vars_factory: Callable[[], TemplateVars] = new_template_vars,
) -> list[ScenarioResult]:
    semaphore = asyncio.Semaphore(config.concurrency)

    async def one_run(scenario: Scenario) -> RunOutcome:
        async with semaphore:
            return await run_scenario_once(client, scenario, config.max_steps, vars_factory())

    async def one_scenario(scenario: Scenario) -> ScenarioResult:
        runs = await asyncio.gather(*(one_run(scenario) for _ in range(config.repeat)))
        result = ScenarioResult(scenario=scenario, runs=list(runs))
        if on_result is not None:
            on_result(result)
        return result

    return list(await asyncio.gather(*(one_scenario(s) for s in scenarios)))
