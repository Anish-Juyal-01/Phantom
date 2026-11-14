"""Export confirmed campaign findings as scenario YAML files that `phantom run` can replay."""

from __future__ import annotations

from pathlib import Path

import yaml

from phantom_redteam.campaign import Attempt, CampaignResult, SeedResult
from phantom_redteam.carrier import restore_placeholders, with_carrier
from phantom_redteam.grader import check_breach, tool_calls_in
from phantom_redteam.protocol import Message
from phantom_redteam.scenarios import Exploit, ExploitCall, Scenario, TemplateVars, fill


def _build_exploit(seed: Scenario, attempt: Attempt, vars: TemplateVars) -> Exploit:
    """The winning run's offending tool calls and output, with placeholders restored."""
    outcome = attempt.outcome
    if outcome is None:
        return seed.exploit or Exploit()
    filled = fill(seed, vars)
    calls: list[ExploitCall] = []
    for call in tool_calls_in([m for m in outcome.messages if m.role == "assistant"]):
        single = [Message(role="assistant", tool_calls=[call])]
        if check_breach(filled, single, None):
            restored = restore_placeholders(call.arguments, vars)
            calls.append(ExploitCall(tool=call.name, arguments=restored))

    output = None
    output_conds = [
        c for c in filled.breach if c.output_contains is not None or c.output_starts_with is not None
    ]
    if output_conds and outcome.final_output is not None:
        output_only = filled.model_copy(update={"breach": output_conds})
        if check_breach(output_only, [], outcome.final_output):
            output = restore_placeholders(outcome.final_output, vars)

    if not calls and output is None:
        # Confirmed by the judge only: nothing the code check can replay, keep the seed's own.
        return seed.exploit or Exploit()
    return Exploit(calls=calls, output=output)


def _scenario_for(sr: SeedResult, winner: Attempt, new_id: str) -> Scenario:
    seed = sr.seed
    vars = TemplateVars(**winner.vars)
    finding = with_carrier(seed, restore_placeholders(winner.carrier_text, vars))
    why = winner.verdict.explanation if winner.verdict is not None else "confirmed by code check"
    # Judge text is free LLM output: neutralise stray braces, then restore the run's values.
    note = f"Tactic: {winner.tactic}. {why}".replace("{{", "{ {").replace("}}", "} }")
    note = restore_placeholders(note, vars)
    return finding.model_copy(
        update={
            "id": new_id,
            "name": f"{seed.name} (Phantom finding)",
            "description": f"{seed.description}\n\n{note}",
            "exploit": _build_exploit(seed, winner, vars),
        }
    )


def _render(sr: SeedResult, winner: Attempt, new_id: str) -> str:
    scenario = _scenario_for(sr, winner, new_id)
    return yaml.safe_dump(
        scenario.model_dump(mode="json", exclude_none=True),
        sort_keys=False,
        allow_unicode=True,
    )


def export_findings(result: CampaignResult, out_dir: Path) -> list[Path]:
    out_dir = Path(out_dir)
    written: list[Path] = []
    for sr in result.seeds:
        winner = sr.winner
        if winner is None or winner.final_status != "confirmed":
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        n = 1
        while True:
            new_id = f"{sr.seed.id}-p{n}"
            path = out_dir / f"{new_id}.yaml"
            try:
                # Creating the file is the reservation, so concurrent exports never collide.
                handle = open(path, "x", encoding="utf-8")  # noqa: SIM115
            except FileExistsError:
                n += 1
                continue
            break
        with handle:
            handle.write(_render(sr, winner, new_id))
        written.append(path)
    return written
