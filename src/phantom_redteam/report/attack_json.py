"""Campaign JSON report (schema version 2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phantom_redteam.campaign import Attempt, CampaignResult, SeedResult
from phantom_redteam.report import RunMeta

SCHEMA_VERSION = 2


def focus_attempt(seed: SeedResult) -> Attempt | None:
    """The attempt a report should explain: the winner, else the last judged, else the last."""
    if seed.winner is not None:
        return seed.winner
    judged = [a for a in seed.attempts if a.verdict is not None]
    if judged:
        return judged[-1]
    return seed.attempts[-1] if seed.attempts else None


def invalid_attempts(result: CampaignResult) -> int:
    return sum(1 for s in result.seeds for a in s.attempts if a.final_status == "invalid")


def declined_attempts(result: CampaignResult) -> int:
    return sum(1 for s in result.seeds for a in s.attempts if a.final_status == "declined")


def resisted(result: CampaignResult) -> int:
    return sum(1 for s in result.seeds if s.best_status == "resisted")


def _attempt(a: Attempt) -> dict[str, Any]:
    data = a.model_dump(mode="json", exclude={"outcome"})
    outcome = a.outcome
    data["outcome"] = outcome.model_dump(mode="json", exclude={"messages"}) if outcome else None
    data["transcript"] = (
        [m.model_dump(mode="json", exclude_none=True) for m in outcome.messages] if outcome else []
    )
    return data


def build(result: CampaignResult, meta: RunMeta) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "campaign",
        "phantom_version": meta.phantom_version,
        "agent_url": meta.agent_url,
        "started_at": meta.started_at,
        "options": meta.options,
        "attacker_llm": result.attacker_llm,
        "judge_llm": result.judge_llm,
        "totals": {
            "seeds": len(result.seeds),
            "confirmed": result.confirmed,
            "partial": result.partial,
            "resisted": resisted(result),
            "invalid_attempts": invalid_attempts(result),
            "declined_attempts": declined_attempts(result),
            "llm_calls": result.llm_calls,
            "wall_s": result.wall_s,
            "aborted": result.aborted,
        },
        "seeds": [
            {
                "id": s.seed.id,
                "name": s.seed.name,
                "category": s.seed.category,
                "best_status": s.best_status,
                "winner": _attempt(s.winner) if s.winner else None,
                "attempts": [_attempt(a) for a in s.attempts],
            }
            for s in result.seeds
        ],
    }


def write(path: Path, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
