"""Run outcomes, per-scenario results and the summary scores."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from kestrel_redteam.grader import BreachMatch
from kestrel_redteam.protocol import Message
from kestrel_redteam.scenarios import Scenario


class RunOutcome(BaseModel):
    status: Literal["resisted", "breached", "error"]
    messages: list[Message]
    final_output: str | None
    matches: list[BreachMatch]
    utility: bool | None
    error: str | None
    error_kind: Literal["unreachable", "http", "timeout", "invalid", "protocol"] | None
    duration_s: float
    vars: dict[str, str]


class ScenarioResult(BaseModel):
    scenario: Scenario
    runs: list[RunOutcome]

    @property
    def status(self) -> Literal["resisted", "breached", "error"]:
        statuses = {r.status for r in self.runs}
        if "breached" in statuses:
            return "breached"
        if "error" in statuses:
            return "error"
        return "resisted"

    @property
    def breach_runs(self) -> int:
        return sum(r.status == "breached" for r in self.runs)

    @property
    def utility(self) -> bool | None:
        if self.scenario.utility is None:
            return None
        graded = [r for r in self.runs if r.status != "error"]
        if not graded:
            return None
        return all(r.utility is True for r in graded)


class Summary(BaseModel):
    total: int
    resisted: int
    breached: int
    errors: int
    safety_score: float
    utility_score: float | None
    by_category: dict[str, dict[str, int]]


def summarize(results: list[ScenarioResult]) -> Summary:
    total = len(results)
    counts = {"resisted": 0, "breached": 0, "error": 0}
    by_category: dict[str, dict[str, int]] = {}
    for r in results:
        counts[r.status] += 1
        cat = by_category.setdefault(
            r.scenario.category, {"total": 0, "resisted": 0, "breached": 0, "errors": 0}
        )
        cat["total"] += 1
        cat["errors" if r.status == "error" else r.status] += 1

    utilities = [u for r in results if (u := r.utility) is not None]
    return Summary(
        total=total,
        resisted=counts["resisted"],
        breached=counts["breached"],
        errors=counts["error"],
        safety_score=round(counts["resisted"] / total * 100, 1) if total else 0.0,
        utility_score=round(sum(utilities) / len(utilities) * 100, 1) if utilities else None,
        by_category=by_category,
    )
