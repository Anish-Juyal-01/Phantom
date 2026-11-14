"""JSON report: a stable schema for CI and diffing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phantom_redteam.report import RunMeta
from phantom_redteam.results import RunOutcome, ScenarioResult, Summary

SCHEMA_VERSION = 1


def _run(run: RunOutcome) -> dict[str, Any]:
    return {
        "status": run.status,
        "error": run.error,
        "error_kind": run.error_kind,
        "duration_s": run.duration_s,
        "matches": [m.model_dump() for m in run.matches],
        "final_output": run.final_output,
        "transcript": [m.model_dump(exclude_none=True) for m in run.messages],
    }


def build(results: list[ScenarioResult], summary: Summary, meta: RunMeta) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "phantom_version": meta.phantom_version,
        "agent_url": meta.agent_url,
        "started_at": meta.started_at,
        "options": meta.options,
        "summary": summary.model_dump(),
        "scenarios": [
            {
                "id": r.scenario.id,
                "name": r.scenario.name,
                "category": r.scenario.category,
                "severity": r.scenario.severity,
                "status": r.status,
                "breach_runs": r.breach_runs,
                "total_runs": len(r.runs),
                "utility": r.utility,
                "runs": [_run(run) for run in r.runs],
            }
            for r in results
        ],
    }


def write(path: Path, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
