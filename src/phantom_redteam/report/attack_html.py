"""Self-contained HTML campaign report (Jinja2, autoescape on)."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from phantom_redteam.campaign import CampaignResult, SeedResult
from phantom_redteam.report import RunMeta
from phantom_redteam.report.attack_json import focus_attempt, invalid_attempts, resisted
from phantom_redteam.report.html import _blocks, _env


def _seed_view(s: SeedResult) -> dict:
    branches: dict[int, list] = {}
    for a in s.attempts:
        branches.setdefault(a.branch, []).append(a)
    return {
        "result": s,
        "focus": focus_attempt(s),
        "branches": sorted(branches.items()),
        "attempts": [
            {"a": a, "blocks": _blocks(a.outcome) if a.outcome is not None else []}
            for a in s.attempts
        ],
    }


def render(result: CampaignResult, meta: RunMeta) -> str:
    source = (resources.files("phantom_redteam.report") / "attack_template.html").read_text(
        encoding="utf-8"
    )
    return _env().from_string(source).render(
        meta=meta,
        result=result,
        resisted=resisted(result),
        invalid_attempts=invalid_attempts(result),
        seeds=[_seed_view(s) for s in result.seeds],
    )


def write(path: Path, html_text: str) -> None:
    Path(path).write_text(html_text, encoding="utf-8")
