"""Self-contained HTML report rendered with Jinja2 (autoescape on)."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Any

from jinja2 import Environment
from markupsafe import Markup, escape

from phantom_redteam.report import RunMeta
from phantom_redteam.results import ScenarioResult, Summary
from phantom_redteam.scenarios import CATEGORY_ORDER

_VAR_KEYS = ("canary", "attacker_email", "attacker_url", "secret")
_EVIDENCE_LIMIT = 200


def highlight(text: str | None, vars: dict[str, str] | None) -> Markup:
    """Escape `text`, then wrap the run's canary/email/URL/secret in <mark>."""
    escaped = str(escape(text or ""))
    values = sorted(
        {str(escape(vars[k])) for k in _VAR_KEYS if vars and vars.get(k)}, key=len, reverse=True
    )
    if values:
        pattern = re.compile("|".join(re.escape(v) for v in values))
        escaped = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", escaped)
    return Markup(escaped)


def _render_call(name: str, arguments: dict[str, Any]) -> str:
    # Must match grader._render so breach evidence can be located.
    return f"{name}({json.dumps(arguments, default=str)})"


def _blocks(run) -> list[dict[str, Any]]:
    evidence = {m.evidence for m in run.matches}
    blocks: list[dict[str, Any]] = []
    for m in run.messages:
        if m.role == "user":
            blocks.append({"kind": "user", "text": m.content or ""})
        elif m.role == "tool":
            blocks.append({"kind": "tool-result", "text": m.content or ""})
        else:
            if m.content:
                blocks.append(
                    {
                        "kind": "assistant",
                        "text": m.content,
                        "breach": m.content[:_EVIDENCE_LIMIT] in evidence,
                    }
                )
            for call in m.tool_calls or []:
                blocks.append(
                    {
                        "kind": "tool-call",
                        "name": call.name,
                        "text": json.dumps(call.arguments, indent=2, ensure_ascii=False, default=str),
                        "breach": _render_call(call.name, call.arguments) in evidence,
                    }
                )
    return blocks


def _env() -> Environment:
    env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    env.filters["highlight"] = highlight
    return env


def render(results: list[ScenarioResult], summary: Summary, meta: RunMeta) -> str:
    source = (resources.files("phantom_redteam.report") / "template.html").read_text(
        encoding="utf-8"
    )
    categories = [c for c in CATEGORY_ORDER if c in summary.by_category] + [
        c for c in summary.by_category if c not in CATEGORY_ORDER
    ]
    scenarios = [
        {
            "result": r,
            "runs": [{"run": run, "blocks": _blocks(run)} for run in r.runs],
        }
        for r in results
    ]
    return _env().from_string(source).render(
        meta=meta,
        summary=summary,
        scenarios=scenarios,
        categories=[(c, summary.by_category[c]) for c in categories],
    )


def write(path: Path, html_text: str) -> None:
    Path(path).write_text(html_text, encoding="utf-8")
