"""Terminal report for an attack campaign: a table per seed, then the totals."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from phantom_redteam.campaign import CampaignResult
from phantom_redteam.report.attack_json import declined_attempts, focus_attempt
from phantom_redteam.report.terminal import _encodable, is_utf8

_STYLE = {
    "confirmed": "red",
    "partial": "yellow",
    "resisted": "green",
    "error": "dim",
    "declined": "dim",
    "invalid": "dim",
}
_EXPLANATION_LIMIT = 80


def _truncate(text: str, ascii_only: bool) -> str:
    text = " ".join(text.split())
    if len(text) <= _EXPLANATION_LIMIT:
        return text
    return text[: _EXPLANATION_LIMIT - 3] + ("..." if ascii_only else "…")


def print_campaign(result: CampaignResult, console: Console) -> None:
    utf8 = is_utf8(console)
    table = Table(box=box.HEAVY_HEAD if utf8 else box.ASCII)
    for column in ("Seed", "Best", "Rounds", "Winning tactic", "Judge explanation"):
        table.add_column(column, no_wrap=column == "Seed", overflow="fold")
    dash = "–" if utf8 else "-"
    for s in result.seeds:
        focus = focus_attempt(s)
        rounds = max((a.round for a in s.attempts), default=0)
        tactic = s.winner.tactic if s.winner else dash
        explanation = ""
        if focus is not None:
            explanation = (
                focus.verdict.explanation
                if focus.verdict is not None
                else focus.invalid_reason or focus.llm_error or ""
            )
        table.add_row(
            Text(_encodable(s.seed.id, console)),
            Text(s.best_status.upper(), style=_STYLE[s.best_status]),
            str(rounds),
            Text(_encodable(tactic, console)),
            Text(_encodable(_truncate(explanation, not utf8), console)),
        )
    console.print(table)
    declined = declined_attempts(result)
    declined_note = f", {declined} declined" if declined else ""
    console.print(
        f"Vulnerabilities: {result.confirmed} confirmed, {result.partial} partial"
        f"{declined_note} across {len(result.seeds)} seeds"
    )
    console.print(f"LLM calls: {result.llm_calls}  Wall time: {result.wall_s:.1f}s")
    if result.aborted:
        console.print(Text(f"aborted: {_encodable(result.aborted, console)}", style="red"))
