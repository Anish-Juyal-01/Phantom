"""Terminal report: a results table, the scores, and one dim line per error."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from kestrel_redteam.results import ScenarioResult, Summary

_STYLE = {"resisted": "green", "breached": "red", "error": "yellow"}


def _result_cell(r: ScenarioResult) -> str:
    style = _STYLE[r.status]
    label = r.status.upper()
    if r.status == "breached" and len(r.runs) > 1:
        label += f" {r.breach_runs}/{len(r.runs)}"
    return f"[{style}]{label}[/{style}]"


def is_utf8(console: Console) -> bool:
    return console.encoding.lower().replace("_", "-") in ("utf-8", "utf8")


def _encodable(text: str, console: Console) -> str:
    """Replace characters the console's encoding cannot represent."""
    return text.encode(console.encoding or "utf-8", errors="replace").decode(
        console.encoding or "utf-8", errors="replace"
    )


def _utility_cell(r: ScenarioResult, utf8: bool) -> str:
    if utf8:
        return {True: "[green]✓[/green]", False: "[red]✗[/red]", None: "–"}[r.utility]
    return {True: "[green]yes[/green]", False: "[red]no[/red]", None: "-"}[r.utility]


def print_report(results: list[ScenarioResult], summary: Summary, console: Console) -> None:
    utf8 = is_utf8(console)
    table = Table(box=box.HEAVY_HEAD if utf8 else box.ASCII)
    for column in ("Scenario", "Category", "Severity", "Result", "Utility"):
        table.add_column(column, no_wrap=column == "Scenario", overflow="fold")
    for r in results:
        table.add_row(
            Text(r.scenario.id),
            Text(r.scenario.category),
            Text(r.scenario.severity),
            _result_cell(r),
            _utility_cell(r, utf8),
        )
    console.print(table)
    console.print(
        f"Safety score: {summary.safety_score}% ({summary.resisted}/{summary.total} resisted)"
    )
    if summary.utility_score is not None:
        console.print(f"Utility score: {summary.utility_score}%")
    for r in results:
        for run in r.runs:
            if run.status == "error":
                console.print(
                    f"[dim]{escape(_encodable(r.scenario.id, console))}: "
                    f"{escape(_encodable(run.error or '', console))}[/dim]"
                )
