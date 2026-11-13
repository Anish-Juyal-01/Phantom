"""The `kestrel` command line."""

from __future__ import annotations

import asyncio
import re
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import httpx
import typer
import yaml
from rich import box
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from kestrel_redteam import __version__
from kestrel_redteam.agent_client import AgentClient
from kestrel_redteam.lure import LURE_AGENT_NAME, LURE_URL, lure_transport
from kestrel_redteam.report import RunMeta, json_out
from kestrel_redteam.report import html as html_report
from kestrel_redteam.report.terminal import is_utf8, print_report
from kestrel_redteam.results import ScenarioResult, summarize
from kestrel_redteam.runner import RunConfig, run_suite
from kestrel_redteam.scenarios import (
    CATEGORY_ORDER,
    ScenarioError,
    TemplateVars,
    load_scenarios,
    new_template_vars,
)

app = typer.Typer(help="Test AI agents for prompt injection.", no_args_is_help=True)

# Test hooks: let CLI tests drive scripted agents with known template values.
_transport_override: httpx.AsyncBaseTransport | None = None
_vars_factory_override: Callable[[], TemplateVars] | None = None

console = Console()


def _tolerate_unencodable_output() -> None:
    """Never let an unencodable character in agent text crash the run."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except Exception:  # noqa: BLE001 - best effort only
                pass


def _fail(message: str) -> typer.Exit:
    console.print(message, markup=False, highlight=False)
    return typer.Exit(2)


def _load(extra_dirs: list[Path], include_builtin: bool = True):
    try:
        return load_scenarios(extra_dirs, include_builtin=include_builtin)
    except ScenarioError as exc:
        for problem in exc.problems:
            console.print(problem, markup=False, highlight=False)
        raise typer.Exit(2) from exc


_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _parse_headers(headers: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in headers:
        name, sep, value = raw.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not name:
            raise _fail(f'Invalid --header "{raw}": expected "Name: value"')
        if not _HEADER_NAME.fullmatch(name):
            raise _fail(f'Invalid --header "{raw}": illegal character in the header name')
        if not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise _fail(f'Invalid --header "{raw}": the value must be printable ASCII')
        parsed[name] = value
    return parsed


@app.command()
def run(
    agent: str = typer.Option(
        ...,
        "--agent",
        help="URL of the agent under test, or 'lure' for the built-in positive-control agent.",
    ),
    suite: list[str] | None = typer.Option(None, "--suite", help="Run one category (repeatable)."),
    scenario: list[str] | None = typer.Option(None, "--scenario", help="Run a scenario id (repeatable)."),
    scenarios: list[Path] | None = typer.Option(None, "--scenarios", help="Add a directory of custom scenarios."),
    repeat: int = typer.Option(1, "--repeat", help="Runs per scenario."),
    concurrency: int = typer.Option(4, "--concurrency", help="Parallel scenarios."),
    timeout: float = typer.Option(60.0, "--timeout", help="Seconds per agent request."),
    max_steps: int = typer.Option(8, "--max-steps", help="Agent replies per scenario."),
    header: list[str] | None = typer.Option(None, "--header", help='Extra HTTP header, "K: V" (repeatable).'),
    report: Path | None = typer.Option(None, "--report", help="Write the HTML report."),
    json_path: Path | None = typer.Option(None, "--json", help="Write JSON results."),
    fail_under: float | None = typer.Option(None, "--fail-under", help="Exit 1 if the safety score is below this percent."),
) -> None:
    """Run the scenarios against an agent."""
    _tolerate_unencodable_output()
    use_lure = agent.lower() == LURE_AGENT_NAME
    if use_lure:
        agent = LURE_AGENT_NAME
    elif not agent.startswith(("http://", "https://")):
        raise _fail("Agent URL must start with http:// or https://")
    for flag, value in (("--repeat", repeat), ("--concurrency", concurrency), ("--max-steps", max_steps)):
        if value < 1:
            raise _fail(f"{flag} must be at least 1")
    if timeout <= 0:
        raise _fail("--timeout must be greater than 0")
    headers = _parse_headers(header or [])

    selected = _load(scenarios or [])
    known_scenarios = selected
    if suite:
        unknown = [s for s in suite if s not in CATEGORY_ORDER]
        if unknown:
            raise _fail(
                f"Unknown suite: {', '.join(unknown)}. Valid suites: {', '.join(CATEGORY_ORDER)}"
            )
        selected = [s for s in selected if s.category in suite]
    if scenario:
        known = {s.id for s in selected}
        unknown = [s for s in scenario if s not in known]
        if unknown:
            raise _fail(f"Unknown scenario: {', '.join(unknown)}. Run `kestrel list` to see ids.")
        selected = [s for s in selected if s.id in scenario]
    if not selected:
        raise _fail("No scenarios selected.")

    config = RunConfig(repeat=repeat, concurrency=concurrency, max_steps=max_steps)
    meta = RunMeta(
        kestrel_version=__version__,
        agent_url=agent,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        options={
            "repeat": repeat,
            "concurrency": concurrency,
            "timeout": timeout,
            "max_steps": max_steps,
            "suites": suite or [],
            "scenarios": scenario or [],
        },
    )

    progress = Progress(
        TextColumn("[bold]Running"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("scenarios"),
        console=console,
        transient=True,
    )
    task = progress.add_task("run", total=len(selected))

    def on_result(_: ScenarioResult) -> None:
        progress.advance(task)

    transport = _transport_override
    client_url = agent
    if use_lure:
        client_url = LURE_URL
        if transport is None:
            transport = lure_transport(known_scenarios)

    async def go() -> list[ScenarioResult]:
        async with AgentClient(
            client_url, headers=headers, timeout=timeout, transport=transport
        ) as client:
            return await run_suite(
                client,
                selected,
                config,
                on_result=on_result,
                vars_factory=_vars_factory_override or new_template_vars,
            )

    with progress:
        results = asyncio.run(go())

    runs = [r for res in results for r in res.runs]
    if all(r.error_kind == "unreachable" for r in runs):
        raise _fail(f"Could not reach agent at {agent}")

    summary = summarize(results)
    try:
        if report is not None:
            html_report.write(report, html_report.render(results, summary, meta))
        if json_path is not None:
            json_out.write(json_path, json_out.build(results, summary, meta))
    except OSError as exc:
        raise _fail(f"Could not write report: {exc}") from exc

    print_report(results, summary, console)
    if report is not None:
        console.print(f"HTML report: {report}", markup=False, highlight=False)
    if json_path is not None:
        console.print(f"JSON results: {json_path}", markup=False, highlight=False)

    if fail_under is not None and summary.safety_score < fail_under:
        raise typer.Exit(1)


@app.command("list")
def list_cmd(
    scenarios: list[Path] | None = typer.Option(None, "--scenarios", help="Add a directory of custom scenarios."),
) -> None:
    """List scenarios with id, category and severity."""
    loaded = _load(scenarios or [])
    table = Table(title=f"{len(loaded)} scenarios", box=box.ROUNDED if is_utf8(console) else box.ASCII)
    for col in ("id", "category", "severity"):
        table.add_column(col, no_wrap=True)
    table.add_column("name")
    for s in loaded:
        table.add_row(Text(s.id), Text(s.category), Text(s.severity), Text(s.name))
    console.print(table)


@app.command()
def validate(
    directory: Path = typer.Argument(..., help="Directory of custom scenario YAML files."),
) -> None:
    """Check custom scenario files and report errors."""
    problems: list[str] = []
    loaded = []
    try:
        loaded = load_scenarios([directory], include_builtin=False)
    except ScenarioError as exc:
        problems.extend(exc.problems)
    builtin_ids = {s.id for s in _load([])}
    if directory.is_dir():
        for f in sorted(p for p in directory.iterdir() if p.suffix in (".yaml", ".yml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError, UnicodeDecodeError):
                continue  # already reported by the loader
            if (
                isinstance(data, dict)
                and isinstance(data.get("id"), str)
                and data["id"] in builtin_ids
            ):
                problems.append(f"{f.name}: id '{data['id']}' clashes with a built-in scenario")
    if problems:
        for problem in problems:
            console.print(problem, markup=False, highlight=False)
        raise typer.Exit(2)
    console.print(f"OK: {len(loaded)} scenarios", markup=False, highlight=False)
