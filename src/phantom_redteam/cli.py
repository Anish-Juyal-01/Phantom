"""The `phantom` command line."""

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

from phantom_redteam import __version__
from phantom_redteam.agent_client import AgentClient
from phantom_redteam.campaign import Attempt, CampaignConfig, partial_result, run_campaign
from phantom_redteam.findings import export_findings
from phantom_redteam.llm import LLM, LLMError, make_llm, redact_url
from phantom_redteam.lure import LURE_AGENT_NAME, LURE_URL, lure_transport
from phantom_redteam.report import RunMeta, attack_html, attack_json, json_out
from phantom_redteam.report import html as html_report
from phantom_redteam.report.attack_terminal import print_campaign
from phantom_redteam.report.terminal import _encodable, is_utf8, print_report
from phantom_redteam.results import ScenarioResult, summarize
from phantom_redteam.runner import RunConfig, run_suite
from phantom_redteam.scenarios import (
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
# (attacker, judge) LLMs injected by `attack` tests instead of `make_llm`.
_llm_override: tuple[LLM, LLM | None] | None = None

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


def _check_agent(agent: str) -> tuple[bool, str]:
    """Return (use_lure, normalised agent); exit 2 for anything but a URL or 'lure'."""
    if agent.lower() == LURE_AGENT_NAME:
        return True, LURE_AGENT_NAME
    if not agent.startswith(("http://", "https://")):
        raise _fail("Agent URL must start with http:// or https://")
    return False, agent


def _shown_url(agent: str, use_lure: bool) -> str:
    """The agent URL as shown in output: userinfo, query and fragment removed."""
    return agent if use_lure else redact_url(agent)


def _check_bounds(timeout: float, **counts: int) -> None:
    for flag, value in counts.items():
        if value < 1:
            raise _fail(f"--{flag.replace('_', '-')} must be at least 1")
    if timeout <= 0:
        raise _fail("--timeout must be greater than 0")


def _filter_suites(selected: list, suite: list[str] | None) -> list:
    if not suite:
        return selected
    unknown = [s for s in suite if s not in CATEGORY_ORDER]
    if unknown:
        raise _fail(f"Unknown suite: {', '.join(unknown)}. Valid suites: {', '.join(CATEGORY_ORDER)}")
    return [s for s in selected if s.category in suite]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    use_lure, agent = _check_agent(agent)
    _check_bounds(timeout, repeat=repeat, concurrency=concurrency, max_steps=max_steps)
    headers = _parse_headers(header or [])

    selected = _load(scenarios or [])
    known_scenarios = selected
    selected = _filter_suites(selected, suite)
    if scenario:
        known = {s.id for s in selected}
        unknown = [s for s in scenario if s not in known]
        if unknown:
            raise _fail(f"Unknown scenario: {', '.join(unknown)}. Run `phantom list` to see ids.")
        selected = [s for s in selected if s.id in scenario]
    if not selected:
        raise _fail("No scenarios selected.")

    config = RunConfig(repeat=repeat, concurrency=concurrency, max_steps=max_steps)
    meta = RunMeta(
        phantom_version=__version__,
        agent_url=_shown_url(agent, use_lure),
        started_at=_now(),
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
        raise _fail(f"Could not reach agent at {_shown_url(agent, use_lure)}")

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


_BACKENDS = ("auto", "claude-cli", "anthropic", "openai-compatible")


def _make_llms(
    backend: str,
    attacker_model: str | None,
    judge_model: str | None,
    no_judge: bool,
    base_url: str | None = None,
    api_key_env: str | None = None,
    judge_backend: str = "same",
    judge_base_url: str | None = None,
    judge_api_key_env: str | None = None,
) -> tuple[LLM, LLM | None]:
    valid = ", ".join(_BACKENDS)
    if backend != "openai-compatible" and (base_url or api_key_env):
        raise _fail("--base-url and --api-key-env only apply with --backend openai-compatible")
    if judge_backend != "openai-compatible" and (judge_base_url or judge_api_key_env):
        raise _fail(
            "--judge-base-url and --judge-api-key-env only apply with "
            "--judge-backend openai-compatible"
        )
    if backend not in _BACKENDS:
        raise _fail(f"Unknown backend: {backend}. Valid backends: {valid}")
    if judge_backend != "same" and judge_backend not in _BACKENDS:
        raise _fail(f"Unknown judge backend: {judge_backend}. Valid backends: {valid}, same")
    if _llm_override is not None:
        attacker, judge = _llm_override
        return attacker, None if no_judge else judge
    try:
        attacker = make_llm(backend, attacker_model, base_url=base_url, api_key_env=api_key_env)  # type: ignore[arg-type]
        if no_judge:
            judge = None
        elif judge_backend == "same":
            judge = make_llm(  # type: ignore[arg-type]
                backend, judge_model or attacker_model, base_url=base_url, api_key_env=api_key_env
            )
        else:
            if judge_backend == "openai-compatible" and not (judge_model and judge_base_url):
                raise LLMError("openai-compatible judge needs --judge-model and --judge-base-url")
            judge = make_llm(  # type: ignore[arg-type]
                judge_backend,
                judge_model,
                base_url=judge_base_url,
                api_key_env=judge_api_key_env,
            )
    except LLMError as exc:
        raise _fail(str(exc)) from exc
    return attacker, judge


def _select_seeds(
    scenarios: list[Path] | None, suite: list[str] | None, seed: list[str] | None
) -> tuple[list, list]:
    """Return (seeds to attack, every loaded scenario); exit 2 on bad or empty selections."""
    loaded = _load(scenarios or [])
    selected = _filter_suites(loaded, suite)
    if seed:
        known = {s.id for s in selected}
        unknown = [s for s in seed if s not in known]
        if unknown:
            raise _fail(f"Unknown seed: {', '.join(unknown)}. Run `phantom list` to see ids.")
        selected = [s for s in selected if s.id in seed]
    usable = [s for s in selected if s.carrier is not None]
    skipped = [s.id for s in selected if s.carrier is None]
    if skipped and seed:
        raise _fail(f"Seed has no carrier and cannot seed a campaign: {', '.join(skipped)}")
    if skipped:
        console.print(f"Skipped (no carrier): {', '.join(skipped)}", markup=False, highlight=False)
    if not usable:
        raise _fail("No seeds selected.")
    return usable, loaded


@app.command()
def attack(
    agent: str = typer.Option(
        ..., "--agent", help="URL of the agent under test, or 'lure' for the built-in positive-control agent."
    ),
    seed: list[str] | None = typer.Option(None, "--seed", help="Attack one seed scenario id (repeatable)."),
    suite: list[str] | None = typer.Option(None, "--suite", help="Attack one category (repeatable)."),
    scenarios: list[Path] | None = typer.Option(None, "--scenarios", help="Add a directory of custom seeds."),
    rounds: int = typer.Option(5, "--rounds", help="Rounds per branch."),
    branches: int = typer.Option(3, "--branches", help="Attacker branches per seed."),
    concurrency: int = typer.Option(3, "--concurrency", help="Parallel rounds. Seeds run one at a time, so values above --branches do not add speed."),
    keep_going: bool = typer.Option(False, "--keep-going", help="Do not stop a seed at its first confirmed finding."),
    backend: str = typer.Option("auto", "--backend", help="LLM backend: auto, claude-cli, anthropic or openai-compatible."),
    base_url: str | None = typer.Option(None, "--base-url", help="OpenAI-compatible endpoint, e.g. http://localhost:11434/v1."),
    api_key_env: str | None = typer.Option(None, "--api-key-env", help="Name of the env var holding the API key (omit for local servers)."),
    judge_backend: str = typer.Option("same", "--judge-backend", help="Judge backend: auto, claude-cli, anthropic, openai-compatible or same."),
    judge_base_url: str | None = typer.Option(None, "--judge-base-url", help="Judge endpoint when the judge backend differs."),
    judge_api_key_env: str | None = typer.Option(None, "--judge-api-key-env", help="Judge key env var when the judge backend differs."),
    attacker_model: str | None = typer.Option(None, "--attacker-model", help="Attacker model (default per backend)."),
    judge_model: str | None = typer.Option(None, "--judge-model", help="Judge model (default: the attacker model with --judge-backend same, otherwise the judge backend's default)."),
    no_judge: bool = typer.Option(False, "--no-judge", help="Grade by code only."),
    save_findings: Path = typer.Option(Path("phantom-findings"), "--save-findings", help="Directory for exported findings."),
    report: Path | None = typer.Option(None, "--report", help="Write the HTML report."),
    json_path: Path | None = typer.Option(None, "--json", help="Write JSON results."),
    timeout: float = typer.Option(60.0, "--timeout", help="Seconds per agent request."),
    max_steps: int = typer.Option(8, "--max-steps", help="Agent replies per attempt."),
    header: list[str] | None = typer.Option(None, "--header", help='Extra HTTP header, "K: V" (repeatable).'),
) -> None:
    """Run an AI red-team campaign against an agent (sandbox only)."""
    _tolerate_unencodable_output()
    use_lure, agent = _check_agent(agent)
    _check_bounds(
        timeout, rounds=rounds, branches=branches, concurrency=concurrency, max_steps=max_steps
    )
    headers = _parse_headers(header or [])
    seeds, known_scenarios = _select_seeds(scenarios, suite, seed)
    attacker_llm, judge_llm = _make_llms(
        backend, attacker_model, judge_model, no_judge, base_url, api_key_env,
        judge_backend, judge_base_url, judge_api_key_env,
    )

    config = CampaignConfig(
        rounds=rounds,
        branches=branches,
        concurrency=concurrency,
        max_steps=max_steps,
        keep_going=keep_going,
        use_judge=judge_llm is not None,
    )
    meta = RunMeta(
        phantom_version=__version__,
        agent_url=_shown_url(agent, use_lure),
        started_at=_now(),
        options={
            "rounds": rounds,
            "branches": branches,
            "concurrency": concurrency,
            "keep_going": keep_going,
            "backend": backend,
            "base_url": redact_url(base_url) if base_url else None,
            "judge_backend": judge_backend,
            "attacker_model": attacker_model,
            "judge_model": judge_model,
            "no_judge": no_judge,
            "timeout": timeout,
            "max_steps": max_steps,
            "seeds": [s.id for s in seeds],
            "suites": suite or [],
        },
    )

    progress = Progress(
        TextColumn("[bold]Attacking"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("{task.fields[latest]}"),
        console=console,
        transient=True,
    )
    task = progress.add_task("attack", total=len(seeds) * branches * rounds, latest="")

    gathered: list[Attempt] = []

    def on_attempt(a: Attempt) -> None:
        gathered.append(a)
        latest = f"{a.seed_id} b{a.branch + 1} r{a.round}: {a.final_status}"
        progress.update(task, advance=1, latest=Text(_encodable(latest, console)))

    transport = _transport_override
    client_url = agent
    if use_lure:
        client_url = LURE_URL
        if transport is None:
            transport = lure_transport(known_scenarios)

    async def go():
        async with AgentClient(
            client_url, headers=headers, timeout=timeout, transport=transport
        ) as client:
            return await run_campaign(
                client,
                seeds,
                attacker_llm,
                judge_llm,
                config,
                on_attempt=on_attempt,
                vars_factory=_vars_factory_override or new_template_vars,
            )

    try:
        with progress:
            result = asyncio.run(go())
    except KeyboardInterrupt:
        by_seed = [(s, [a for a in gathered if a.seed_id == s.id]) for s in seeds]
        result = partial_result(by_seed, attacker_llm, judge_llm, 0, 0.0, "interrupted")

    reached = [a.outcome for s in result.seeds for a in s.attempts if a.outcome is not None]
    if reached and all(o.error_kind == "unreachable" for o in reached):
        raise _fail(f"Could not reach agent at {_shown_url(agent, use_lure)}")

    try:
        if report is not None:
            attack_html.write(report, attack_html.render(result, meta))
        if json_path is not None:
            attack_json.write(json_path, attack_json.build(result, meta))
        exported = export_findings(result, save_findings)
    except OSError as exc:
        raise _fail(f"Could not write report or findings: {exc}") from exc

    print_campaign(result, console)
    if report is not None:
        console.print(f"HTML report: {report}", markup=False, highlight=False)
    if json_path is not None:
        console.print(f"JSON results: {json_path}", markup=False, highlight=False)
    if exported:
        console.print(f"Findings: {save_findings}", markup=False, highlight=False)
        console.print(
            f"Replay them: phantom run --agent <url> --scenarios {save_findings}",
            markup=False,
            highlight=False,
        )

    if result.aborted:
        if result.aborted == "interrupted":
            console.print(
                "Interrupted: partial results were saved.", markup=False, highlight=False
            )
        if "declined" in result.aborted:
            console.print(
                "The attacker model declined. Try another model with --backend "
                "openai-compatible --base-url ... --attacker-model ...",
                markup=False,
                highlight=False,
            )
        raise typer.Exit(2)
    if result.confirmed:
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
