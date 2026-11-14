import asyncio
import json
import re

from fake_agents import obedient, refusing, transport_for
from rich.console import Console

from phantom_redteam.agent_client import AgentClient
from phantom_redteam.report import RunMeta, json_out
from phantom_redteam.report import html as html_report
from phantom_redteam.report.terminal import print_report
from phantom_redteam.results import RunOutcome, ScenarioResult, summarize
from phantom_redteam.runner import run_scenario_once
from phantom_redteam.scenarios import TemplateVars, fill, load_scenarios

VARS = TemplateVars(
    canary="PHNTM-0123abcd",
    attacker_email="exfil-ab12@attacker.example",
    attacker_url="https://attacker.example/c/ab12",
    secret="sk-live-" + "0" * 24,
)
BY_ID = {s.id: s for s in load_scenarios()}
BREACHED_ID = "inbox-forward-exfil"
RESISTED_ID = "webpage-summary-email"

META = RunMeta(
    phantom_version="0.1.0",
    agent_url="http://agent.test/",
    started_at="2026-11-13T10:00:00Z",
    options={"repeat": 1, "concurrency": 4, "timeout": 60, "max_steps": 8},
)


def run(scenario, agent_factory):
    transport = transport_for(agent_factory(fill(scenario, VARS)))

    async def go():
        async with AgentClient("http://agent.test/", timeout=5.0, transport=transport) as c:
            return await run_scenario_once(c, scenario, 8, VARS)

    return asyncio.run(go())


def make_results():
    return [
        ScenarioResult(scenario=BY_ID[BREACHED_ID], runs=[run(BY_ID[BREACHED_ID], obedient)]),
        ScenarioResult(
            scenario=BY_ID[RESISTED_ID], runs=[run(BY_ID[RESISTED_ID], lambda f: refusing())]
        ),
    ]


def test_terminal_lists_scores():
    results = make_results()
    console = Console(record=True, width=120)
    print_report(results, summarize(results), console)
    text = console.export_text()
    assert "Safety score: 50.0%" in text
    assert "(1/2 resisted)" in text
    assert BREACHED_ID in text and RESISTED_ID in text
    assert "BREACHED" in text and "RESISTED" in text


def test_terminal_error_line_and_repeat_fraction():
    ok = run(BY_ID[BREACHED_ID], obedient)
    bad = RunOutcome(
        status="error", messages=[], final_output=None, matches=[], utility=None,
        error="cannot [connect]", error_kind="unreachable", duration_s=0.1, vars={},
    )
    results = [ScenarioResult(scenario=BY_ID[BREACHED_ID], runs=[ok, ok, bad])]
    console = Console(record=True, width=120)
    print_report(results, summarize(results), console)
    text = console.export_text()
    assert "2/3" in text
    assert f"{BREACHED_ID}: cannot [connect]" in text


def test_json_schema_keys():
    results = make_results()
    data = json_out.build(results, summarize(results), META)
    assert list(data) == [
        "schema_version", "phantom_version", "agent_url", "started_at",
        "options", "summary", "scenarios",
    ]
    assert data["schema_version"] == 1
    first = data["scenarios"][0]
    assert set(first) == {
        "id", "name", "category", "severity", "status", "breach_runs",
        "total_runs", "utility", "runs",
    }
    assert set(first["runs"][0]) == {
        "status", "error", "error_kind", "duration_s", "matches", "final_output", "transcript",
    }
    assert first["runs"][0]["transcript"][0]["role"] == "user"
    json.dumps(data)


def test_html_self_contained():
    results = make_results()
    text = html_report.render(results, summarize(results), META)
    for r in results:
        assert f'id="{r.scenario.id}"' in text
    assert 'src="http' not in text and 'href="http' not in text
    assert "<mark>" in text
    assert "50.0%" in text
    assert re.search(r'class="[^"]*\bbreach\b', text)


def test_html_escapes_agent_output():
    results = make_results()
    results[1].runs[0].final_output = "<script>alert(1)</script>"
    results[1].runs[0].messages[-1].content = "<script>alert(1)</script>"
    text = html_report.render(results, summarize(results), META)
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_highlight_after_escape():
    out = html_report.highlight("a <b> exfil-ab12@attacker.example", {"attacker_email": "exfil-ab12@attacker.example"})
    assert str(out) == "a &lt;b&gt; <mark>exfil-ab12@attacker.example</mark>"


def test_utf8_roundtrip(tmp_path):
    results = make_results()
    results[1].runs[0].final_output = "✓ résumé 🦅"
    results[1].runs[0].messages[-1].content = "✓ résumé 🦅"
    summary = summarize(results)
    jp, hp = tmp_path / "r.json", tmp_path / "r.html"
    json_out.write(jp, json_out.build(results, summary, META))
    html_report.write(hp, html_report.render(results, summary, META))
    assert "✓ résumé 🦅" in jp.read_text(encoding="utf-8")
    assert "✓ résumé 🦅" in hp.read_text(encoding="utf-8")


def _render(encoding):
    import io

    results = make_results()
    wrapper = io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors="strict")
    console = Console(file=wrapper, force_terminal=False, width=120)
    print_report(results, summarize(results), console)
    wrapper.flush()
    return wrapper.buffer.getvalue().decode(encoding)


def test_terminal_ascii_fallback_on_cp1252():
    text = _render("cp1252")
    assert "BREACHED" in text and "RESISTED" in text
    assert "✓" not in text and "✗" not in text
    assert re.search(r"\b(yes|no)\b", text)


def test_terminal_keeps_symbols_on_utf8():
    text = _render("utf-8")
    assert "✓" in text or "✗" in text


def test_terminal_survives_unencodable_error_text_on_cp1252():
    import io

    ok = run(BY_ID[BREACHED_ID], obedient)
    bad = RunOutcome(
        status="error", messages=[], final_output=None, matches=[], utility=None,
        error="HTTP 500: \u2192 upstream \u6545\u969c", error_kind="http", duration_s=0.1, vars={},
    )
    results = [ScenarioResult(scenario=BY_ID[BREACHED_ID], runs=[ok, bad])]
    wrapper = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    console = Console(file=wrapper, force_terminal=False, width=120)
    print_report(results, summarize(results), console)
    wrapper.flush()
    text = wrapper.buffer.getvalue().decode("cp1252")
    assert "HTTP 500" in text and "upstream" in text


def test_terminal_shows_full_scenario_id_at_80_columns():
    results = [ScenarioResult(scenario=BY_ID["doc-quote-instructions"], runs=[
        run(BY_ID["doc-quote-instructions"], obedient)])]
    console = Console(record=True, width=80)
    print_report(results, summarize(results), console)
    text = console.export_text().replace("\n", "")
    assert "doc-quote-instructions" in text.replace(" ", "").replace("|", "").replace("\u2503", "").replace("\u2502", "")
    assert "\u2026" not in text


def test_terminal_markup_in_scenario_name_and_id_is_literal():
    scenario = BY_ID[BREACHED_ID].model_copy(update={"name": "Leaks [/bold] secrets"})
    results = [ScenarioResult(scenario=scenario, runs=[run(BY_ID[BREACHED_ID], obedient)])]
    console = Console(record=True, width=120)
    print_report(results, summarize(results), console)
    assert BREACHED_ID in console.export_text()
