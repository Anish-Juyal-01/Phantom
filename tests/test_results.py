from phantom_redteam.results import RunOutcome, ScenarioResult, summarize
from phantom_redteam.scenarios import Scenario


def scen(sid="s", category="data-exfiltration", utility=True):
    return Scenario.model_validate(
        {
            "id": sid,
            "name": sid,
            "category": category,
            "severity": "low",
            "description": "d",
            "user": "u",
            "tools": ["read_email"],
            "breach": [{"tool_called": "read_email"}],
            "utility": {"output_contains_any": ["x"]} if utility else None,
        }
    )


def run(status, utility=None):
    return RunOutcome(
        status=status,
        messages=[],
        final_output=None,
        matches=[],
        utility=utility,
        error="boom" if status == "error" else None,
        error_kind="timeout" if status == "error" else None,
        duration_s=0.1,
        vars={},
    )


def test_status_priority():
    assert ScenarioResult(scenario=scen(), runs=[run("resisted"), run("breached")]).status == "breached"
    assert ScenarioResult(scenario=scen(), runs=[run("resisted"), run("error")]).status == "error"
    assert ScenarioResult(scenario=scen(), runs=[run("resisted"), run("resisted")]).status == "resisted"
    r = ScenarioResult(scenario=scen(), runs=[run("breached"), run("error"), run("breached")])
    assert r.status == "breached"
    assert r.breach_runs == 2


def test_result_utility():
    assert ScenarioResult(scenario=scen(), runs=[run("error")]).utility is None
    assert ScenarioResult(scenario=scen(utility=False), runs=[run("resisted")]).utility is None
    ok = ScenarioResult(scenario=scen(), runs=[run("resisted", True), run("error")])
    assert ok.utility is True
    bad = ScenarioResult(scenario=scen(), runs=[run("resisted", True), run("breached", False)])
    assert bad.utility is False


def test_summary_scores():
    results = [
        ScenarioResult(scenario=scen("a", utility=True), runs=[run("resisted", True)]),
        ScenarioResult(scenario=scen("b", utility=True), runs=[run("resisted", False)]),
        ScenarioResult(scenario=scen("c", "fake-authority", utility=False), runs=[run("resisted")]),
        ScenarioResult(scenario=scen("d", "fake-authority"), runs=[run("breached", True)]),
        ScenarioResult(scenario=scen("e", "fake-authority"), runs=[run("error")]),
    ]
    s = summarize(results)
    assert (s.total, s.resisted, s.breached, s.errors) == (5, 3, 1, 1)
    assert s.safety_score == 60.0
    assert s.utility_score == 66.7  # 2 of 3 defined checks passed
    assert s.by_category["data-exfiltration"] == {"total": 2, "resisted": 2, "breached": 0, "errors": 0}
    assert s.by_category["fake-authority"] == {"total": 3, "resisted": 1, "breached": 1, "errors": 1}


def test_empty_summary():
    s = summarize([])
    assert s.safety_score == 0.0
    assert s.utility_score is None
    assert s.total == 0
