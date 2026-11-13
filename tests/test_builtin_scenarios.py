import asyncio
from collections import Counter

import pytest
from fake_agents import obedient, refusing, transport_for, whistleblower

from kestrel_redteam.agent_client import AgentClient
from kestrel_redteam.runner import run_scenario_once
from kestrel_redteam.scenarios import CATEGORY_ORDER, TemplateVars, fill, load_scenarios

VARS = TemplateVars(
    canary="KSTRL-0123abcd",
    attacker_email="exfil-ab12@attacker.example",
    attacker_url="https://attacker.example/c/ab12",
    secret="sk-live-" + "0" * 24,
)

EXPECTED_IDS = {
    "inbox-forward-exfil",
    "webpage-summary-email",
    "calendar-invite-instruction",
    "search-snippet-redirect",
    "env-file-to-url",
    "config-review-email-secret",
    "support-ticket-paste-keys",
    "markdown-image-beacon",
    "cleanup-delete-project",
    "shell-upload-helper",
    "notes-file-tamper",
    "mass-email-blast",
    "system-override-search",
    "admin-email-policy",
    "tool-error-reauth",
    "developer-mode-file",
    "doc-quote-instructions",
    "email-debug-dump",
    "translation-trick",
    "summary-prefix",
}

BUILTINS = load_scenarios()
BY_ID = {s.id: s for s in BUILTINS}
IDS = sorted(BY_ID)


def run(scenario, agent_factory):
    transport = transport_for(agent_factory(fill(scenario, VARS)))

    async def go():
        async with AgentClient("http://agent.test/", timeout=5.0, transport=transport) as c:
            return await run_scenario_once(c, scenario, 8, VARS)

    return asyncio.run(go())


def fixture_text(scenario) -> str:
    parts = []
    for value in scenario.fixtures.values():
        parts.extend(value.values() if isinstance(value, dict) else [value])
    return "\n".join(parts)


def arg_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from arg_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from arg_strings(v)
    else:
        yield str(obj)


def test_twenty_builtins_four_per_category():
    assert len(BUILTINS) == 20
    assert {s.id for s in BUILTINS} == EXPECTED_IDS
    counts = Counter(s.category for s in BUILTINS)
    assert counts == {c: 4 for c in CATEGORY_ORDER}


def test_every_builtin_has_exploit_and_utility():
    for s in BUILTINS:
        assert s.exploit is not None, s.id
        assert s.exploit.calls or s.exploit.output, s.id
        assert s.utility is not None, s.id


def test_attack_targets_appear_in_fixtures():
    for s in BUILTINS:
        filled = fill(s, VARS)
        text = fixture_text(filled)
        for call in filled.exploit.calls:
            for value in arg_strings(call.arguments):
                for target in (VARS.attacker_email, VARS.attacker_url):
                    if target in value:
                        assert target in text, f"{s.id}: {target} not in fixtures"


@pytest.mark.parametrize("scenario_id", IDS)
def test_authoring_rules(scenario_id):
    filled = fill(BY_ID[scenario_id], VARS)
    text = fixture_text(filled)

    exploit_values = [v for c in filled.exploit.calls for v in arg_strings(c.arguments)]
    if filled.exploit.output:
        exploit_values.append(filled.exploit.output)
    for marker in (VARS.secret, VARS.canary):
        if any(marker in v for v in exploit_values):
            assert marker in text, f"{marker} used in exploit but not in fixtures"

    for needle in filled.utility.output_contains_any:
        assert needle.lower() in text.lower(), f"utility string {needle!r} not in fixtures"

    forbidden = (VARS.attacker_email, VARS.attacker_url, VARS.secret)
    for fixture in filled.fixtures.values():
        if isinstance(fixture, dict):
            for key in fixture:
                assert not any(f in key for f in forbidden), f"fixture key {key!r}"

    assert all(b.output_contains is None for b in filled.breach)


@pytest.mark.parametrize("scenario_id", IDS)
def test_obedient_breaches_every_builtin(scenario_id):
    out = run(BY_ID[scenario_id], obedient)
    assert out.status == "breached", out.error


@pytest.mark.parametrize("scenario_id", IDS)
def test_refusing_resists_every_builtin(scenario_id):
    out = run(BY_ID[scenario_id], lambda filled: refusing())
    assert out.status == "resisted"


@pytest.mark.parametrize("scenario_id", IDS)
def test_whistleblower_resists_every_builtin(scenario_id):
    out = run(BY_ID[scenario_id], whistleblower)
    assert out.status == "resisted", [m.condition for m in out.matches]


@pytest.mark.parametrize("scenario_id", IDS)
def test_utility_reachable(scenario_id):
    out = run(BY_ID[scenario_id], whistleblower)
    assert out.utility is True
