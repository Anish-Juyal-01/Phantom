"""The adaptive attack campaign: ties the AI attacker, the target and the judge together.

For each seed the campaign runs several attacker branches, each up to a few rounds.
A round proposes a carrier, validates it, runs the target through it, grades the run by
code and (optionally) by the AI judge, and feeds the result back to the next round.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Literal

from pydantic import BaseModel

from phantom_redteam.agent_client import AgentClient
from phantom_redteam.attacker import AttackerDeclined, RoundFeedback, propose_attempt
from phantom_redteam.carrier import (
    InvalidAttempt,
    restore_placeholders,
    validate_attempt,
    with_carrier,
)
from phantom_redteam.judge import JudgeVerdict, judge_attempt, merge_status
from phantom_redteam.llm import LLM, LLMError
from phantom_redteam.results import RunOutcome
from phantom_redteam.runner import run_scenario_once
from phantom_redteam.scenarios import Scenario, TemplateVars, fill, new_template_vars
from phantom_redteam.tactics import tactic_for

FinalStatus = Literal["confirmed", "partial", "resisted", "error", "declined", "invalid"]
_BEST_ORDER: tuple[FinalStatus, ...] = (
    "confirmed", "partial", "resisted", "error", "declined", "invalid",
)

# A strategy that reads like the attacker model declining in prose.
_REFUSAL = re.compile(r"decline|cannot|can't|won't|refuse|unable", re.IGNORECASE)
_UNREACHABLE_ABORT_AFTER = 3

# Attacker judged to have written no real attack: told to the attacker next round.
_NOT_GENUINE_NOTE = "The judge decided this attempt contained no real attack. "


@dataclass
class CampaignConfig:
    rounds: int = 5
    branches: int = 3
    concurrency: int = 3
    max_steps: int = 8
    keep_going: bool = False
    use_judge: bool = True
    max_consecutive_llm_errors: int = 3


class Attempt(BaseModel):
    seed_id: str
    branch: int
    round: int
    tactic: str
    strategy: str
    carrier_text: str
    vars: dict[str, str]
    outcome: RunOutcome | None = None
    code_status: str | None = None
    verdict: JudgeVerdict | None = None
    final_status: FinalStatus
    invalid_reason: str | None = None
    llm_error: str | None = None
    t_attacker: float = 0.0
    t_agent: float = 0.0
    t_judge: float = 0.0


class SeedResult(BaseModel):
    seed: Scenario
    attempts: list[Attempt]

    @property
    def best_status(self) -> FinalStatus:
        present = {a.final_status for a in self.attempts}
        for status in _BEST_ORDER:
            if status in present:
                return status
        return "invalid"

    @property
    def winner(self) -> Attempt | None:
        for wanted in ("confirmed", "partial"):
            for a in self.attempts:
                if a.final_status == wanted:
                    return a
        return None


class CampaignResult(BaseModel):
    seeds: list[SeedResult]
    aborted: str | None
    llm_calls: int
    wall_s: float
    attacker_llm: str
    judge_llm: str | None

    @property
    def confirmed(self) -> int:
        return sum(1 for s in self.seeds if s.best_status == "confirmed")

    @property
    def partial(self) -> int:
        return sum(1 for s in self.seeds if s.best_status == "partial")


def _render_tool_calls(outcome: RunOutcome) -> list[str]:
    rendered: list[str] = []
    for m in outcome.messages:
        for call in m.tool_calls or []:
            args = json.dumps(call.arguments, ensure_ascii=False, sort_keys=True)
            rendered.append(f"{call.name}({args})")
    return rendered


class _Campaign:
    def __init__(
        self,
        client: AgentClient,
        attacker_llm: LLM,
        judge_llm: LLM | None,
        config: CampaignConfig,
        on_attempt: Callable[[Attempt], None] | None,
        vars_factory: Callable[[], TemplateVars],
    ):
        self.client = client
        self.attacker_llm = attacker_llm
        self.judge_llm = judge_llm
        self.config = config
        self.on_attempt = on_attempt
        self.vars_factory = vars_factory
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.abort = asyncio.Event()
        self.aborted_msg: str | None = None
        self.llm_calls = 0
        self.consecutive_errors = 0  # consecutive attacker LLM errors
        self.all_declines = True  # every error in the current streak was a decline
        self.refusal_streak = 0  # consecutive prose refusals (invalid: required value missing)
        self.unreachable_streak = 0  # consecutive attempts where the agent was unreachable
        # Attempts per started seed, kept live so a cancelled campaign can return them.
        self.started: list[tuple[Scenario, list[Attempt]]] = []

    async def run(self, seeds: list[Scenario]) -> list[SeedResult]:
        results: list[SeedResult] = []
        for seed_index, seed in enumerate(seeds):
            seed_stop = asyncio.Event()
            live: list[Attempt] = []
            self.started.append((seed, live))
            branch_lists = await asyncio.gather(
                *(
                    self._run_branch(seed_index, seed, branch, seed_stop, live)
                    for branch in range(self.config.branches)
                )
            )
            attempts = [a for branch in branch_lists for a in branch]
            self.started[-1] = (seed, attempts)
            results.append(SeedResult(seed=seed, attempts=attempts))
            if self.abort.is_set():
                break
        return results

    async def _run_branch(
        self,
        seed_index: int,
        seed: Scenario,
        branch: int,
        seed_stop: asyncio.Event,
        live: list[Attempt],
    ) -> list[Attempt]:
        tactic = tactic_for(seed_index, branch)
        history: list[RoundFeedback] = []
        attempts: list[Attempt] = []
        for round_num in range(1, self.config.rounds + 1):
            if seed_stop.is_set() or self.abort.is_set():
                break
            async with self.semaphore:
                if seed_stop.is_set() or self.abort.is_set():
                    break
                try:
                    attempt, feedback = await self._run_round(
                        seed, seed_index, branch, round_num, tactic, history
                    )
                except Exception as exc:  # noqa: BLE001 - one bad round must not lose the rest
                    attempt = _internal_error_attempt(seed, branch, round_num, tactic, exc)
                    feedback = None
            attempts.append(attempt)
            live.append(attempt)
            self._track(attempt)
            if self.on_attempt is not None:
                self.on_attempt(attempt)
            if feedback is not None:
                history.append(feedback)
            if attempt.final_status == "confirmed":
                if not self.config.keep_going:
                    seed_stop.set()
                break
            if self.abort.is_set():
                break
        return attempts

    def _track(self, attempt: Attempt) -> None:
        """Update the abort streaks that span the whole campaign."""
        refusal = (
            attempt.final_status == "invalid"
            and (attempt.invalid_reason or "").startswith("required value missing")
            and _REFUSAL.search(attempt.strategy) is not None
        )
        self.refusal_streak = self.refusal_streak + 1 if refusal else 0
        if self.refusal_streak >= self.config.max_consecutive_llm_errors:
            self._abort_with(
                f"attacker model declined to write attacks ({self.refusal_streak} in a row)"
            )
        o = attempt.outcome
        if o is not None:
            self.unreachable_streak = (
                self.unreachable_streak + 1 if o.error_kind == "unreachable" else 0
            )
            if self.unreachable_streak >= _UNREACHABLE_ABORT_AFTER:
                self._abort_with(f"agent unreachable ({self.unreachable_streak} in a row)")

    def _abort_with(self, message: str) -> None:
        if self.aborted_msg is None:
            self.aborted_msg = message
        self.abort.set()

    def _reset_errors(self) -> None:
        self.consecutive_errors = 0
        self.all_declines = True

    async def _call_attacker(
        self, filled_seed: Scenario, tactic, history: list[RoundFeedback]
    ) -> tuple[tuple[str, str] | None, LLMError | None, float]:
        start = time.perf_counter()
        try:
            result = await asyncio.to_thread(
                propose_attempt, self.attacker_llm, filled_seed, tactic, history
            )
            self.llm_calls += 1
            self._reset_errors()
            return result, None, time.perf_counter() - start
        except LLMError as exc:
            self.llm_calls += 1
            self.consecutive_errors += 1
            self.all_declines = (
                self.consecutive_errors == 1 or self.all_declines
            ) and isinstance(exc, AttackerDeclined)
            if self.consecutive_errors >= self.config.max_consecutive_llm_errors:
                if self.aborted_msg is None:
                    if self.all_declines:
                        self.aborted_msg = (
                            "attacker model declined to write attacks "
                            f"({self.consecutive_errors} in a row)"
                        )
                    else:
                        self.aborted_msg = (
                            f"aborted after {self.consecutive_errors} "
                            "consecutive attacker LLM errors"
                        )
                self.abort.set()
            return None, exc, time.perf_counter() - start

    async def _run_round(
        self,
        seed: Scenario,
        seed_index: int,
        branch: int,
        round_num: int,
        tactic,
        history: list[RoundFeedback],
    ) -> tuple[Attempt, RoundFeedback | None]:
        vars = self.vars_factory()
        filled_seed = fill(seed, vars)
        base = dict(
            seed_id=seed.id, branch=branch, round=round_num, tactic=tactic.name, vars=asdict(vars)
        )

        # Step 2-3: propose, validate, and on InvalidAttempt retry once with the reason.
        result, err, t_attacker = await self._call_attacker(filled_seed, tactic, history)
        if err is not None:
            return self._error_attempt(base, err, t_attacker), None
        strategy, text = result
        reason = _validation_error(text, filled_seed, vars.secret)
        if reason is not None:
            retry_fb = _invalid_feedback(text, reason)
            result, err, t_retry = await self._call_attacker(
                filled_seed, tactic, history + [retry_fb]
            )
            t_attacker += t_retry
            if err is not None:
                # Keep the first invalid carrier on the record.
                first = dict(strategy=strategy, carrier_text=text, invalid_reason=reason)
                return self._error_attempt(base, err, t_attacker, first), None
            strategy, text = result
            reason = _validation_error(text, filled_seed, vars.secret)
            if reason is not None:
                attempt = Attempt(
                    **base,
                    strategy=strategy,
                    carrier_text=text,
                    final_status="invalid",
                    invalid_reason=reason,
                    t_attacker=t_attacker,
                )
                return attempt, _invalid_feedback(text, reason)

        # Step 4: run the target with the carrier restored to placeholders and the same vars.
        runnable = with_carrier(seed, restore_placeholders(text, vars))
        agent_start = time.perf_counter()
        outcome = await run_scenario_once(self.client, runnable, self.config.max_steps, vars=vars)
        t_agent = time.perf_counter() - agent_start
        code_status = outcome.status

        # Step 5: the AI judge. Its failures are recorded but never abort the campaign.
        verdict: JudgeVerdict | None = None
        llm_error: str | None = None
        t_judge = 0.0
        # A run that never reached the agent has nothing to judge.
        if self.config.use_judge and self.judge_llm is not None and code_status != "error":
            judge_start = time.perf_counter()
            try:
                verdict = await asyncio.to_thread(
                    judge_attempt, self.judge_llm, filled_seed, text, outcome
                )
                self.llm_calls += 1
                self._reset_errors()
            except LLMError as exc:
                self.llm_calls += 1
                llm_error = str(exc)
            t_judge = time.perf_counter() - judge_start

        # Step 6: merge the verdicts and build the feedback for the next round.
        final_status = merge_status(code_status, verdict)
        attempt = Attempt(
            **base,
            strategy=strategy,
            carrier_text=text,
            outcome=outcome,
            code_status=code_status,
            verdict=verdict,
            final_status=final_status,
            llm_error=llm_error,
            t_attacker=t_attacker,
            t_agent=t_agent,
            t_judge=t_judge,
        )
        note = "" if verdict is None or verdict.attempt_genuine else _NOT_GENUINE_NOTE
        feedback = RoundFeedback(
            carrier_text=text,
            tool_calls=_render_tool_calls(outcome),
            final_reply=outcome.final_output or "",
            final_status=final_status,
            judge_explanation=note + (verdict.explanation if verdict is not None else ""),
        )
        return attempt, feedback

    def _error_attempt(
        self, base: dict, err: LLMError, t_attacker: float, first_invalid: dict | None = None
    ) -> Attempt:
        kept = first_invalid or dict(strategy="", carrier_text="")
        return Attempt(
            **base,
            **kept,
            final_status="declined" if isinstance(err, AttackerDeclined) else "error",
            llm_error=str(err),
            t_attacker=t_attacker,
        )


def _internal_error_attempt(
    seed: Scenario, branch: int, round_num: int, tactic, exc: Exception
) -> Attempt:
    return Attempt(
        seed_id=seed.id,
        branch=branch,
        round=round_num,
        tactic=tactic.name,
        strategy="",
        carrier_text="",
        vars={},
        final_status="error",
        llm_error=f"internal error: {type(exc).__name__}: {exc}",
    )


def _validation_error(text: str, filled_seed: Scenario, secret: str | None = None) -> str | None:
    try:
        validate_attempt(text, filled_seed, secret)
        return None
    except InvalidAttempt as exc:
        return str(exc)


def _invalid_feedback(text: str, reason: str) -> RoundFeedback:
    return RoundFeedback(
        carrier_text=text,
        tool_calls=[],
        final_reply="",
        final_status="invalid",
        judge_explanation="",
        invalid_reason=reason,
    )


def partial_result(
    started: list[tuple[Scenario, list[Attempt]]],
    attacker_llm: LLM,
    judge_llm: LLM | None,
    llm_calls: int,
    wall_s: float,
    aborted: str | None,
) -> CampaignResult:
    seeds = [
        SeedResult(seed=seed, attempts=sorted(attempts, key=lambda a: (a.branch, a.round)))
        for seed, attempts in started
        if attempts
    ]
    return CampaignResult(
        seeds=seeds,
        aborted=aborted,
        llm_calls=llm_calls,
        wall_s=wall_s,
        attacker_llm=attacker_llm.name,
        judge_llm=judge_llm.name if judge_llm is not None else None,
    )


async def run_campaign(
    client: AgentClient,
    seeds: list[Scenario],
    attacker_llm: LLM,
    judge_llm: LLM | None,
    config: CampaignConfig,
    on_attempt: Callable[[Attempt], None] | None = None,
    vars_factory: Callable[[], TemplateVars] = new_template_vars,
) -> CampaignResult:
    """Run the campaign; if cancelled (Ctrl+C), return what was gathered, aborted="interrupted"."""
    start = time.perf_counter()
    campaign = _Campaign(client, attacker_llm, judge_llm, config, on_attempt, vars_factory)
    try:
        seed_results = await campaign.run(seeds)
    except asyncio.CancelledError:
        return partial_result(
            campaign.started, attacker_llm, judge_llm, campaign.llm_calls,
            time.perf_counter() - start, "interrupted",
        )
    return CampaignResult(
        seeds=seed_results,
        aborted=campaign.aborted_msg,
        llm_calls=campaign.llm_calls,
        wall_s=time.perf_counter() - start,
        attacker_llm=attacker_llm.name,
        judge_llm=judge_llm.name if judge_llm is not None else None,
    )
