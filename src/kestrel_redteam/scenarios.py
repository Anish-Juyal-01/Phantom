"""Scenario model, loading from YAML, and template-variable filling."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from kestrel_redteam.tools import CATALOG

Category = Literal[
    "hidden-instructions",
    "data-exfiltration",
    "dangerous-actions",
    "fake-authority",
    "prompt-extraction",
]
Severity = Literal["low", "medium", "high", "critical"]

CATEGORY_ORDER: tuple[str, ...] = (
    "hidden-instructions",
    "data-exfiltration",
    "dangerous-actions",
    "fake-authority",
    "prompt-extraction",
)

_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
_ALLOWED_PLACEHOLDERS = {"CANARY", "ATTACKER_EMAIL", "ATTACKER_URL", "SECRET"}


class BreachCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_called: str | None = None
    args_contain: str | None = None
    output_contains: str | None = None
    output_starts_with: str | None = None
    any_tool_args_contain: str | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> BreachCondition:
        for name in (
            "tool_called",
            "args_contain",
            "output_contains",
            "output_starts_with",
            "any_tool_args_contain",
        ):
            value = getattr(self, name)
            if value is not None and not value.strip():
                raise ValueError(f"{name} must not be empty or whitespace")
        if self.output_starts_with is not None and not any(
            c.isalnum() for c in self.output_starts_with
        ):
            raise ValueError("output_starts_with must contain a letter or digit")
        return self

    @model_validator(mode="after")
    def _one_kind(self) -> BreachCondition:
        kinds = [
            self.tool_called,
            self.output_contains,
            self.output_starts_with,
            self.any_tool_args_contain,
        ]
        if sum(k is not None for k in kinds) != 1:
            raise ValueError(
                "set exactly one of tool_called, output_contains, "
                "output_starts_with, any_tool_args_contain"
            )
        if self.args_contain is not None and self.tool_called is None:
            raise ValueError("args_contain is only allowed together with tool_called")
        return self

    def describe(self) -> str:
        parts = [
            f"{name}={value}"
            for name in (
                "tool_called",
                "args_contain",
                "output_contains",
                "output_starts_with",
                "any_tool_args_contain",
            )
            if (value := getattr(self, name)) is not None
        ]
        return " ".join(parts)


class Utility(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output_contains_any: list[str] = Field(min_length=1)


class ExploitCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: dict[str, Any] = {}


class Exploit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    calls: list[ExploitCall] = []
    output: str | None = None


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str
    category: Category
    severity: Severity
    description: str
    user: str
    tools: list[str] = Field(min_length=1)
    fixtures: dict[str, str | dict[str, str]] = {}
    breach: list[BreachCondition] = Field(min_length=1)
    utility: Utility | None = None
    exploit: Exploit | None = None

    @field_validator("fixtures", mode="before")
    @classmethod
    def _coerce_keys(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return {
                str(k): ({str(ik): iv for ik, iv in val.items()} if isinstance(val, dict) else val)
                for k, val in v.items()
            }
        return v

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        for t in self.tools:
            if t not in CATALOG:
                raise ValueError(f"unknown tool: {t}")
        for t in self.fixtures:
            if t not in self.tools:
                raise ValueError(f"fixture for tool not in tools: {t}")
        for b in self.breach:
            if b.tool_called is not None and b.tool_called not in self.tools:
                raise ValueError(
                    f"breach condition tool_called '{b.tool_called}' is not in this scenario's tools"
                )
        if self.exploit:
            for c in self.exploit.calls:
                if c.tool not in self.tools:
                    raise ValueError(f"exploit calls tool not in tools: {c.tool}")
        for s in _strings(self.model_dump()):
            for name in _PLACEHOLDER.findall(s):
                if name not in _ALLOWED_PLACEHOLDERS:
                    raise ValueError(f"unknown placeholder: {{{{{name}}}}}")
        return self


def _strings(obj: Any):
    """Yield every string in a nested structure, dict keys included."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


@dataclass(frozen=True)
class TemplateVars:
    canary: str
    attacker_email: str
    attacker_url: str
    secret: str

    def mapping(self) -> dict[str, str]:
        return {
            "{{CANARY}}": self.canary,
            "{{ATTACKER_EMAIL}}": self.attacker_email,
            "{{ATTACKER_URL}}": self.attacker_url,
            "{{SECRET}}": self.secret,
        }


def new_template_vars() -> TemplateVars:
    return TemplateVars(
        canary=f"KSTRL-{secrets.token_hex(4)}",
        attacker_email=f"exfil-{secrets.token_hex(2)}@attacker.example",
        attacker_url=f"https://attacker.example/c/{secrets.token_hex(2)}",
        secret=f"sk-live-{secrets.token_hex(12)}",
    )


def _replace(obj: Any, mapping: dict[str, str]) -> Any:
    if isinstance(obj, str):
        return _PLACEHOLDER.sub(lambda m: mapping.get("{{" + m.group(1) + "}}", m.group(0)), obj)
    if isinstance(obj, dict):
        return {_replace(k, mapping): _replace(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace(v, mapping) for v in obj]
    return obj


def fill(scenario: Scenario, v: TemplateVars) -> Scenario:
    return Scenario.model_validate(_replace(scenario.model_dump(), v.mapping()))


class ScenarioError(Exception):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("\n".join(problems))


def builtin_dir() -> Path:
    return Path(str(resources.files("kestrel_redteam") / "scenarios"))


def _format_validation(err: ValidationError) -> str:
    out = []
    for e in err.errors():
        loc = ".".join(str(p) for p in e["loc"])
        out.append(f"{loc}: {e['msg']}" if loc else e["msg"])
    return "; ".join(out)


def load_scenarios(
    extra_dirs: list[Path] = (), include_builtin: bool = True
) -> list[Scenario]:
    dirs: list[Path] = ([builtin_dir()] if include_builtin else []) + [Path(d) for d in extra_dirs]
    problems: list[str] = []
    loaded: list[tuple[Scenario, Path]] = []

    for d in dirs:
        if not d.is_dir():
            problems.append(f"{d}: scenario directory not found")
            continue
        files = sorted(p for p in d.iterdir() if p.suffix in (".yaml", ".yml"))
        for f in files:
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                problems.append(f"{f.name}: invalid YAML: {str(e).replace(chr(10), ' ')}")
                continue
            except (OSError, UnicodeDecodeError) as e:
                problems.append(f"{f.name}: cannot read file: {e}")
                continue
            if not isinstance(data, dict):
                problems.append(f"{f.name}: expected a mapping at the top level")
                continue
            try:
                loaded.append((Scenario.model_validate(data), f))
            except ValidationError as e:
                problems.append(f"{f.name}: {_format_validation(e)}")

    seen: dict[str, Path] = {}
    for s, f in loaded:
        if s.id in seen:
            problems.append(f"{f.name}: duplicate id '{s.id}' (also in {seen[s.id].name})")
        else:
            seen[s.id] = f

    if problems:
        raise ScenarioError(problems)

    scenarios = [s for s, _ in loaded]
    scenarios.sort(key=lambda s: (CATEGORY_ORDER.index(s.category), s.id))
    return scenarios
