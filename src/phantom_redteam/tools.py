"""Fake tool catalog: Phantom plays every tool the agent calls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from phantom_redteam.protocol import ToolSpec


class UnknownToolError(Exception):
    """Raised when a tool name is not in the catalog."""


@dataclass(frozen=True)
class ToolDef:
    name: str
    description: str
    parameters: dict[str, Any]
    side_effect: bool
    lookup_arg: str | None


def _params(props: dict[str, str], required: list[str]) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
    }
    if required:
        schema["required"] = required
    return schema


def _tool(name, description, props, required, side_effect=False, lookup_arg=None) -> ToolDef:
    return ToolDef(name, description, _params(props, required), side_effect, lookup_arg)


CATALOG: dict[str, ToolDef] = {
    t.name: t
    for t in [
        _tool("read_inbox", "List the emails in the user's inbox.", {}, []),
        _tool("read_email", "Read the full body of one email.",
              {"id": "Email id"}, ["id"], lookup_arg="id"),
        _tool("send_email", "Send an email.",
              {"to": "Recipient address", "subject": "Subject line", "body": "Message body"},
              ["to", "subject", "body"], side_effect=True),
        _tool("fetch_url", "Fetch the body of a web page.",
              {"url": "Page URL"}, ["url"], lookup_arg="url"),
        _tool("read_file", "Read the contents of a file.",
              {"path": "File path"}, ["path"], lookup_arg="path"),
        _tool("write_file", "Write content to a file.",
              {"path": "File path", "content": "Content to write"},
              ["path", "content"], side_effect=True),
        _tool("delete_file", "Delete a file.",
              {"path": "File path"}, ["path"], side_effect=True),
        _tool("run_shell", "Run a shell command.",
              {"command": "Command to run"}, ["command"], side_effect=True),
        _tool("get_calendar", "Get calendar events for a date.",
              {"date": "Date (optional)"}, [], lookup_arg="date"),
        _tool("search_web", "Search the web and return result snippets.",
              {"query": "Search query"}, ["query"], lookup_arg="query"),
    ]
}


def tool_specs(names: list[str]) -> list[ToolSpec]:
    specs = []
    for name in names:
        tool = CATALOG.get(name)
        if tool is None:
            raise UnknownToolError(name)
        specs.append(ToolSpec(name=tool.name, description=tool.description,
                              parameters=tool.parameters))
    return specs


def _side_effect_reply(name: str, arguments: dict) -> str:
    def arg(key: str) -> str:
        value = arguments.get(key, "")
        return "" if value is None else str(value)

    if name == "send_email":
        return f"Email sent to {arg('to')}."
    if name == "write_file":
        return f"Wrote {len(arg('content'))} characters to {arg('path')}."
    if name == "delete_file":
        return f"Deleted {arg('path')}."
    return "Command completed with exit code 0."


def execute_tool(name: str, arguments: dict, fixtures: dict[str, str | dict[str, str]]) -> str:
    tool = CATALOG.get(name)
    if tool is None:
        raise UnknownToolError(name)
    if tool.side_effect:
        return _side_effect_reply(name, arguments)
    fixture = fixtures.get(name)
    if fixture is None:
        return "No data available."
    if isinstance(fixture, str):
        return fixture
    if tool.lookup_arg is None:
        return fixture.get("*", "No data available.")
    value = str(arguments.get(tool.lookup_arg, ""))
    if value in fixture:
        return fixture[value]
    if "*" in fixture:
        return fixture["*"]
    return f"No result for {tool.lookup_arg}={value!r}."
