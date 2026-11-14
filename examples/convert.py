"""Pure conversions between Phantom's protocol and Anthropic Messages API shapes."""

from __future__ import annotations

import re

from phantom_redteam.protocol import AgentResponse, Message, ToolCall, ToolSpec
from phantom_redteam.tools import CATALOG

_INTENT = {
    "send_email": ("send", "email", "forward", "reply"),
    "write_file": ("write", "save", "create", "update"),
    "delete_file": ("delete", "remove", "clean"),
    "run_shell": ("run", "execute", "install", "command"),
}


def to_anthropic_tools(tools: list[ToolSpec]) -> list[dict]:
    return [
        {"name": t.name, "description": t.description, "input_schema": t.parameters}
        for t in tools
    ]


def to_anthropic_messages(messages: list[Message], wrap_untrusted: bool) -> list[dict]:
    out: list[dict] = []
    for m in messages:
        if m.role == "tool":
            content = m.content or ""
            if wrap_untrusted:
                content = f"<untrusted_tool_output>\n{content}\n</untrusted_tool_output>"
            block = {"type": "tool_result", "tool_use_id": m.tool_call_id, "content": content}
            if out and out[-1]["role"] == "user" and _only_tool_results(out[-1]["content"]):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        elif m.role == "assistant":
            blocks: list[dict] = []
            if m.content:
                blocks.append({"type": "text", "text": m.content})
            for call in m.tool_calls or []:
                blocks.append(
                    {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}
                )
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": "user", "content": [{"type": "text", "text": m.content or ""}]})
    return out


def _only_tool_results(blocks: list[dict]) -> bool:
    return all(b["type"] == "tool_result" for b in blocks)


def from_anthropic_content(blocks: list[dict]) -> AgentResponse:
    texts = [b["text"] for b in blocks if b.get("type") == "text"]
    calls = [
        ToolCall(id=b["id"], name=b["name"], arguments=b.get("input") or {})
        for b in blocks
        if b.get("type") == "tool_use"
    ]
    return AgentResponse(content="\n".join(texts) or None, tool_calls=calls)


def _mentions(text: str, keyword: str) -> bool:
    # Whole word, optionally inflected (-d/-ed/-ing); "emails" (a noun) is not an intent to email.
    return re.search(rf"\b{keyword}(?:d|ed|ing)?\b", text, re.IGNORECASE) is not None


def blocked_side_effects(user_text: str, calls: list[ToolCall]) -> list[ToolCall]:
    blocked = []
    for call in calls:
        tool = CATALOG.get(call.name)
        if tool is None or not tool.side_effect:
            continue
        if not any(_mentions(user_text, k) for k in _INTENT.get(call.name, ())):
            blocked.append(call)
    return blocked
