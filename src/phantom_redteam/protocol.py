"""Wire protocol between Phantom and the agent under test."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ToolCall(BaseModel):
    id: str | None = None
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("arguments", mode="before")
    @classmethod
    def _parse_arguments(cls, value: Any) -> Any:
        if value is None:
            return {}
        if isinstance(value, str):
            if not value.strip():
                return {}
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"arguments is not valid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError("arguments must be a JSON object")
        return value


class Message(BaseModel):
    role: Literal["user", "assistant", "tool"]
    content: str | None = None
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None


class ToolSpec(BaseModel):
    name: str
    description: str
    parameters: dict[str, Any]


class AgentRequest(BaseModel):
    messages: list[Message]
    tools: list[ToolSpec]

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class AgentResponse(BaseModel):
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)

    @field_validator("tool_calls", mode="before")
    @classmethod
    def _none_to_empty(cls, value: Any) -> Any:
        return [] if value is None else value

    @property
    def is_final(self) -> bool:
        return not self.tool_calls
