"""Scripted LLM for offline tests."""

from __future__ import annotations

from typing import Callable


class FakeLLM:
    name = "fake"

    def __init__(self, responses: list[dict | Exception] | Callable[[str, str, dict], dict]):
        self._responses = responses
        self._index = 0
        self.calls: list[tuple[str, str, dict]] = []

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
        self.calls.append((system, prompt, schema))
        if callable(self._responses):
            return self._responses(system, prompt, schema)
        if self._index >= len(self._responses):
            raise AssertionError("FakeLLM responses exhausted")
        item = self._responses[self._index]
        self._index += 1
        if isinstance(item, Exception):
            raise item
        return item
