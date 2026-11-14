"""Terminal, JSON and HTML reports."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RunMeta(BaseModel):
    phantom_version: str
    agent_url: str
    started_at: str  # ISO 8601, UTC
    options: dict[str, Any]
