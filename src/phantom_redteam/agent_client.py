"""HTTP client for the agent under test. The only network I/O in Phantom."""

from __future__ import annotations

from types import TracebackType
from typing import Literal

import httpx
from pydantic import ValidationError

from phantom_redteam.protocol import AgentRequest, AgentResponse

ErrorKind = Literal["unreachable", "http", "timeout", "invalid"]


class AgentError(Exception):
    def __init__(self, kind: ErrorKind, message: str):
        self.kind: ErrorKind = kind
        self.message = message
        super().__init__(message)


class AgentClient:
    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.url = url
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout, transport=transport)

    async def step(self, request: AgentRequest) -> AgentResponse:
        try:
            resp = await self._client.post(self.url, json=request.to_payload())
        except httpx.ConnectTimeout as exc:
            raise AgentError("unreachable", f"Could not connect to {self.url}: {exc!r}") from exc
        except httpx.TimeoutException as exc:
            raise AgentError("timeout", f"Agent did not reply in time: {exc!r}") from exc
        except httpx.ConnectError as exc:
            raise AgentError("unreachable", f"Could not connect to {self.url}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AgentError("unreachable", f"Request to {self.url} failed: {exc!r}") from exc

        if not 200 <= resp.status_code < 300:
            raise AgentError("http", f"HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            return AgentResponse.model_validate_json(resp.content)
        except ValidationError as exc:
            raise AgentError("invalid", f"Agent reply is not valid: {exc}") from exc

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AgentClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
