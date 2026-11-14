"""Shared FastAPI app for the example agents (needs the [examples] extra)."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Literal

import anthropic
import uvicorn
from fastapi import FastAPI, HTTPException

from claude_cli import CliBackendError, complete_via_cli, find_executable
from convert import (
    blocked_side_effects,
    from_anthropic_content,
    to_anthropic_messages,
    to_anthropic_tools,
)
from phantom_redteam.protocol import AgentRequest, AgentResponse

Backend = Literal["anthropic", "claude-cli"]

DEFAULT_MODELS: dict[str, str] = {"anthropic": "claude-haiku-5-5", "claude-cli": "haiku"}


def model_for(backend: Backend) -> str:
    return os.environ.get("PHANTOM_EXAMPLE_MODEL", DEFAULT_MODELS[backend])


def create_app(system_prompt: str, guarded: bool, backend: Backend) -> FastAPI:
    app = FastAPI()
    clients: list[anthropic.Anthropic] = []  # created lazily so import needs no API key
    model = model_for(backend)

    def complete(request: AgentRequest) -> AgentResponse:
        if backend == "claude-cli":
            try:
                return complete_via_cli(system_prompt, request, wrap_untrusted=guarded, model=model)
            except CliBackendError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
        if not clients:
            clients.append(anthropic.Anthropic())
        reply = clients[0].messages.create(
            model=model,
            max_tokens=1024,
            system=system_prompt,
            tools=to_anthropic_tools(request.tools),
            messages=to_anthropic_messages(request.messages, wrap_untrusted=guarded),
        )
        return from_anthropic_content([b.model_dump() for b in reply.content])

    @app.post("/")
    def respond(request: AgentRequest) -> AgentResponse:  # sync: FastAPI runs it in a threadpool
        response = complete(request)
        if guarded and response.tool_calls:
            user_text = " ".join(
                m.content or "" for m in request.messages if m.role == "user"
            )
            blocked = blocked_side_effects(user_text, response.tool_calls)
            if blocked:
                names = ", ".join(c.name for c in blocked)
                return AgentResponse(
                    content=f"I won't run {names} without your explicit confirmation."
                )
        return response

    return app


def choose_backend(requested: str) -> Backend | None:
    if requested != "auto":
        return requested  # type: ignore[return-value]
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if find_executable():
        return "claude-cli"
    return None


def main(system_prompt: str, guarded: bool) -> None:
    parser = argparse.ArgumentParser(description="Phantom example agent")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument(
        "--backend",
        choices=["auto", "anthropic", "claude-cli"],
        default="auto",
        help="auto: anthropic if ANTHROPIC_API_KEY is set, else the local claude CLI",
    )
    args = parser.parse_args()
    backend = choose_backend(args.backend)
    if backend is None:
        print(
            "error: no backend available (set ANTHROPIC_API_KEY or install the claude CLI)",
            file=sys.stderr,
        )
        sys.exit(2)
    print(f"backend: {backend}, model: {model_for(backend)}")
    uvicorn.run(create_app(system_prompt, guarded, backend), host="127.0.0.1", port=args.port)
