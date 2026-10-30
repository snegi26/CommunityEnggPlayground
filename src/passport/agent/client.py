"""The model client behind a small protocol, so tests inject a stub and never reach the network.

Drafting calls the Anthropic Messages API (KTD4). Forced ``tool_choice`` is rejected by the
current models, so requests use ``auto`` with ``strict`` tool schemas and the prompt names the
tool to call. Server-side refusal fallback is requested in its ``"default"`` form, which runs
the requested model alone where fallbacks are not supported.
"""

import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

import anthropic
from anthropic import Omit, omit
from anthropic.types.beta import (
    BetaMessage,
    BetaMessageParam,
    BetaOutputConfigParam,
    BetaToolParam,
)

DEFAULT_DRAFTING_MODEL = "claude-sonnet-5-5"
MODEL_ENV_VAR = "PASSPORT_DRAFTING_MODEL"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Non-streaming requests stay under the SDK's HTTP timeout at this size.
MAX_TOKENS = 16000


def drafting_model() -> str:
    """The model id drafting runs on: ``PASSPORT_DRAFTING_MODEL``, else the default."""
    return os.environ.get(MODEL_ENV_VAR) or DEFAULT_DRAFTING_MODEL


@dataclass(frozen=True)
class ModelRequest:
    model: str
    system: str
    messages: Sequence[BetaMessageParam]
    tools: Sequence[BetaToolParam] = ()
    # Structured-output format (``output_config.format``), for calls that return JSON.
    output_format: dict[str, Any] | None = None
    max_tokens: int = MAX_TOKENS


class ModelClient(Protocol):
    def send(self, request: ModelRequest) -> BetaMessage: ...


class AnthropicModelClient:
    """``ModelClient`` over the Anthropic SDK; credentials resolve from the environment."""

    def __init__(self, client: anthropic.Anthropic | None = None) -> None:
        self._client = client

    def _sdk(self) -> anthropic.Anthropic:
        if self._client is None:
            self._client = anthropic.Anthropic()
        return self._client

    def send(self, request: ModelRequest) -> BetaMessage:
        tools = list(request.tools)
        output_config: BetaOutputConfigParam | Omit = omit
        if request.output_format is not None:
            output_config = cast(BetaOutputConfigParam, {"format": request.output_format})
        return self._sdk().beta.messages.create(
            model=request.model,
            max_tokens=request.max_tokens,
            system=request.system,
            messages=list(request.messages),
            tools=tools if tools else omit,
            tool_choice={"type": "auto"} if tools else omit,
            output_config=output_config,
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
