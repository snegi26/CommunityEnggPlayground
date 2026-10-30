"""Who made a change: a person, or the agent with its run, model, and prompt (KTD8)."""

import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class Human:
    user_id: uuid.UUID
    # True when an external (consultant) member acts for a client org (R21).
    on_behalf_of_org: bool = False


@dataclass(frozen=True)
class Agent:
    run_id: uuid.UUID
    model_id: str
    prompt_version: str


Actor = Human | Agent


class AgentNotPermittedError(PermissionError):
    """A human-only operation was invoked by the agent (KTD10)."""


def require_human(actor: Actor) -> Human:
    if not isinstance(actor, Human):
        raise AgentNotPermittedError("this operation is reserved for people")
    return actor
