"""The drafting job. Deferred after a policy version is uploaded and committed.

``passport.jobs.app`` must list ``"passport.agent.jobs"`` in its ``import_paths`` so the
worker registers this task.
"""

import uuid
from typing import Any

from passport.agent.client import AnthropicModelClient, ModelClient
from passport.agent.drafting import draft_claims_for_version, fail_run, start_run
from passport.agent.models import AgentRun
from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context
from passport.jobs import app


def run_drafting(
    org_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    client: ModelClient | None = None,
    model_id: str | None = None,
) -> dict[str, Any]:
    """Create the run record, draft in its own transaction, and record a failure if it fails.

    The run row is committed first so a failed run stays visible with its reason, while
    the failed attempt's claims roll back together.
    """
    sessions = get_sessionmaker()
    with sessions() as session:
        set_org_context(session, org_id)
        run = start_run(session, org_id=org_id, version_id=version_id, model_id=model_id)
        run_id = run.id
        session.commit()

    try:
        with sessions() as session:
            set_org_context(session, org_id)
            stored = session.get(AgentRun, run_id)
            assert stored is not None
            result = draft_claims_for_version(
                session, run=stored, client=client or AnthropicModelClient()
            )
            session.commit()
    except Exception as exc:
        with sessions() as session:
            set_org_context(session, org_id)
            fail_run(session, run_id, f"{type(exc).__name__}: {exc}")
            session.commit()
        raise

    suggestion = result.review_suggestion
    return {
        "run_id": str(run_id),
        "claims": len(result.claims),
        "counts": result.counts,
        "suggested_review_on": suggestion.review_on.isoformat() if suggestion else None,
    }


@app.task(name="passport.agent.draft_claims")
def draft_claims(org_id: str, document_version_id: str) -> dict[str, Any]:
    """Draft claims for one document version with the configured model."""
    return run_drafting(uuid.UUID(org_id), uuid.UUID(document_version_id))
