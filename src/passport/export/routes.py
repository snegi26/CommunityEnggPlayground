"""``GET /orgs/{org_id}/export``: download the auditor export ZIP (owner-only)."""

from fastapi import APIRouter, Response

from passport.auth.deps import DbSession, InOrg, require_roles
from passport.controls.models import Framework
from passport.export.builder import generate_export
from passport.tenancy.models import Role

router = APIRouter()


@router.get("/orgs/{org_id}/export")
def download_export(ctx: InOrg, db: DbSession, framework: Framework) -> Response:
    require_roles(ctx, Role.OWNER)
    export = generate_export(db, ctx.org_id, ctx.actor, framework)
    return Response(
        content=export.data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{export.filename}"'},
    )
