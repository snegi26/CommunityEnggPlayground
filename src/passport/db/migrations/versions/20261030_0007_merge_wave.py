"""Merge the parallel controls, documents, and connectors branches.

Revision ID: 0007
Revises: 0004, 0005, 0006
Create Date: 2026-10-30
"""

from collections.abc import Sequence

revision: str = "0007"
down_revision: str | tuple[str, ...] | None = ("0004", "0005", "0006")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
