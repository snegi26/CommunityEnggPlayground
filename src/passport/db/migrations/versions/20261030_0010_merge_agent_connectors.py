"""Merge the parallel agent-runs and connection-setups branches.

Revision ID: 0010
Revises: 0008, 0009
Create Date: 2026-10-30
"""

from collections.abc import Sequence

revision: str = "0010"
down_revision: str | tuple[str, ...] | None = ("0008", "0009")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
