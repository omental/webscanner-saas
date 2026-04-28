"""add finding deduplication key

Revision ID: 20260428_0019
Revises: 20260428_0018
Create Date: 2026-04-28 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260428_0019"
down_revision: Union[str, None] = "20260428_0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("deduplication_key", sa.String(length=255), nullable=True),
    )
    op.create_index(
        op.f("ix_findings_deduplication_key"),
        "findings",
        ["deduplication_key"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_deduplication_key"), table_name="findings")
    op.drop_column("findings", "deduplication_key")
