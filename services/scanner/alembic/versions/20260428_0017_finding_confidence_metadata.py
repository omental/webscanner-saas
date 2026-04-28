"""add finding confidence metadata

Revision ID: 20260428_0017
Revises: 20260425_0016
Create Date: 2026-04-28 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260428_0017"
down_revision: Union[str, None] = "20260425_0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("confidence_level", sa.String(length=50), nullable=True),
    )
    op.add_column("findings", sa.Column("confidence_score", sa.Integer(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("evidence_type", sa.String(length=100), nullable=True),
    )
    op.add_column("findings", sa.Column("verification_steps", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("payload_used", sa.Text(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("affected_parameter", sa.String(length=255), nullable=True),
    )
    op.add_column("findings", sa.Column("response_snippet", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("false_positive_notes", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "false_positive_notes")
    op.drop_column("findings", "response_snippet")
    op.drop_column("findings", "affected_parameter")
    op.drop_column("findings", "payload_used")
    op.drop_column("findings", "verification_steps")
    op.drop_column("findings", "evidence_type")
    op.drop_column("findings", "confidence_score")
    op.drop_column("findings", "confidence_level")
