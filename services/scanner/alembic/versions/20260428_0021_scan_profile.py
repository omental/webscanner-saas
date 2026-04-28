"""add scan profile

Revision ID: 20260428_0021
Revises: 20260428_0020
Create Date: 2026-04-28 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260428_0021"
down_revision: Union[str, None] = "20260428_0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("scan_profile", sa.String(length=50), nullable=True),
    )
    op.execute("UPDATE scans SET scan_profile = 'standard' WHERE scan_profile IS NULL")


def downgrade() -> None:
    op.drop_column("scans", "scan_profile")
