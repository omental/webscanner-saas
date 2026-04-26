"""add per scan crawler limits

Revision ID: 20260424_0010
Revises: 20260424_0009
Create Date: 2026-04-24 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260424_0010"
down_revision: Union[str, None] = "20260424_0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("max_depth", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("max_pages", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("timeout_seconds", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "timeout_seconds")
    op.drop_column("scans", "max_pages")
    op.drop_column("scans", "max_depth")
