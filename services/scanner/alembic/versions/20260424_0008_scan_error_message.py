"""add scan error message

Revision ID: 20260424_0008
Revises: 20260424_0007
Create Date: 2026-04-24 03:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260424_0008"
down_revision: Union[str, None] = "20260424_0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("error_message", sa.String(length=1000), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "error_message")
