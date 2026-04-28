"""add scan risk score

Revision ID: 20260428_0020
Revises: 20260428_0019
Create Date: 2026-04-28 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260428_0020"
down_revision: Union[str, None] = "20260428_0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("risk_score", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "risk_score")
