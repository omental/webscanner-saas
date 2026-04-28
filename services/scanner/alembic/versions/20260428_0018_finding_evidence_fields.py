"""add finding evidence fields

Revision ID: 20260428_0018
Revises: 20260428_0017
Create Date: 2026-04-28 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260428_0018"
down_revision: Union[str, None] = "20260428_0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("request_url", sa.String(length=2048), nullable=True))
    op.add_column("findings", sa.Column("http_method", sa.String(length=16), nullable=True))
    op.add_column("findings", sa.Column("tested_parameter", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("payload", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("baseline_status_code", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("attack_status_code", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("baseline_response_size", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("attack_response_size", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("baseline_response_time_ms", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("attack_response_time_ms", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("response_diff_summary", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "response_diff_summary")
    op.drop_column("findings", "attack_response_time_ms")
    op.drop_column("findings", "baseline_response_time_ms")
    op.drop_column("findings", "attack_response_size")
    op.drop_column("findings", "baseline_response_size")
    op.drop_column("findings", "attack_status_code")
    op.drop_column("findings", "baseline_status_code")
    op.drop_column("findings", "payload")
    op.drop_column("findings", "tested_parameter")
    op.drop_column("findings", "http_method")
    op.drop_column("findings", "request_url")
