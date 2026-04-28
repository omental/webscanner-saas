"""add retest scan links and finding comparison status

Revision ID: 20260429_0022
Revises: 20260428_0021
Create Date: 2026-04-29 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260429_0022"
down_revision: Union[str, None] = "20260428_0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("previous_scan_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_scans_previous_scan_id_scans"),
        "scans",
        "scans",
        ["previous_scan_id"],
        ["id"],
    )
    op.add_column(
        "findings",
        sa.Column("comparison_status", sa.String(length=50), nullable=True),
    )
    op.create_index(
        op.f("ix_findings_comparison_status"),
        "findings",
        ["comparison_status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_comparison_status"), table_name="findings")
    op.drop_column("findings", "comparison_status")
    op.drop_constraint(
        op.f("fk_scans_previous_scan_id_scans"),
        "scans",
        type_="foreignkey",
    )
    op.drop_column("scans", "previous_scan_id")
