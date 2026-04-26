"""add scan_reports table

Revision ID: 20260425_0016
Revises: 20260425_0015
Create Date: 2026-04-25 23:38:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260425_0016"
down_revision: Union[str, None] = "20260425_0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("generated_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "provider",
            sa.String(length=100),
            server_default="openrouter",
            nullable=False,
        ),
        sa.Column("model", sa.String(length=255), nullable=False),
        sa.Column("report_text", sa.Text(), nullable=False),
        sa.Column("pdf_path", sa.String(length=1024), nullable=True),
        sa.Column(
            "status",
            sa.String(length=50),
            server_default="completed",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_reports_scan_id_scans"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_scan_reports_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["generated_by_user_id"],
            ["users.id"],
            name=op.f("fk_scan_reports_generated_by_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_reports")),
    )
    op.create_index(
        op.f("ix_scan_reports_id"), "scan_reports", ["id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_reports_id"), table_name="scan_reports")
    op.drop_table("scan_reports")
