"""add scheduled scans

Revision ID: 20260429_0023
Revises: 20260429_0022
Create Date: 2026-04-29 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260429_0023"
down_revision: Union[str, None] = "20260429_0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("scan_profile", sa.String(length=50), nullable=True),
        sa.Column("frequency", sa.String(length=50), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
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
            ["created_by_user_id"],
            ["users.id"],
            name=op.f("fk_scheduled_scans_created_by_user_id_users"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_scheduled_scans_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_scheduled_scans_target_id_targets"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scheduled_scans")),
    )
    op.create_index(
        op.f("ix_scheduled_scans_id"),
        "scheduled_scans",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scheduled_scans_next_run_at"),
        "scheduled_scans",
        ["next_run_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scheduled_scans_is_active"),
        "scheduled_scans",
        ["is_active"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_scheduled_scans_is_active"), table_name="scheduled_scans")
    op.drop_index(op.f("ix_scheduled_scans_next_run_at"), table_name="scheduled_scans")
    op.drop_index(op.f("ix_scheduled_scans_id"), table_name="scheduled_scans")
    op.drop_table("scheduled_scans")
