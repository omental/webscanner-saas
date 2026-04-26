"""add finding references

Revision ID: 20260424_0007
Revises: 20260424_0006
Create Date: 2026-04-24 02:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260424_0007"
down_revision: Union[str, None] = "20260424_0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_references",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("ref_type", sa.String(length=50), nullable=False),
        sa.Column("ref_value", sa.String(length=255), nullable=False),
        sa.Column("ref_url", sa.String(length=1024), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_references_finding_id_findings"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_references")),
    )
    op.create_index(
        op.f("ix_finding_references_id"), "finding_references", ["id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_references_id"), table_name="finding_references")
    op.drop_table("finding_references")
