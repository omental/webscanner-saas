"""add wordfence vulnerabilities

Revision ID: 20260424_0009
Revises: 20260424_0008
Create Date: 2026-04-24 00:45:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260424_0009"
down_revision: Union[str, None] = "20260424_0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "wordfence_vulnerabilities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("wordfence_id", sa.String(length=128), nullable=True),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("software_type", sa.String(length=32), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=50), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("affected_version_start", sa.String(length=100), nullable=True),
        sa.Column("affected_version_end", sa.String(length=100), nullable=True),
        sa.Column("patched_version", sa.String(length=100), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "row_updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_wordfence_vulnerabilities")),
    )
    op.create_index(
        op.f("ix_wordfence_vulnerabilities_id"),
        "wordfence_vulnerabilities",
        ["id"],
        unique=False,
    )
    op.create_index(
        "ix_wordfence_vulnerabilities_dedupe",
        "wordfence_vulnerabilities",
        ["wordfence_id", "slug", "affected_version_start", "affected_version_end"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_wordfence_vulnerabilities_dedupe",
        table_name="wordfence_vulnerabilities",
    )
    op.drop_index(
        op.f("ix_wordfence_vulnerabilities_id"),
        table_name="wordfence_vulnerabilities",
    )
    op.drop_table("wordfence_vulnerabilities")
