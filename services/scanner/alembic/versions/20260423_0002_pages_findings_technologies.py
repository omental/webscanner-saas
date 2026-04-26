"""add pages findings and technologies

Revision ID: 20260423_0002
Revises: 20260423_0001
Create Date: 2026-04-23 00:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260423_0002"
down_revision: Union[str, None] = "20260423_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_pages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("response_time_ms", sa.Integer(), nullable=True),
        sa.Column("page_title", sa.String(length=512), nullable=True),
        sa.Column("discovered_from", sa.String(length=2048), nullable=True),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_scan_pages_scan_id_scans")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_pages")),
    )
    op.create_index(op.f("ix_scan_pages_id"), "scan_pages", ["id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("scan_page_id", sa.Integer(), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.String(length=50), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("is_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
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
            ["scan_id"], ["scans.id"], name=op.f("fk_findings_scan_id_scans")
        ),
        sa.ForeignKeyConstraint(
            ["scan_page_id"],
            ["scan_pages.id"],
            name=op.f("fk_findings_scan_page_id_scan_pages"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
    )
    op.create_index(op.f("ix_findings_id"), "findings", ["id"], unique=False)

    op.create_table(
        "detected_technologies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("scan_page_id", sa.Integer(), nullable=True),
        sa.Column("product_name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("version", sa.String(length=100), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("detection_method", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_detected_technologies_scan_id_scans"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_page_id"],
            ["scan_pages.id"],
            name=op.f("fk_detected_technologies_scan_page_id_scan_pages"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detected_technologies")),
    )
    op.create_index(
        op.f("ix_detected_technologies_id"),
        "detected_technologies",
        ["id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_detected_technologies_id"), table_name="detected_technologies"
    )
    op.drop_table("detected_technologies")
    op.drop_index(op.f("ix_findings_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_scan_pages_id"), table_name="scan_pages")
    op.drop_table("scan_pages")
