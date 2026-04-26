"""add vulnerability intelligence tables

Revision ID: 20260424_0006
Revises: 20260423_0005
Create Date: 2026-04-24 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260424_0006"
down_revision: Union[str, None] = "20260423_0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vuln_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("primary_id", sa.String(length=255), nullable=False),
        sa.Column("source_priority", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.String(), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("has_cve", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("has_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "has_public_exploit", sa.Boolean(), nullable=False, server_default=sa.false()
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vuln_records")),
        sa.UniqueConstraint("primary_id", name=op.f("uq_vuln_records_primary_id")),
    )
    op.create_index(op.f("ix_vuln_records_id"), "vuln_records", ["id"], unique=False)
    op.create_index(
        op.f("ix_vuln_records_cve_id"), "vuln_records", ["cve_id"], unique=False
    )

    op.create_table(
        "vuln_aliases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("vuln_record_id", sa.Integer(), nullable=False),
        sa.Column("alias_type", sa.String(length=50), nullable=False),
        sa.Column("alias_value", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(
            ["vuln_record_id"],
            ["vuln_records.id"],
            name=op.f("fk_vuln_aliases_vuln_record_id_vuln_records"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vuln_aliases")),
    )
    op.create_index(op.f("ix_vuln_aliases_id"), "vuln_aliases", ["id"], unique=False)

    op.create_table(
        "vuln_affected_products",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("vuln_record_id", sa.Integer(), nullable=False),
        sa.Column("product_name", sa.String(length=255), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("ecosystem", sa.String(length=100), nullable=True),
        sa.Column("package_name", sa.String(length=255), nullable=True),
        sa.Column("version_exact", sa.String(length=255), nullable=True),
        sa.Column("version_start", sa.String(length=255), nullable=True),
        sa.Column("version_end", sa.String(length=255), nullable=True),
        sa.Column("cpe", sa.String(length=1024), nullable=True),
        sa.Column("purl", sa.String(length=1024), nullable=True),
        sa.ForeignKeyConstraint(
            ["vuln_record_id"],
            ["vuln_records.id"],
            name=op.f(
                "fk_vuln_affected_products_vuln_record_id_vuln_records"
            ),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vuln_affected_products")),
    )
    op.create_index(
        op.f("ix_vuln_affected_products_id"),
        "vuln_affected_products",
        ["id"],
        unique=False,
    )

    op.create_table(
        "kev_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=False),
        sa.Column("vendor_project", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("vulnerability_name", sa.String(length=500), nullable=True),
        sa.Column("date_added", sa.DateTime(timezone=True), nullable=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kev_entries")),
        sa.UniqueConstraint("cve_id", name=op.f("uq_kev_entries_cve_id")),
    )
    op.create_index(op.f("ix_kev_entries_id"), "kev_entries", ["id"], unique=False)

    op.create_table(
        "ghsa_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ghsa_id", sa.String(length=64), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=50), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("permalink", sa.String(length=1024), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ghsa_records")),
        sa.UniqueConstraint("ghsa_id", name=op.f("uq_ghsa_records_ghsa_id")),
    )
    op.create_index(op.f("ix_ghsa_records_id"), "ghsa_records", ["id"], unique=False)

    op.create_table(
        "osv_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("osv_id", sa.String(length=128), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ecosystem_specific", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_osv_records")),
        sa.UniqueConstraint("osv_id", name=op.f("uq_osv_records_osv_id")),
    )
    op.create_index(op.f("ix_osv_records_id"), "osv_records", ["id"], unique=False)

    op.create_table(
        "exploitdb_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("edb_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("product_name", sa.String(length=255), nullable=True),
        sa.Column("exploit_type", sa.String(length=100), nullable=True),
        sa.Column("platform", sa.String(length=100), nullable=True),
        sa.Column("author", sa.String(length=255), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exploit_url", sa.String(length=1024), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_exploitdb_entries")),
        sa.UniqueConstraint("edb_id", name=op.f("uq_exploitdb_entries_edb_id")),
    )
    op.create_index(
        op.f("ix_exploitdb_entries_id"), "exploitdb_entries", ["id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_exploitdb_entries_id"), table_name="exploitdb_entries")
    op.drop_table("exploitdb_entries")
    op.drop_index(op.f("ix_osv_records_id"), table_name="osv_records")
    op.drop_table("osv_records")
    op.drop_index(op.f("ix_ghsa_records_id"), table_name="ghsa_records")
    op.drop_table("ghsa_records")
    op.drop_index(op.f("ix_kev_entries_id"), table_name="kev_entries")
    op.drop_table("kev_entries")
    op.drop_index(
        op.f("ix_vuln_affected_products_id"), table_name="vuln_affected_products"
    )
    op.drop_table("vuln_affected_products")
    op.drop_index(op.f("ix_vuln_aliases_id"), table_name="vuln_aliases")
    op.drop_table("vuln_aliases")
    op.drop_index(op.f("ix_vuln_records_cve_id"), table_name="vuln_records")
    op.drop_index(op.f("ix_vuln_records_id"), table_name="vuln_records")
    op.drop_table("vuln_records")
