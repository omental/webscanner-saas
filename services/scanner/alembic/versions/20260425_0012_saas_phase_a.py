"""add saas phase a tenant tables

Revision ID: 20260425_0012
Revises: 20260425_0011
Create Date: 2026-04-25 12:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260425_0012"
down_revision: Union[str, None] = "20260425_0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "packages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("scan_limit_per_week", sa.Integer(), nullable=False),
        sa.Column("price_monthly", sa.Numeric(10, 2), nullable=False),
        sa.Column("status", sa.String(length=50), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_packages_id"), "packages", ["id"], unique=False)

    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("package_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=50), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["package_id"], ["packages.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_organizations_id"), "organizations", ["id"], unique=False)

    op.add_column("users", sa.Column("organization_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_users_organization_id_organizations"),
        "users",
        "organizations",
        ["organization_id"],
        ["id"],
    )
    op.add_column("targets", sa.Column("organization_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_targets_organization_id_organizations"),
        "targets",
        "organizations",
        ["organization_id"],
        ["id"],
    )
    op.add_column("scans", sa.Column("organization_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_scans_organization_id_organizations"),
        "scans",
        "organizations",
        ["organization_id"],
        ["id"],
    )

    op.execute(
        """
        INSERT INTO packages (name, slug, scan_limit_per_week, price_monthly, status)
        SELECT 'Bronze', 'bronze', 1, 0, 'active'
        WHERE NOT EXISTS (SELECT 1 FROM packages WHERE slug = 'bronze')
        """
    )
    op.execute(
        """
        INSERT INTO packages (name, slug, scan_limit_per_week, price_monthly, status)
        SELECT 'Silver', 'silver', 10, 0, 'active'
        WHERE NOT EXISTS (SELECT 1 FROM packages WHERE slug = 'silver')
        """
    )
    op.execute(
        """
        INSERT INTO packages (name, slug, scan_limit_per_week, price_monthly, status)
        SELECT 'Gold', 'gold', 100, 0, 'active'
        WHERE NOT EXISTS (SELECT 1 FROM packages WHERE slug = 'gold')
        """
    )
    op.execute(
        """
        INSERT INTO organizations (name, slug, package_id, status)
        SELECT 'Default Organization', 'default-organization',
            (SELECT id FROM packages WHERE slug = 'bronze'),
            'active'
        WHERE EXISTS (SELECT 1 FROM users WHERE role != 'super_admin')
        AND NOT EXISTS (SELECT 1 FROM organizations WHERE slug = 'default-organization')
        """
    )
    op.execute(
        """
        UPDATE users
        SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-organization')
        WHERE role != 'super_admin' AND organization_id IS NULL
        """
    )
    op.execute(
        """
        UPDATE targets
        SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-organization')
        WHERE organization_id IS NULL
        """
    )
    op.execute(
        """
        UPDATE scans
        SET organization_id = (SELECT id FROM organizations WHERE slug = 'default-organization')
        WHERE organization_id IS NULL
        """
    )


def downgrade() -> None:
    op.drop_constraint(op.f("fk_scans_organization_id_organizations"), "scans", type_="foreignkey")
    op.drop_column("scans", "organization_id")
    op.drop_constraint(op.f("fk_targets_organization_id_organizations"), "targets", type_="foreignkey")
    op.drop_column("targets", "organization_id")
    op.drop_constraint(op.f("fk_users_organization_id_organizations"), "users", type_="foreignkey")
    op.drop_column("users", "organization_id")
    op.drop_index(op.f("ix_organizations_id"), table_name="organizations")
    op.drop_table("organizations")
    op.drop_index(op.f("ix_packages_id"), table_name="packages")
    op.drop_table("packages")
