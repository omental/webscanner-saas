"""add subscription state and payment method settings

Revision ID: 20260425_0013
Revises: 20260425_0012
Create Date: 2026-04-25 13:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260425_0013"
down_revision: Union[str, None] = "20260425_0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "subscription_status",
            sa.String(length=50),
            server_default="active",
            nullable=False,
        ),
    )
    op.add_column(
        "organizations",
        sa.Column("subscription_start", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("subscription_end", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "payment_methods",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("config_json", sa.JSON(), nullable=True),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_payment_methods_id"), "payment_methods", ["id"], unique=False)

    for name, slug in (
        ("Stripe", "stripe"),
        ("PayPal", "paypal"),
        ("Bank Transfer", "bank_transfer"),
    ):
        op.execute(
            sa.text(
                """
                INSERT INTO payment_methods (name, slug, is_active)
                SELECT :name, :slug, false
                WHERE NOT EXISTS (
                    SELECT 1 FROM payment_methods WHERE slug = :slug
                )
                """
            ).bindparams(name=name, slug=slug)
        )


def downgrade() -> None:
    op.drop_index(op.f("ix_payment_methods_id"), table_name="payment_methods")
    op.drop_table("payment_methods")
    op.drop_column("organizations", "trial_ends_at")
    op.drop_column("organizations", "subscription_end")
    op.drop_column("organizations", "subscription_start")
    op.drop_column("organizations", "subscription_status")
