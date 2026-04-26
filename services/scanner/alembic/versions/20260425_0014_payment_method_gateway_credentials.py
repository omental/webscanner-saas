"""add payment method gateway credentials

Revision ID: 20260425_0014
Revises: 20260425_0013
Create Date: 2026-04-25 15:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260425_0014"
down_revision: Union[str, None] = "20260425_0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "payment_methods",
        sa.Column(
            "mode",
            sa.String(length=20),
            server_default="test",
            nullable=False,
        ),
    )
    op.add_column(
        "payment_methods", sa.Column("public_key", sa.String(length=2000), nullable=True)
    )
    op.add_column(
        "payment_methods",
        sa.Column("encrypted_secret_key", sa.String(length=4000), nullable=True),
    )
    op.add_column(
        "payment_methods", sa.Column("webhook_url", sa.String(length=1000), nullable=True)
    )
    op.add_column(
        "payment_methods",
        sa.Column("encrypted_webhook_secret", sa.String(length=4000), nullable=True),
    )
    op.add_column(
        "payment_methods",
        sa.Column(
            "webhook_enabled",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.execute(
        sa.text(
            """
            UPDATE payment_methods
            SET webhook_url = '/api/v1/webhooks/' || slug
            WHERE slug IN ('stripe', 'paypal')
            """
        )
    )


def downgrade() -> None:
    op.drop_column("payment_methods", "webhook_enabled")
    op.drop_column("payment_methods", "encrypted_webhook_secret")
    op.drop_column("payment_methods", "webhook_url")
    op.drop_column("payment_methods", "encrypted_secret_key")
    op.drop_column("payment_methods", "public_key")
    op.drop_column("payment_methods", "mode")
