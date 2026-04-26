"""add page body excerpt

Revision ID: 20260423_0005
Revises: 20260423_0004
Create Date: 2026-04-23 01:40:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260423_0005"
down_revision: Union[str, None] = "20260423_0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_pages",
        sa.Column("response_body_excerpt", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_pages", "response_body_excerpt")
