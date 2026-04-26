"""add response headers and finding totals

Revision ID: 20260423_0004
Revises: 20260423_0003
Create Date: 2026-04-23 01:20:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260423_0004"
down_revision: Union[str, None] = "20260423_0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_pages",
        sa.Column("response_headers", sa.JSON(), nullable=True),
    )
    op.add_column(
        "scans",
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("scans", "total_findings")
    op.drop_column("scan_pages", "response_headers")
