"""normalize user roles and statuses

Revision ID: 20260425_0011
Revises: 20260424_0010
Create Date: 2026-04-25 00:11:00.000000

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "20260425_0011"
down_revision: Union[str, None] = "20260424_0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("UPDATE users SET role = 'admin' WHERE role = 'owner'")
    op.execute("UPDATE users SET role = 'team_member' WHERE role IN ('analyst', 'viewer')")
    op.execute("UPDATE users SET status = 'inactive' WHERE status IN ('disabled', 'suspended')")
    op.execute("UPDATE users SET status = 'active' WHERE status = 'invited'")


def downgrade() -> None:
    op.execute("UPDATE users SET role = 'owner' WHERE role = 'admin'")
    op.execute("UPDATE users SET role = 'analyst' WHERE role = 'team_member'")
    op.execute("UPDATE users SET status = 'disabled' WHERE status = 'inactive'")
