"""add_port_to_scopes

Revision ID: f9a3b2c1d5e6
Revises: e1f72bb2977b
Create Date: 2026-01-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f9a3b2c1d5e6'
down_revision: Union[str, None] = 'e1f72bb2977b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add port column to scopes table
    op.add_column('scopes', sa.Column('port', sa.Integer(), nullable=True))


def downgrade() -> None:
    # Remove port column from scopes table
    op.drop_column('scopes', 'port')
