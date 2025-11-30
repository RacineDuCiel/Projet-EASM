"""Add hostname to ScopeType enum

Revision ID: a0c3550f5556
Revises: 0359462a2524
Create Date: 2025-11-29 22:42:36.165648

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a0c3550f5556'
down_revision = '0359462a2524'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add 'hostname' value to the ScopeType enum
    # PostgreSQL requires ALTER TYPE command
    op.execute("ALTER TYPE scopetype ADD VALUE IF NOT EXISTS 'hostname'")


def downgrade() -> None:
    # Downgrading enums in PostgreSQL is complex and risky
    # We don't implement it to avoid data loss
    # If you need to remove 'hostname', manually migrate data first
    pass
