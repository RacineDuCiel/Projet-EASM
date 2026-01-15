"""add_scan_id_to_vulnerabilities

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-01-15 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'd3e4f5a6b7c8'
down_revision = 'c2d3e4f5a6b7'
branch_labels = None
depends_on = None


def upgrade():
    # Add scan_id column to vulnerabilities table
    op.add_column('vulnerabilities', sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=True))

    # Add foreign key constraint
    op.create_foreign_key(
        'fk_vulnerabilities_scan_id',
        'vulnerabilities', 'scans',
        ['scan_id'], ['id'],
        ondelete='SET NULL'
    )

    # Add indexes for performance
    op.create_index('ix_vulnerabilities_scan_id', 'vulnerabilities', ['scan_id'])
    op.create_index('ix_vulnerabilities_scan_title', 'vulnerabilities', ['scan_id', 'title'])


def downgrade():
    # Remove indexes
    op.drop_index('ix_vulnerabilities_scan_title', table_name='vulnerabilities')
    op.drop_index('ix_vulnerabilities_scan_id', table_name='vulnerabilities')

    # Remove foreign key
    op.drop_constraint('fk_vulnerabilities_scan_id', 'vulnerabilities', type_='foreignkey')

    # Remove column
    op.drop_column('vulnerabilities', 'scan_id')
