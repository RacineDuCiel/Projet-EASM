"""add_scan_depth_and_tech_detection

Revision ID: a7b8c9d0e1f2
Revises: f9a3b2c1d5e6
Create Date: 2026-01-14 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, None] = 'f9a3b2c1d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create ScanDepth enum type
    scandepth_enum = sa.Enum('fast', 'deep', name='scandepth')
    scandepth_enum.create(op.get_bind(), checkfirst=True)

    # Add scan configuration columns to programs table
    op.add_column('programs', sa.Column('scan_depth', sa.Enum('fast', 'deep', name='scandepth'), nullable=False, server_default='fast'))
    op.add_column('programs', sa.Column('custom_ports', sa.String(), nullable=True))
    op.add_column('programs', sa.Column('nuclei_rate_limit', sa.Integer(), nullable=True))
    op.add_column('programs', sa.Column('nuclei_timeout', sa.Integer(), nullable=True))

    # Add scan_depth column to scans table
    op.add_column('scans', sa.Column('scan_depth', sa.Enum('fast', 'deep', name='scandepth'), nullable=False, server_default='fast'))

    # Add technology detection columns to services table
    op.add_column('services', sa.Column('technologies', sa.Text(), nullable=True))
    op.add_column('services', sa.Column('web_server', sa.String(), nullable=True))
    op.add_column('services', sa.Column('waf_detected', sa.String(), nullable=True))
    op.add_column('services', sa.Column('tls_version', sa.String(), nullable=True))
    op.add_column('services', sa.Column('response_time_ms', sa.Integer(), nullable=True))


def downgrade() -> None:
    # Remove technology detection columns from services table
    op.drop_column('services', 'response_time_ms')
    op.drop_column('services', 'tls_version')
    op.drop_column('services', 'waf_detected')
    op.drop_column('services', 'web_server')
    op.drop_column('services', 'technologies')

    # Remove scan_depth column from scans table
    op.drop_column('scans', 'scan_depth')

    # Remove scan configuration columns from programs table
    op.drop_column('programs', 'nuclei_timeout')
    op.drop_column('programs', 'nuclei_rate_limit')
    op.drop_column('programs', 'custom_ports')
    op.drop_column('programs', 'scan_depth')

    # Drop ScanDepth enum type
    sa.Enum(name='scandepth').drop(op.get_bind(), checkfirst=True)
