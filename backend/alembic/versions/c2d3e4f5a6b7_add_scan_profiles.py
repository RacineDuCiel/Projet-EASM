"""add_scan_profiles

Replace ScanType/ScanDepth with ScanProfile-based architecture.
Add AssetCriticality, ScanPhase, and delta scanning support.

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-01-15 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY


# revision identifiers, used by Alembic.
revision: str = 'c2d3e4f5a6b7'
down_revision: Union[str, None] = 'b1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # === Create new enum types ===

    # ScanProfile enum
    scan_profile_enum = sa.Enum(
        'discovery', 'quick_assessment', 'standard_assessment',
        'full_audit', 'continuous_monitoring',
        name='scanprofile'
    )
    scan_profile_enum.create(op.get_bind(), checkfirst=True)

    # ScanPhase enum
    scan_phase_enum = sa.Enum(
        'asset_discovery', 'service_enumeration', 'tech_detection',
        'vuln_assessment', 'deep_analysis',
        name='scanphase'
    )
    scan_phase_enum.create(op.get_bind(), checkfirst=True)

    # AssetCriticality enum
    asset_criticality_enum = sa.Enum(
        'critical', 'high', 'medium', 'low', 'unclassified',
        name='assetcriticality'
    )
    asset_criticality_enum.create(op.get_bind(), checkfirst=True)

    # === Update assets table ===
    op.add_column('assets', sa.Column(
        'criticality',
        sa.Enum('critical', 'high', 'medium', 'low', 'unclassified', name='assetcriticality'),
        nullable=False,
        server_default='unclassified'
    ))
    op.add_column('assets', sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('assets', sa.Column('scan_count', sa.Integer(), nullable=False, server_default='0'))

    # === Update scans table ===
    # Add new columns first
    op.add_column('scans', sa.Column(
        'scan_profile',
        sa.Enum('discovery', 'quick_assessment', 'standard_assessment', 'full_audit', 'continuous_monitoring', name='scanprofile'),
        nullable=True  # Temporarily nullable for migration
    ))
    op.add_column('scans', sa.Column('selected_phases', ARRAY(sa.String()), nullable=True))
    op.add_column('scans', sa.Column(
        'current_phase',
        sa.Enum('asset_discovery', 'service_enumeration', 'tech_detection', 'vuln_assessment', 'deep_analysis', name='scanphase'),
        nullable=True
    ))
    op.add_column('scans', sa.Column('is_delta_scan', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('scans', sa.Column('delta_threshold_hours', sa.Integer(), nullable=True))
    op.add_column('scans', sa.Column('assets_scanned', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scans', sa.Column('assets_skipped', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scans', sa.Column('vulns_found', sa.Integer(), nullable=False, server_default='0'))

    # Migrate existing data: map old scan_depth to new scan_profile
    # fast -> quick_assessment, deep -> full_audit
    op.execute("""
        UPDATE scans
        SET scan_profile = CASE
            WHEN scan_depth = 'fast' THEN 'quick_assessment'::scanprofile
            WHEN scan_depth = 'deep' THEN 'full_audit'::scanprofile
            ELSE 'standard_assessment'::scanprofile
        END
    """)

    # Now make scan_profile non-nullable
    op.alter_column('scans', 'scan_profile', nullable=False, server_default='standard_assessment')

    # Remove old columns from scans
    op.drop_column('scans', 'scan_type')
    op.drop_column('scans', 'scan_depth')

    # === Update programs table ===
    op.add_column('programs', sa.Column(
        'default_scan_profile',
        sa.Enum('discovery', 'quick_assessment', 'standard_assessment', 'full_audit', 'continuous_monitoring', name='scanprofile'),
        nullable=True  # Temporarily nullable for migration
    ))
    op.add_column('programs', sa.Column('delta_scan_threshold_hours', sa.Integer(), nullable=False, server_default='24'))

    # Migrate existing data: map old scan_depth to new default_scan_profile
    op.execute("""
        UPDATE programs
        SET default_scan_profile = CASE
            WHEN scan_depth = 'fast' THEN 'quick_assessment'::scanprofile
            WHEN scan_depth = 'deep' THEN 'full_audit'::scanprofile
            ELSE 'standard_assessment'::scanprofile
        END
    """)

    # Now make default_scan_profile non-nullable
    op.alter_column('programs', 'default_scan_profile', nullable=False, server_default='standard_assessment')

    # Remove old column from programs
    op.drop_column('programs', 'scan_depth')

    # === Drop old enum types ===
    sa.Enum(name='scantype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='scandepth').drop(op.get_bind(), checkfirst=True)


def downgrade() -> None:
    # === Recreate old enum types ===
    scantype_enum = sa.Enum('passive', 'active', 'full', name='scantype')
    scantype_enum.create(op.get_bind(), checkfirst=True)

    scandepth_enum = sa.Enum('fast', 'deep', name='scandepth')
    scandepth_enum.create(op.get_bind(), checkfirst=True)

    # === Restore programs table ===
    op.add_column('programs', sa.Column('scan_depth', sa.Enum('fast', 'deep', name='scandepth'), nullable=True))

    # Migrate data back
    op.execute("""
        UPDATE programs
        SET scan_depth = CASE
            WHEN default_scan_profile IN ('discovery', 'quick_assessment', 'continuous_monitoring') THEN 'fast'::scandepth
            ELSE 'deep'::scandepth
        END
    """)

    op.alter_column('programs', 'scan_depth', nullable=False, server_default='fast')
    op.drop_column('programs', 'delta_scan_threshold_hours')
    op.drop_column('programs', 'default_scan_profile')

    # === Restore scans table ===
    op.add_column('scans', sa.Column('scan_type', sa.Enum('passive', 'active', 'full', name='scantype'), nullable=True))
    op.add_column('scans', sa.Column('scan_depth', sa.Enum('fast', 'deep', name='scandepth'), nullable=True))

    # Migrate data back
    op.execute("""
        UPDATE scans
        SET scan_type = 'full'::scantype,
            scan_depth = CASE
                WHEN scan_profile IN ('discovery', 'quick_assessment', 'continuous_monitoring') THEN 'fast'::scandepth
                ELSE 'deep'::scandepth
            END
    """)

    op.alter_column('scans', 'scan_type', nullable=False)
    op.alter_column('scans', 'scan_depth', nullable=False, server_default='fast')

    op.drop_column('scans', 'vulns_found')
    op.drop_column('scans', 'assets_skipped')
    op.drop_column('scans', 'assets_scanned')
    op.drop_column('scans', 'delta_threshold_hours')
    op.drop_column('scans', 'is_delta_scan')
    op.drop_column('scans', 'current_phase')
    op.drop_column('scans', 'selected_phases')
    op.drop_column('scans', 'scan_profile')

    # === Restore assets table ===
    op.drop_column('assets', 'scan_count')
    op.drop_column('assets', 'last_scanned_at')
    op.drop_column('assets', 'criticality')

    # === Drop new enum types ===
    sa.Enum(name='assetcriticality').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='scanphase').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='scanprofile').drop(op.get_bind(), checkfirst=True)
