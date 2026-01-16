"""add_auto_scan_configuration

Add auto_scan_enabled and delta_scan_enabled columns to programs.
Remove continuous_monitoring from ScanProfile enum.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-01-16 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e4f5a6b7c8d9'
down_revision = 'd3e4f5a6b7c8'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add new columns to programs table
    op.add_column('programs', sa.Column('auto_scan_enabled', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('programs', sa.Column('delta_scan_enabled', sa.Boolean(), nullable=False, server_default='false'))

    # Step 2: Migrate existing data
    # If scan_frequency != 'never', set auto_scan_enabled = true
    op.execute("""
        UPDATE programs
        SET auto_scan_enabled = true
        WHERE scan_frequency != 'never'
    """)

    # Step 3: Update any programs using continuous_monitoring to standard_assessment
    op.execute("""
        UPDATE programs
        SET default_scan_profile = 'standard_assessment'
        WHERE default_scan_profile = 'continuous_monitoring'
    """)

    # Step 4: Update any scans using continuous_monitoring to full_audit
    op.execute("""
        UPDATE scans
        SET scan_profile = 'full_audit'
        WHERE scan_profile = 'continuous_monitoring'
    """)

    # Step 5: Remove continuous_monitoring from enum
    # In PostgreSQL, we need to:
    # 1. Drop the default constraints
    # 2. Alter columns to VARCHAR
    # 3. Drop the old enum
    # 4. Create new enum
    # 5. Alter columns back to enum
    # 6. Re-add default constraints

    # Drop default constraints first
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile DROP DEFAULT")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile DROP DEFAULT")

    # Alter columns to VARCHAR
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile TYPE VARCHAR(50) USING default_scan_profile::text")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile TYPE VARCHAR(50) USING scan_profile::text")

    # Drop the old enum
    op.execute("DROP TYPE IF EXISTS scanprofile")

    # Create the new enum without continuous_monitoring
    op.execute("""
        CREATE TYPE scanprofile AS ENUM (
            'discovery',
            'quick_assessment',
            'standard_assessment',
            'full_audit'
        )
    """)

    # Convert back to enum
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile TYPE scanprofile USING default_scan_profile::scanprofile")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile TYPE scanprofile USING scan_profile::scanprofile")

    # Re-add default values
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile SET DEFAULT 'standard_assessment'")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile SET DEFAULT 'standard_assessment'")


def downgrade():
    # Drop defaults
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile DROP DEFAULT")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile DROP DEFAULT")

    # Alter to VARCHAR
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile TYPE VARCHAR(50) USING default_scan_profile::text")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile TYPE VARCHAR(50) USING scan_profile::text")

    # Drop current enum
    op.execute("DROP TYPE IF EXISTS scanprofile")

    # Create enum with continuous_monitoring
    op.execute("""
        CREATE TYPE scanprofile AS ENUM (
            'discovery',
            'quick_assessment',
            'standard_assessment',
            'full_audit',
            'continuous_monitoring'
        )
    """)

    # Convert back to enum
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile TYPE scanprofile USING default_scan_profile::scanprofile")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile TYPE scanprofile USING scan_profile::scanprofile")

    # Re-add defaults
    op.execute("ALTER TABLE programs ALTER COLUMN default_scan_profile SET DEFAULT 'standard_assessment'")
    op.execute("ALTER TABLE scans ALTER COLUMN scan_profile SET DEFAULT 'standard_assessment'")

    # Remove new columns
    op.drop_column('programs', 'delta_scan_enabled')
    op.drop_column('programs', 'auto_scan_enabled')
