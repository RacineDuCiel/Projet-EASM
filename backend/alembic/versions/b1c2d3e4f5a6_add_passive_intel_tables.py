"""add_passive_intel_tables

Revision ID: b1c2d3e4f5a6
Revises: a7b8c9d0e1f2
Create Date: 2026-01-15 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, None] = 'a7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # === Add new columns to programs table for passive recon config ===
    op.add_column('programs', sa.Column('passive_recon_enabled', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('programs', sa.Column('enable_web_archive', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('programs', sa.Column('enable_url_aggregation', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('programs', sa.Column('enable_crawling', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('programs', sa.Column('shodan_api_key', sa.String(), nullable=True))
    op.add_column('programs', sa.Column('securitytrails_api_key', sa.String(), nullable=True))
    op.add_column('programs', sa.Column('censys_api_id', sa.String(), nullable=True))
    op.add_column('programs', sa.Column('censys_api_secret', sa.String(), nullable=True))

    # === Create dns_records table ===
    op.create_table(
        'dns_records',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('record_type', sa.String(10), nullable=False),
        sa.Column('record_value', sa.Text(), nullable=False),
        sa.Column('ttl', sa.Integer(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_dns_records_asset_id', 'dns_records', ['asset_id'])
    op.create_index('ix_dns_records_type', 'dns_records', ['record_type'])
    op.create_index('ix_dns_records_asset_type', 'dns_records', ['asset_id', 'record_type'])

    # === Create whois_records table ===
    op.create_table(
        'whois_records',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('registrar', sa.String(255), nullable=True),
        sa.Column('creation_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expiration_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('name_servers', sa.Text(), nullable=True),
        sa.Column('registrant_org', sa.String(255), nullable=True),
        sa.Column('registrant_country', sa.String(10), nullable=True),
        sa.Column('registrant_email', sa.String(255), nullable=True),
        sa.Column('dnssec', sa.Boolean(), nullable=True),
        sa.Column('raw_data', sa.Text(), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_whois_records_asset_id', 'whois_records', ['asset_id'])

    # === Create certificates table ===
    op.create_table(
        'certificates',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('service_id', UUID(as_uuid=True), sa.ForeignKey('services.id', ondelete='SET NULL'), nullable=True),
        sa.Column('serial_number', sa.String(255), nullable=True),
        sa.Column('issuer_cn', sa.String(255), nullable=True),
        sa.Column('issuer_org', sa.String(255), nullable=True),
        sa.Column('subject_cn', sa.String(255), nullable=True),
        sa.Column('subject_alt_names', sa.Text(), nullable=True),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=True),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=True),
        sa.Column('signature_algorithm', sa.String(100), nullable=True),
        sa.Column('key_algorithm', sa.String(50), nullable=True),
        sa.Column('key_size', sa.Integer(), nullable=True),
        sa.Column('is_self_signed', sa.Boolean(), nullable=True),
        sa.Column('is_expired', sa.Boolean(), nullable=True),
        sa.Column('is_wildcard', sa.Boolean(), nullable=True),
        sa.Column('fingerprint_sha256', sa.String(64), nullable=True),
        sa.Column('tls_version', sa.String(20), nullable=True),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_certificates_asset_id', 'certificates', ['asset_id'])
    op.create_index('ix_certificates_fingerprint', 'certificates', ['fingerprint_sha256'])
    op.create_index('ix_certificates_expiry', 'certificates', ['not_after'])

    # === Create asn_info table ===
    op.create_table(
        'asn_info',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('asn_number', sa.Integer(), nullable=True),
        sa.Column('asn_name', sa.String(255), nullable=True),
        sa.Column('asn_description', sa.Text(), nullable=True),
        sa.Column('asn_country', sa.String(10), nullable=True),
        sa.Column('bgp_prefix', sa.String(50), nullable=True),
        sa.Column('rir', sa.String(20), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_asn_info_asset_id', 'asn_info', ['asset_id'])
    op.create_index('ix_asn_info_asn_number', 'asn_info', ['asn_number'])

    # === Create historical_urls table ===
    op.create_table(
        'historical_urls',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('archived_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(100), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_historical_urls_asset_id', 'historical_urls', ['asset_id'])
    op.create_index('ix_historical_urls_source', 'historical_urls', ['source'])

    # === Create security_headers table ===
    op.create_table(
        'security_headers',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('service_id', UUID(as_uuid=True), sa.ForeignKey('services.id', ondelete='SET NULL'), nullable=True),
        sa.Column('url', sa.String(500), nullable=True),
        sa.Column('content_security_policy', sa.Text(), nullable=True),
        sa.Column('strict_transport_security', sa.Text(), nullable=True),
        sa.Column('x_frame_options', sa.String(50), nullable=True),
        sa.Column('x_content_type_options', sa.String(50), nullable=True),
        sa.Column('x_xss_protection', sa.String(50), nullable=True),
        sa.Column('referrer_policy', sa.String(100), nullable=True),
        sa.Column('permissions_policy', sa.Text(), nullable=True),
        sa.Column('missing_headers', sa.Text(), nullable=True),
        sa.Column('score', sa.Integer(), nullable=True),
        sa.Column('grade', sa.String(5), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_security_headers_asset_id', 'security_headers', ['asset_id'])
    op.create_index('ix_security_headers_score', 'security_headers', ['score'])

    # === Create favicon_hashes table ===
    op.create_table(
        'favicon_hashes',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('mmh3_hash', sa.String(20), nullable=True),
        sa.Column('md5_hash', sa.String(32), nullable=True),
        sa.Column('sha256_hash', sa.String(64), nullable=True),
        sa.Column('favicon_url', sa.Text(), nullable=True),
        sa.Column('favicon_size', sa.Integer(), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_favicon_hashes_asset_id', 'favicon_hashes', ['asset_id'])
    op.create_index('ix_favicon_hashes_mmh3', 'favicon_hashes', ['mmh3_hash'])

    # === Create shodan_data table ===
    op.create_table(
        'shodan_data',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('open_ports', sa.Text(), nullable=True),
        sa.Column('hostnames', sa.Text(), nullable=True),
        sa.Column('domains', sa.Text(), nullable=True),
        sa.Column('os', sa.String(100), nullable=True),
        sa.Column('isp', sa.String(255), nullable=True),
        sa.Column('org', sa.String(255), nullable=True),
        sa.Column('city', sa.String(100), nullable=True),
        sa.Column('region', sa.String(100), nullable=True),
        sa.Column('country', sa.String(100), nullable=True),
        sa.Column('latitude', sa.String(20), nullable=True),
        sa.Column('longitude', sa.String(20), nullable=True),
        sa.Column('last_update', sa.DateTime(timezone=True), nullable=True),
        sa.Column('vulns', sa.Text(), nullable=True),
        sa.Column('tags', sa.Text(), nullable=True),
        sa.Column('raw_data', sa.Text(), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_shodan_data_asset_id', 'shodan_data', ['asset_id'])
    op.create_index('ix_shodan_data_ip', 'shodan_data', ['ip_address'])

    # === Create crawled_endpoints table ===
    op.create_table(
        'crawled_endpoints',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('method', sa.String(10), server_default='GET'),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(100), nullable=True),
        sa.Column('content_length', sa.Integer(), nullable=True),
        sa.Column('parameters', sa.Text(), nullable=True),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('is_js_file', sa.Boolean(), server_default='false'),
        sa.Column('is_api_endpoint', sa.Boolean(), server_default='false'),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_crawled_endpoints_asset_id', 'crawled_endpoints', ['asset_id'])
    op.create_index('ix_crawled_endpoints_source', 'crawled_endpoints', ['source'])
    op.create_index('ix_crawled_endpoints_is_js', 'crawled_endpoints', ['is_js_file'])

    # === Create technology_fingerprints table ===
    op.create_table(
        'technology_fingerprints',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('service_id', UUID(as_uuid=True), sa.ForeignKey('services.id', ondelete='SET NULL'), nullable=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('category', sa.String(50), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=True),
        sa.Column('cpe', sa.String(255), nullable=True),
        sa.Column('detection_method', sa.String(50), nullable=True),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_tech_fingerprints_asset_id', 'technology_fingerprints', ['asset_id'])
    op.create_index('ix_tech_fingerprints_category', 'technology_fingerprints', ['category'])


def downgrade() -> None:
    # Drop all passive intel tables in reverse order
    op.drop_table('technology_fingerprints')
    op.drop_table('crawled_endpoints')
    op.drop_table('shodan_data')
    op.drop_table('favicon_hashes')
    op.drop_table('security_headers')
    op.drop_table('historical_urls')
    op.drop_table('asn_info')
    op.drop_table('certificates')
    op.drop_table('whois_records')
    op.drop_table('dns_records')

    # Remove columns from programs table
    op.drop_column('programs', 'censys_api_secret')
    op.drop_column('programs', 'censys_api_id')
    op.drop_column('programs', 'securitytrails_api_key')
    op.drop_column('programs', 'shodan_api_key')
    op.drop_column('programs', 'enable_crawling')
    op.drop_column('programs', 'enable_url_aggregation')
    op.drop_column('programs', 'enable_web_archive')
    op.drop_column('programs', 'passive_recon_enabled')
