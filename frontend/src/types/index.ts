export interface DashboardStats {
    programs: {
        total: number;
    };
    assets: {
        total: number;
    };

    scans: {
        total: number;
        running: number;
        failed: number;
    };
    vulnerabilities: {
        total: number;
        critical: number;
        high: number;
    };
}

// Scan Profiles - available for manual scans
export type ScanProfile =
    | 'discovery'
    | 'quick_assessment'
    | 'standard_assessment'
    | 'full_audit';

export type ScanPhase =
    | 'asset_discovery'
    | 'service_enumeration'
    | 'tech_detection'
    | 'vuln_assessment'
    | 'deep_analysis';

export type AssetCriticality =
    | 'critical'
    | 'high'
    | 'medium'
    | 'low'
    | 'unclassified';

export interface ScanProfileInfo {
    profile: ScanProfile;
    display_name: string;
    description: string;
    phases: ScanPhase[];
    estimated_duration: string;
    intensity: string;
}

export interface Service {
    id: string;
    port: number;
    protocol: string;
    service_name?: string;
    banner?: string;
    // Technology detection fields (populated by httpx)
    technologies?: string[];
    web_server?: string;
    waf_detected?: string;
    tls_version?: string;
    response_time_ms?: number;
}

export interface Vulnerability {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    status: 'open' | 'fixed' | 'false_positive';
    description?: string;
    created_at: string;
}

export interface Asset {
    id: string;
    value: string;
    asset_type: 'domain' | 'subdomain' | 'ip';
    is_active: boolean;
    first_seen: string;
    last_seen: string;
    // Criticality and scan tracking
    criticality: AssetCriticality;
    last_scanned_at?: string;
    scan_count: number;
    services: Service[];
    vulnerabilities: Vulnerability[];
}

export interface Scope {
    id: string;
    scope_type: 'domain' | 'ip_range' | 'hostname';
    value: string;
    port?: number;  // Support pour la syntaxe Cible:Port
    program_id: string;
}

export interface Program {
    id: string;
    name: string;
    discord_webhook_url?: string;
    scan_frequency?: 'never' | 'daily' | 'weekly' | 'monthly';
    created_at: string;
    scopes: Scope[];
    // Scan configuration
    default_scan_profile: ScanProfile;
    custom_ports?: string;
    nuclei_rate_limit?: number;
    nuclei_timeout?: number;
    // Automated monitoring configuration
    auto_scan_enabled: boolean;
    delta_scan_enabled: boolean;
    delta_scan_threshold_hours: number;
}
export interface User {
    id: string;
    username: string;
    role: 'admin' | 'user';
    program_id?: string | null;
    is_active: boolean;
    program?: Program; // Optional relationship
}

export interface Scan {
    id: string;
    scope_id: string;
    scan_profile: ScanProfile;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'stopped';
    started_at: string;
    completed_at?: string;
    // Phase tracking
    selected_phases?: ScanPhase[];
    current_phase?: ScanPhase;
    // Delta scanning
    is_delta_scan: boolean;
    delta_threshold_hours?: number;
    // Statistics
    assets_scanned: number;
    assets_skipped: number;
    vulns_found: number;
}

export interface SystemLog {
    id: string;
    level: 'info' | 'warning' | 'error';
    message: string;
    source: string;
    user_id?: string;
    created_at: string;
}

// ============================================================================
// Passive Intelligence Types
// ============================================================================

export interface DNSRecord {
    id: string;
    asset_id: string;
    record_type: string;  // A, AAAA, MX, TXT, NS, SOA, CNAME, PTR
    record_value: string;
    ttl?: number;
    priority?: number;
    first_seen: string;
    last_seen: string;
}

export interface WHOISRecord {
    id: string;
    asset_id: string;
    registrar?: string;
    creation_date?: string;
    expiration_date?: string;
    updated_date?: string;
    name_servers?: string;
    registrant_org?: string;
    registrant_country?: string;
    registrant_email?: string;
    dnssec?: boolean;
    raw_data?: string;
    collected_at: string;
}

export interface Certificate {
    id: string;
    asset_id: string;
    service_id?: string;
    serial_number?: string;
    issuer_cn?: string;
    issuer_org?: string;
    subject_cn?: string;
    subject_alt_names?: string;
    not_before?: string;
    not_after?: string;
    signature_algorithm?: string;
    key_algorithm?: string;
    key_size?: number;
    is_self_signed?: boolean;
    is_expired?: boolean;
    is_wildcard?: boolean;
    fingerprint_sha256?: string;
    tls_version?: string;
    source?: string;
    collected_at: string;
}

export interface ASNInfo {
    id: string;
    asset_id: string;
    ip_address: string;
    asn_number?: number;
    asn_name?: string;
    asn_description?: string;
    asn_country?: string;
    bgp_prefix?: string;
    rir?: string;
    collected_at: string;
}

export interface HistoricalURL {
    id: string;
    asset_id: string;
    url: string;
    source?: string;
    archived_date?: string;
    status_code?: number;
    content_type?: string;
    collected_at: string;
}

export interface SecurityHeader {
    id: string;
    asset_id: string;
    service_id?: string;
    url?: string;
    content_security_policy?: string;
    strict_transport_security?: string;
    x_frame_options?: string;
    x_content_type_options?: string;
    x_xss_protection?: string;
    referrer_policy?: string;
    permissions_policy?: string;
    missing_headers?: string;
    score?: number;
    grade?: string;
    collected_at: string;
}

export interface FaviconHash {
    id: string;
    asset_id: string;
    mmh3_hash?: string;
    md5_hash?: string;
    sha256_hash?: string;
    favicon_url?: string;
    favicon_size?: number;
    collected_at: string;
}

export interface ShodanData {
    id: string;
    asset_id: string;
    ip_address: string;
    open_ports?: string;
    hostnames?: string;
    domains?: string;
    os?: string;
    isp?: string;
    org?: string;
    city?: string;
    region?: string;
    country?: string;
    latitude?: string;
    longitude?: string;
    last_update?: string;
    vulns?: string;
    tags?: string;
    raw_data?: string;
    collected_at: string;
}

export interface CrawledEndpoint {
    id: string;
    asset_id: string;
    url: string;
    method: string;
    status_code?: number;
    content_type?: string;
    content_length?: number;
    parameters?: string;
    source?: string;
    is_js_file: boolean;
    is_api_endpoint: boolean;
    collected_at: string;
}

export interface PassiveIntelSummary {
    asset_id: string;
    asset_value: string;
    dns_record_count: number;
    certificate_count: number;
    historical_url_count: number;
    endpoint_count: number;
    has_whois: boolean;
    has_asn: boolean;
    has_shodan: boolean;
    security_header_score?: number;
    security_header_grade?: string;
    favicon_mmh3_hash?: string;
}

export interface AssetPassiveIntel {
    asset_id: string;
    asset_value: string;
    dns_records: DNSRecord[];
    whois_record?: WHOISRecord;
    certificates: Certificate[];
    asn_info: ASNInfo[];
    historical_urls: HistoricalURL[];
    security_headers: SecurityHeader[];
    favicon_hash?: FaviconHash;
    shodan_data?: ShodanData;
    crawled_endpoints: CrawledEndpoint[];
}
