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

export type ScanDepth = 'fast' | 'deep';

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
    scan_depth: ScanDepth;
    custom_ports?: string;
    nuclei_rate_limit?: number;
    nuclei_timeout?: number;
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
    scan_type: 'passive' | 'active' | 'full';
    scan_depth: ScanDepth;
    status: 'pending' | 'running' | 'completed' | 'failed';
    started_at: string;
    completed_at?: string;
}

export interface SystemLog {
    id: string;
    level: 'info' | 'warning' | 'error';
    message: string;
    source: string;
    user_id?: string;
    created_at: string;
}
