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

export interface Service {
    id: string;
    port: number;
    protocol: string;
    service_name?: string;
    banner?: string;
}

export interface Vulnerability {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    status: 'open' | 'closed' | 'ignored';
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
    program_id: string;
}

export interface Program {
    id: string;
    name: string;
    discord_webhook_url?: string;
    scan_frequency?: 'never' | 'daily' | 'weekly' | 'monthly';
    created_at: string;
    scopes: Scope[];
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
    status: 'pending' | 'running' | 'completed' | 'failed';
    started_at: string;
    completed_at?: string;
}
