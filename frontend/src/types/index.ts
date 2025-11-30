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
