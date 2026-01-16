/**
 * Shared utilities for status colors and severity handling.
 *
 * Centralizes color definitions and utility functions used across the application.
 */

// Severity colors for vulnerabilities
export const severityColors = {
    critical: 'bg-red-600 hover:bg-red-700 text-white',
    high: 'bg-orange-500 hover:bg-orange-600 text-white',
    medium: 'bg-yellow-500 hover:bg-yellow-600 text-black',
    low: 'bg-blue-500 hover:bg-blue-600 text-white',
    info: 'bg-gray-500 hover:bg-gray-600 text-white',
} as const;

// Severity badge variants for shadcn Badge component
export const severityBadgeVariants = {
    critical: 'destructive',
    high: 'default',
    medium: 'secondary',
    low: 'outline',
    info: 'outline',
} as const;

// Scan status colors
export const scanStatusColors = {
    pending: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    running: 'bg-blue-100 text-blue-800 border-blue-200',
    completed: 'bg-green-100 text-green-800 border-green-200',
    stopped: 'bg-gray-100 text-gray-800 border-gray-200',
    failed: 'bg-red-100 text-red-800 border-red-200',
} as const;

// Active/inactive status colors
export const activeStatusColors = {
    active: 'bg-green-100 text-green-800',
    inactive: 'bg-gray-100 text-gray-800',
} as const;

// Vulnerability status colors
export const vulnStatusColors = {
    open: 'bg-red-100 text-red-800',
    fixed: 'bg-green-100 text-green-800',
    false_positive: 'bg-gray-100 text-gray-800',
    accepted: 'bg-yellow-100 text-yellow-800',
} as const;

export type Severity = keyof typeof severityColors;
export type ScanStatus = keyof typeof scanStatusColors;
export type VulnStatus = keyof typeof vulnStatusColors;

/**
 * Get weight for severity sorting (higher = more severe)
 */
export function getSeverityWeight(severity: string): number {
    const weights: Record<string, number> = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
        info: 1,
    };
    return weights[severity.toLowerCase()] || 0;
}

/**
 * Sort items by severity (most severe first)
 */
export function sortBySeverity<T extends { severity: string }>(
    items: T[],
    direction: 'asc' | 'desc' = 'desc'
): T[] {
    return [...items].sort((a, b) => {
        const weightA = getSeverityWeight(a.severity);
        const weightB = getSeverityWeight(b.severity);
        return direction === 'desc' ? weightB - weightA : weightA - weightB;
    });
}

/**
 * Get color classes for scan status
 */
export function getScanStatusColor(status: string): string {
    return (
        scanStatusColors[status as ScanStatus] ||
        'bg-gray-100 text-gray-800 border-gray-200'
    );
}

/**
 * Get color classes for severity
 */
export function getSeverityColor(severity: string): string {
    return severityColors[severity as Severity] || severityColors.info;
}

/**
 * Get color classes for vulnerability status
 */
export function getVulnStatusColor(status: string): string {
    return vulnStatusColors[status as VulnStatus] || 'bg-gray-100 text-gray-800';
}

/**
 * Format severity for display (capitalize first letter)
 */
export function formatSeverity(severity: string): string {
    return severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
}

/**
 * Format vulnerability status for display
 */
export function formatVulnStatus(status: string): string {
    const statusMap: Record<string, string> = {
        open: 'Open',
        fixed: 'Fixed',
        false_positive: 'False Positive',
        accepted: 'Accepted Risk',
    };
    return statusMap[status] || status;
}

/**
 * Format scan status for display
 */
export function formatScanStatus(status: string): string {
    return status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
}
