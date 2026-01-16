import {
    getScanStatusColor,
    getVulnStatusColor,
    formatScanStatus,
    formatVulnStatus,
} from '@/lib/status-utils';

interface ScanStatusBadgeProps {
    status: string;
    className?: string;
}

/**
 * Badge component for displaying scan status.
 */
export function ScanStatusBadge({ status, className = '' }: ScanStatusBadgeProps) {
    const colorClasses = getScanStatusColor(status);

    return (
        <span
            className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${colorClasses} ${className}`}
        >
            {formatScanStatus(status)}
        </span>
    );
}

interface VulnStatusBadgeProps {
    status: string;
    className?: string;
}

/**
 * Badge component for displaying vulnerability status.
 */
export function VulnStatusBadge({ status, className = '' }: VulnStatusBadgeProps) {
    const colorClasses = getVulnStatusColor(status);

    return (
        <span
            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${colorClasses} ${className}`}
        >
            {formatVulnStatus(status)}
        </span>
    );
}

export { ScanStatusBadge as default };
