import { Badge } from '@/components/ui/badge';
import {
    severityColors,
    formatSeverity,
    type Severity,
} from '@/lib/status-utils';

interface SeverityBadgeProps {
    severity: Severity | string;
    size?: 'sm' | 'default';
    className?: string;
}

/**
 * Badge component for displaying vulnerability severity.
 *
 * Uses consistent colors across the application.
 */
export function SeverityBadge({
    severity,
    size = 'default',
    className = '',
}: SeverityBadgeProps) {
    const severityLower = severity.toLowerCase() as Severity;
    const colorClasses =
        severityColors[severityLower] || severityColors.info;
    const sizeClasses = size === 'sm' ? 'text-[10px] px-1.5 py-0 h-5' : '';

    return (
        <Badge className={`${colorClasses} ${sizeClasses} ${className}`}>
            {formatSeverity(severity)}
        </Badge>
    );
}

export default SeverityBadge;
