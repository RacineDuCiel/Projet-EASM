import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
    label?: string;
    size?: 'sm' | 'default' | 'lg';
    className?: string;
}

/**
 * Consistent loading spinner component.
 */
export function LoadingSpinner({
    label = 'Loading...',
    size = 'default',
    className = '',
}: LoadingSpinnerProps) {
    const sizeClasses = {
        sm: 'h-4 w-4',
        default: 'h-6 w-6',
        lg: 'h-8 w-8',
    };

    return (
        <div
            className={`flex items-center justify-center gap-2 p-8 ${className}`}
            role="status"
            aria-label={label}
        >
            <Loader2
                className={`animate-spin text-primary ${sizeClasses[size]}`}
            />
            {label && (
                <span className="text-muted-foreground">{label}</span>
            )}
        </div>
    );
}

export default LoadingSpinner;
