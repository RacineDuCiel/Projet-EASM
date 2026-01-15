import type { AssetCriticality } from '@/types';
import { cn } from '@/lib/utils';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { AlertTriangle, AlertCircle, Minus, ChevronDown, HelpCircle } from 'lucide-react';

const criticalityConfig: Record<AssetCriticality, {
    label: string;
    color: string;
    icon: typeof AlertTriangle;
}> = {
    critical: {
        label: 'Critical',
        color: 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900 dark:text-red-300 dark:border-red-700',
        icon: AlertTriangle,
    },
    high: {
        label: 'High',
        color: 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900 dark:text-orange-300 dark:border-orange-700',
        icon: AlertCircle,
    },
    medium: {
        label: 'Medium',
        color: 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900 dark:text-yellow-300 dark:border-yellow-700',
        icon: Minus,
    },
    low: {
        label: 'Low',
        color: 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900 dark:text-green-300 dark:border-green-700',
        icon: ChevronDown,
    },
    unclassified: {
        label: 'Unclassified',
        color: 'bg-gray-100 text-gray-600 border-gray-200 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600',
        icon: HelpCircle,
    },
};

interface CriticalityBadgeProps {
    criticality: AssetCriticality;
    editable?: boolean;
    onChange?: (criticality: AssetCriticality) => void;
    size?: 'sm' | 'md';
}

export function CriticalityBadge({
    criticality,
    editable,
    onChange,
    size = 'sm'
}: CriticalityBadgeProps) {
    const config = criticalityConfig[criticality];
    const Icon = config.icon;

    if (editable && onChange) {
        return (
            <Select value={criticality} onValueChange={(val) => onChange(val as AssetCriticality)}>
                <SelectTrigger className={cn(
                    "w-[140px]",
                    size === 'sm' ? 'h-7 text-xs' : 'h-9 text-sm'
                )}>
                    <SelectValue>
                        <span className={cn(
                            "inline-flex items-center gap-1 px-2 py-0.5 rounded-full border",
                            config.color
                        )}>
                            <Icon className="h-3 w-3" />
                            {config.label}
                        </span>
                    </SelectValue>
                </SelectTrigger>
                <SelectContent>
                    {Object.entries(criticalityConfig).map(([key, { label, color, icon: ItemIcon }]) => (
                        <SelectItem key={key} value={key}>
                            <span className={cn(
                                "inline-flex items-center gap-1 px-2 py-0.5 rounded-full border",
                                color
                            )}>
                                <ItemIcon className="h-3 w-3" />
                                {label}
                            </span>
                        </SelectItem>
                    ))}
                </SelectContent>
            </Select>
        );
    }

    return (
        <span className={cn(
            "inline-flex items-center gap-1 rounded-full border",
            config.color,
            size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
        )}>
            <Icon className={size === 'sm' ? 'h-3 w-3' : 'h-4 w-4'} />
            {config.label}
        </span>
    );
}

export function getCriticalityLabel(criticality: AssetCriticality): string {
    return criticalityConfig[criticality].label;
}
