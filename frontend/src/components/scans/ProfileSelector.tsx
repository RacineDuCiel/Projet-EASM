import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { ScanProfile, ScanProfileInfo } from '@/types';
import { cn } from '@/lib/utils';
import {
    Search,
    Zap,
    BarChart3,
    ShieldCheck,
    Clock,
    Activity,
    Loader2
} from 'lucide-react';

const profileIcons: Record<ScanProfile, typeof Search> = {
    discovery: Search,
    quick_assessment: Zap,
    standard_assessment: BarChart3,
    full_audit: ShieldCheck,
};

const intensityColors: Record<string, string> = {
    'Light (passive)': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
    'Medium': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
    'Medium-High': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300',
    'Heavy': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
    'Adaptive': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
};

interface ProfileSelectorProps {
    value: ScanProfile | null;
    onChange: (profile: ScanProfile) => void;
    showDescriptions?: boolean;
}

export function ProfileSelector({ value, onChange, showDescriptions = true }: ProfileSelectorProps) {
    const { data: profiles, isLoading, error } = useQuery({
        queryKey: ['scan-profiles'],
        queryFn: async () => {
            const response = await api.get<ScanProfileInfo[]>('/scans/profiles');
            return response.data;
        },
    });

    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-48">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
        );
    }

    if (error) {
        return (
            <div className="text-sm text-red-500 p-4">
                Failed to load scan profiles
            </div>
        );
    }

    return (
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {profiles?.map((profile) => {
                const Icon = profileIcons[profile.profile as ScanProfile];
                const isSelected = value === profile.profile;

                return (
                    <div
                        key={profile.profile}
                        className={cn(
                            "cursor-pointer rounded-lg border p-4 transition-all hover:shadow-md",
                            isSelected
                                ? "ring-2 ring-primary border-primary bg-primary/5"
                                : "border-border hover:border-primary/50"
                        )}
                        onClick={() => onChange(profile.profile as ScanProfile)}
                    >
                        <div className="flex items-center justify-between mb-2">
                            <Icon className="h-5 w-5 text-muted-foreground" />
                            <span
                                className={cn(
                                    "text-xs px-2 py-0.5 rounded-full",
                                    intensityColors[profile.intensity] || 'bg-gray-100 text-gray-800'
                                )}
                            >
                                {profile.intensity}
                            </span>
                        </div>

                        <h3 className="font-semibold text-sm mb-1">
                            {profile.display_name}
                        </h3>

                        {showDescriptions && (
                            <p className="text-xs text-muted-foreground mb-3 line-clamp-2">
                                {profile.description}
                            </p>
                        )}

                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <div className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                {profile.estimated_duration}
                            </div>
                            <div className="flex items-center gap-1">
                                <Activity className="h-3 w-3" />
                                {profile.phases.length} phases
                            </div>
                        </div>
                    </div>
                );
            })}
        </div>
    );
}

export function getProfileDisplayName(profile: ScanProfile): string {
    const displayNames: Record<ScanProfile, string> = {
        discovery: 'Discovery',
        quick_assessment: 'Quick Assessment',
        standard_assessment: 'Standard Assessment',
        full_audit: 'Full Audit',
    };
    return displayNames[profile] || profile;
}

export function ProfileBadge({ profile }: { profile: ScanProfile }) {
    const Icon = profileIcons[profile];
    const displayName = getProfileDisplayName(profile);

    const badgeColors: Record<ScanProfile, string> = {
        discovery: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
        quick_assessment: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
        standard_assessment: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
        full_audit: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300',
    };

    return (
        <span className={cn(
            "inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium",
            badgeColors[profile]
        )}>
            <Icon className="h-3 w-3" />
            {displayName}
        </span>
    );
}
