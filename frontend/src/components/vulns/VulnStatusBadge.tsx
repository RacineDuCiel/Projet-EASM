import { Badge } from "@/components/ui/badge";
import { CheckCircle, AlertCircle, XCircle } from "lucide-react";

interface VulnStatusBadgeProps {
    status: 'open' | 'fixed' | 'false_positive';
}

export function VulnStatusBadge({ status }: VulnStatusBadgeProps) {
    switch (status) {
        case 'open':
            return (
                <Badge variant="outline" className="gap-1 border-primary/50 text-primary">
                    <AlertCircle className="h-3 w-3" />
                    Open
                </Badge>
            );
        case 'fixed':
            return (
                <Badge variant="default" className="bg-green-600 hover:bg-green-700 gap-1">
                    <CheckCircle className="h-3 w-3" />
                    Fixed
                </Badge>
            );
        case 'false_positive':
            return (
                <Badge variant="secondary" className="gap-1">
                    <XCircle className="h-3 w-3" />
                    False Positive
                </Badge>
            );

        default:
            return <Badge variant="outline">{status}</Badge>;
    }
}
