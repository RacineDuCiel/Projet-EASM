import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { MoreHorizontal, CheckCircle, AlertCircle, XCircle } from "lucide-react";
import type { Vulnerability } from "@/types";

interface VulnActionsProps {
    vuln: Vulnerability;
    onStatusChange: (id: string, status: Vulnerability['status']) => void;
}

export function VulnActions({ vuln, onStatusChange }: VulnActionsProps) {
    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="h-8 w-8 p-0">
                    <span className="sr-only">Open menu</span>
                    <MoreHorizontal className="h-4 w-4" />
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
                <DropdownMenuLabel>Actions</DropdownMenuLabel>
                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(vuln.id)}>
                    Copy ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuLabel>Change Status</DropdownMenuLabel>
                <DropdownMenuItem onClick={() => onStatusChange(vuln.id, 'open')}>
                    <AlertCircle className="mr-2 h-4 w-4 text-red-500" />
                    Mark as Open
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => onStatusChange(vuln.id, 'fixed')}>
                    <CheckCircle className="mr-2 h-4 w-4 text-green-500" />
                    Mark as Fixed
                </DropdownMenuItem>

                <DropdownMenuItem onClick={() => onStatusChange(vuln.id, 'false_positive')}>
                    <XCircle className="mr-2 h-4 w-4 text-gray-500" />
                    Mark as False Positive
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
