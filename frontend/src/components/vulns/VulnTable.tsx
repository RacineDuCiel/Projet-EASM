import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { formatDistanceToNow } from "date-fns";
import type { Vulnerability } from "@/types";
import { VulnStatusBadge } from "./VulnStatusBadge";
import { VulnActions } from "./VulnActions";
import { SeverityBadge, LoadingSpinner, EmptyState } from "@/components/common";
import { ShieldAlert } from "lucide-react";

interface VulnTableProps {
    vulns: Vulnerability[];
    isLoading: boolean;
    onStatusChange: (id: string, status: Vulnerability['status']) => void;
}

export function VulnTable({ vulns, isLoading, onStatusChange }: VulnTableProps) {
    if (isLoading) {
        return <LoadingSpinner label="Loading vulnerabilities..." />;
    }

    return (
        <div className="rounded-md border">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Severity</TableHead>
                        <TableHead>Title</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Found</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {vulns.length === 0 ? (
                        <TableRow>
                            <TableCell colSpan={5} className="h-24 text-center">
                                <EmptyState
                                    icon={ShieldAlert}
                                    title="No vulnerabilities found"
                                    description="Vulnerabilities will appear here once a scan discovers them."
                                />
                            </TableCell>
                        </TableRow>
                    ) : (
                        vulns.map((vuln) => (
                            <TableRow key={vuln.id}>
                                <TableCell>
                                    <SeverityBadge severity={vuln.severity} />
                                </TableCell>
                                <TableCell className="font-medium">
                                    <div className="flex flex-col">
                                        <span>{vuln.title}</span>
                                        {vuln.description && (
                                            <span className="text-xs text-muted-foreground truncate max-w-[300px]">
                                                {vuln.description}
                                            </span>
                                        )}
                                    </div>
                                </TableCell>
                                <TableCell>
                                    <VulnStatusBadge status={vuln.status} />
                                </TableCell>
                                <TableCell>
                                    {formatDistanceToNow(new Date(vuln.created_at), { addSuffix: true })}
                                </TableCell>
                                <TableCell className="text-right">
                                    <VulnActions vuln={vuln} onStatusChange={onStatusChange} />
                                </TableCell>
                            </TableRow>
                        ))
                    )}
                </TableBody>
            </Table>
        </div>
    );
}
