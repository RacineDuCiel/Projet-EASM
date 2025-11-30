import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { formatDistanceToNow } from "date-fns";
import type { Vulnerability } from "@/types";
import { VulnStatusBadge } from "./VulnStatusBadge";
import { VulnActions } from "./VulnActions";

interface VulnTableProps {
    vulns: Vulnerability[];
    isLoading: boolean;
    onStatusChange: (id: string, status: Vulnerability['status']) => void;
}

export function VulnTable({ vulns, isLoading, onStatusChange }: VulnTableProps) {
    if (isLoading) {
        return <div className="text-center py-10">Loading vulnerabilities...</div>;
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
                                No vulnerabilities found.
                            </TableCell>
                        </TableRow>
                    ) : (
                        vulns.map((vuln) => (
                            <TableRow key={vuln.id}>
                                <TableCell>
                                    <Badge
                                        className={`${vuln.severity === 'critical' ? 'bg-red-600 hover:bg-red-700' :
                                                vuln.severity === 'high' ? 'bg-orange-500 hover:bg-orange-600' :
                                                    vuln.severity === 'medium' ? 'bg-yellow-500 hover:bg-yellow-600' :
                                                        vuln.severity === 'low' ? 'bg-blue-500 hover:bg-blue-600' :
                                                            'bg-gray-500 hover:bg-gray-600'
                                            }`}
                                    >
                                        {vuln.severity}
                                    </Badge>
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
