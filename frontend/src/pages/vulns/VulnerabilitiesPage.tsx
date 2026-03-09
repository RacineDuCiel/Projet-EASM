import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/lib/api";
import type { Vulnerability } from "@/types";
import { VulnTable } from "@/components/vulns/VulnTable";
import { useToast } from "@/components/ui/use-toast";
import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight } from "lucide-react";

const PAGE_SIZE = 100;

export default function VulnerabilitiesPage() {
    const { toast } = useToast();
    const queryClient = useQueryClient();
    const [page, setPage] = useState(0);

    // Fetch vulnerabilities
    const { data: vulns, isLoading } = useQuery({
        queryKey: ['vulnerabilities', page],
        queryFn: async () => {
            const response = await api.get<Vulnerability[]>('/vulnerabilities', {
                params: {
                    skip: page * PAGE_SIZE,
                    limit: PAGE_SIZE
                }
            });
            return response.data;
        }
    });

    // Update status mutation
    const updateStatusMutation = useMutation({
        mutationFn: async ({ id, status }: { id: string; status: Vulnerability['status'] }) => {
            const response = await api.patch<Vulnerability>(`/vulnerabilities/${id}`, { status });
            return response.data;
        },
        onSuccess: (updatedVuln) => {
            toast({
                title: "Status updated",
                description: `Vulnerability marked as ${updatedVuln.status}`,
            });
            queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
            queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] }); // Update dashboard too
        },
        onError: () => {
            toast({
                title: "Error",
                description: "Failed to update status",
                variant: "destructive",
            });
        }
    });

    const handleStatusChange = (id: string, status: Vulnerability['status']) => {
        updateStatusMutation.mutate({ id, status });
    };

    const handleExportCsv = async () => {
        try {
            const response = await api.get('/vulnerabilities/export/csv', {
                responseType: 'blob',
            });

            // Create blob link to download
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', 'vulnerabilities.csv');

            // Append to html link element page
            document.body.appendChild(link);

            // Start download
            link.click();

            // Clean up and remove the link
            link.parentNode?.removeChild(link);
        } catch (error) {
            toast({
                title: "Export Failed",
                description: "Could not export vulnerabilities.",
                variant: "destructive",
            });
        }
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-3xl font-bold tracking-tight">Vulnerabilities</h2>
                    <p className="text-muted-foreground">
                        Manage and triage discovered vulnerabilities.
                    </p>
                </div>
                <Button onClick={handleExportCsv}>
                    Export CSV
                </Button>
            </div>

            <VulnTable
                vulns={vulns || []}
                isLoading={isLoading}
                onStatusChange={handleStatusChange}
            />

            {/* Pagination Controls */}
            <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                    Page {page + 1} {vulns && vulns.length > 0 ? `(${vulns.length} results)` : ''}
                </p>
                <div className="flex items-center gap-2">
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setPage((p) => Math.max(0, p - 1))}
                        disabled={page === 0}
                    >
                        <ChevronLeft className="h-4 w-4 mr-1" />
                        Previous
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setPage((p) => p + 1)}
                        disabled={!vulns || vulns.length < PAGE_SIZE}
                    >
                        Next
                        <ChevronRight className="h-4 w-4 ml-1" />
                    </Button>
                </div>
            </div>
        </div>
    );
}
