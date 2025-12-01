import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/lib/api";
import type { Vulnerability } from "@/types";
import { VulnTable } from "@/components/vulns/VulnTable";
import { useToast } from "@/components/ui/use-toast";
import { Button } from "@/components/ui/button";

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
                    skip: page * 100,
                    limit: 100
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
        </div>
    );
}
