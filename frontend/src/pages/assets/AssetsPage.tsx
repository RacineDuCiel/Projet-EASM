import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Asset } from '@/types';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';
import { Eye, ChevronLeft, ChevronRight } from 'lucide-react';
import { LoadingSpinner, EmptyState } from '@/components/common';
import { Globe } from 'lucide-react';

const PAGE_SIZE = 50;

export default function AssetsPage() {
    const [page, setPage] = useState(0);

    const { data: assets, isLoading, error } = useQuery({
        queryKey: ['assets', page],
        queryFn: async () => {
            const response = await api.get<Asset[]>('/assets/', {
                params: {
                    skip: page * PAGE_SIZE,
                    limit: PAGE_SIZE,
                },
            });
            return response.data;
        },
    });

    if (isLoading) {
        return <LoadingSpinner label="Loading assets..." size="lg" />;
    }

    if (error) {
        return <div className="p-8 text-destructive">Error loading assets.</div>;
    }

    return (
        <div className="space-y-8">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Assets</h2>
                <p className="text-muted-foreground">
                    Manage and monitor your infrastructure assets.
                </p>
            </div>

            <div className="rounded-md border">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead>Asset</TableHead>
                            <TableHead>Type</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Services</TableHead>
                            <TableHead>Vulnerabilities</TableHead>
                            <TableHead className="text-right">Last Seen</TableHead>
                            <TableHead>Actions</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {assets?.length === 0 && page === 0 ? (
                            <TableRow>
                                <TableCell colSpan={7} className="h-24 text-center">
                                    <EmptyState
                                        icon={Globe}
                                        title="No assets found"
                                        description="Assets will appear here once a scan has been completed."
                                    />
                                </TableCell>
                            </TableRow>
                        ) : (
                            assets?.map((asset) => (
                                <TableRow key={asset.id}>
                                    <TableCell className="font-medium">{asset.value}</TableCell>
                                    <TableCell>
                                        <span className="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                                            {asset.asset_type}
                                        </span>
                                    </TableCell>
                                    <TableCell>
                                        <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent ${asset.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                                            {asset.is_active ? 'Active' : 'Inactive'}
                                        </span>
                                    </TableCell>
                                    <TableCell>{asset.services.length}</TableCell>
                                    <TableCell>{asset.vulnerabilities.length}</TableCell>
                                    <TableCell className="text-right">
                                        {new Date(asset.last_seen).toLocaleDateString()}
                                    </TableCell>
                                    <TableCell>
                                        <Link to={`/assets/${asset.id}`}>
                                            <Button variant="ghost" size="sm">
                                                <Eye className="h-4 w-4 mr-2" />
                                                View
                                            </Button>
                                        </Link>
                                    </TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </div>

            {/* Pagination Controls */}
            <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                    Page {page + 1} {assets && assets.length > 0 ? `(${assets.length} results)` : ''}
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
                        disabled={!assets || assets.length < PAGE_SIZE}
                    >
                        Next
                        <ChevronRight className="h-4 w-4 ml-1" />
                    </Button>
                </div>
            </div>
        </div>
    );
}
