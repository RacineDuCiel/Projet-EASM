import { useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Scan, Asset } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Loader2, RefreshCw, ShieldAlert, Globe, ArrowUpDown, AlertTriangle } from 'lucide-react';
import { format } from 'date-fns';
import { getProfileDisplayName } from '@/components/scans/ProfileSelector';

type SortDirection = 'asc' | 'desc';
type SortKey = 'severity' | 'title' | 'asset';

export default function ScanDetailsPage() {
    const { scanId } = useParams<{ scanId: string }>();
    const [sortConfig, setSortConfig] = useState<{ key: SortKey; direction: SortDirection }>({ key: 'severity', direction: 'desc' });

    // 1. Fetch Scan Details
    const { data: scan, isLoading: isLoadingScan, error: scanError } = useQuery({
        queryKey: ['scan', scanId],
        queryFn: async () => {
            const response = await api.get<Scan>(`/scans/${scanId}`);
            return response.data;
        },
        refetchInterval: (query) => {
            return query.state.data?.status === 'running' ? 2000 : false;
        }
    });

    // 2. Fetch Assets (Filtered by Scope)
    const { data: assets, isLoading: isLoadingAssets } = useQuery({
        queryKey: ['scan-assets', scan?.scope_id],
        queryFn: async () => {
            if (!scan?.scope_id) return [];
            const response = await api.get<Asset[]>(`/assets/?scope_id=${scan.scope_id}`);
            return response.data;
        },
        enabled: !!scan?.scope_id,
        refetchInterval: (query) => {
            // Poll if scan is running
            return scan?.status === 'running' ? 5000 : false;
        }
    });

    // Flatten and Sort Vulnerabilities
    // MOVED UP: Hooks must be called before any early return
    const sortedVulns = useMemo(() => {
        if (!assets) return [];

        // Defensive coding: ensure asset.vulnerabilities exists
        const flatVulns = assets.flatMap(asset =>
            (asset.vulnerabilities || []).map(vuln => ({ ...vuln, assetValue: asset.value }))
        );

        return flatVulns.sort((a, b) => {
            const direction = sortConfig.direction === 'asc' ? 1 : -1;

            if (sortConfig.key === 'severity') {
                const severityWeight = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                const weightA = severityWeight[a.severity as keyof typeof severityWeight] || 0;
                const weightB = severityWeight[b.severity as keyof typeof severityWeight] || 0;
                return (weightA - weightB) * direction;
            }

            if (sortConfig.key === 'title') {
                return (a.title || '').localeCompare(b.title || '') * direction;
            }

            if (sortConfig.key === 'asset') {
                return (a.assetValue || '').localeCompare(b.assetValue || '') * direction;
            }

            return 0;
        });
    }, [assets, sortConfig]);

    const handleSort = (key: SortKey) => {
        setSortConfig(current => ({
            key,
            direction: current.key === key && current.direction === 'desc' ? 'asc' : 'desc'
        }));
    };

    const totalVulns = assets?.reduce((acc, asset) => acc + (asset.vulnerabilities?.length || 0), 0) || 0;

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'completed': return 'bg-green-100 text-green-800 hover:bg-green-100 border-green-200';
            case 'running': return 'bg-blue-100 text-blue-800 hover:bg-blue-100 border-blue-200';
            case 'failed': return 'bg-red-100 text-red-800 hover:bg-red-100 border-red-200';
            default: return 'bg-gray-100 text-gray-800 hover:bg-gray-100 border-gray-200';
        }
    };

    // --- EARLY RETURNS START HERE ---

    if (isLoadingScan) {
        return <div className="flex h-[50vh] items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
    }

    if (scanError || !scan) {
        return (
            <div className="flex h-[50vh] flex-col items-center justify-center gap-4 text-destructive">
                <AlertTriangle className="h-12 w-12" />
                <h3 className="text-lg font-semibold">Scan not found or error loading details</h3>
                <Link to="/scans">
                    <Button variant="outline">Back to Scans</Button>
                </Link>
            </div>
        );
    }

    return (
        <div className="space-y-6 animate-in fade-in duration-500">
            <div className="flex items-center gap-4">
                <Link to="/scans">
                    <Button variant="outline" size="icon">
                        <ArrowLeft className="h-4 w-4" />
                    </Button>
                </Link>
                <div>
                    <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
                        Scan Details
                        <Badge variant="outline" className={getStatusColor(scan.status)}>
                            {scan.status === 'running' && <RefreshCw className="mr-1 h-3 w-3 animate-spin" />}
                            {scan.status}
                        </Badge>
                    </h2>
                    <p className="text-muted-foreground text-sm">
                        ID: <span className="font-mono text-xs">{scan.id}</span> •
                        Profile: <span className="font-medium">{getProfileDisplayName(scan.scan_profile)}</span> •
                        Started: {scan.started_at ? format(new Date(scan.started_at), 'MMM d, yyyy HH:mm:ss') : 'N/A'}
                    </p>
                </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Assets Scanned</CardTitle>
                        <Globe className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {isLoadingAssets ? <Loader2 className="h-6 w-6 animate-spin" /> : (assets?.length || 0)}
                        </div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Vulnerabilities Found</CardTitle>
                        <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {isLoadingAssets ? <Loader2 className="h-6 w-6 animate-spin" /> : totalVulns}
                        </div>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Vulnerabilities</CardTitle>
                    <CardDescription>All vulnerabilities found during this scan.</CardDescription>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead className="cursor-pointer hover:bg-muted/50" onClick={() => handleSort('severity')}>
                                    <div className="flex items-center gap-1">
                                        Severity <ArrowUpDown className="h-3 w-3" />
                                    </div>
                                </TableHead>
                                <TableHead className="cursor-pointer hover:bg-muted/50" onClick={() => handleSort('title')}>
                                    <div className="flex items-center gap-1">
                                        Title <ArrowUpDown className="h-3 w-3" />
                                    </div>
                                </TableHead>
                                <TableHead className="cursor-pointer hover:bg-muted/50" onClick={() => handleSort('asset')}>
                                    <div className="flex items-center gap-1">
                                        Asset <ArrowUpDown className="h-3 w-3" />
                                    </div>
                                </TableHead>
                                <TableHead>Description</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {isLoadingAssets ? (
                                <TableRow>
                                    <TableCell colSpan={4} className="h-24 text-center">
                                        <div className="flex justify-center items-center gap-2 text-muted-foreground">
                                            <Loader2 className="h-4 w-4 animate-spin" /> Loading vulnerabilities...
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ) : sortedVulns.length > 0 ? (
                                sortedVulns.map((vuln, index) => (
                                    <TableRow key={`${vuln.id}-${index}`}>
                                        <TableCell>
                                            <Badge variant={
                                                vuln.severity === 'critical' ? 'destructive' :
                                                    vuln.severity === 'high' ? 'destructive' :
                                                        vuln.severity === 'medium' ? 'default' :
                                                            'secondary'
                                            }>
                                                {vuln.severity}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="font-medium">{vuln.title}</TableCell>
                                        <TableCell className="font-mono text-sm">{vuln.assetValue}</TableCell>
                                        <TableCell className="text-muted-foreground text-sm max-w-md truncate" title={vuln.description}>
                                            {vuln.description || '-'}
                                        </TableCell>
                                    </TableRow>
                                ))
                            ) : (
                                <TableRow>
                                    <TableCell colSpan={4} className="text-center text-muted-foreground py-8">
                                        No vulnerabilities found yet.
                                    </TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    );
}
