import { useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Asset } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Loader2, ShieldAlert, Globe, Server, ArrowUpDown, AlertTriangle } from 'lucide-react';
import { format } from 'date-fns';

type SortDirection = 'asc' | 'desc';
type SortKey = 'severity' | 'title';

export default function AssetDetailsPage() {
    const { assetId } = useParams<{ assetId: string }>();
    const [sortConfig, setSortConfig] = useState<{ key: SortKey; direction: SortDirection }>({ key: 'severity', direction: 'desc' });

    const { data: asset, isLoading, error } = useQuery({
        queryKey: ['asset', assetId],
        queryFn: async () => {
            const response = await api.get<Asset>(`/assets/${assetId}`);
            return response.data;
        },
    });

    // Sorted Vulnerabilities
    const sortedVulns = useMemo(() => {
        if (!asset?.vulnerabilities) return [];

        return [...asset.vulnerabilities].sort((a, b) => {
            const direction = sortConfig.direction === 'asc' ? 1 : -1;

            if (sortConfig.key === 'severity') {
                const severityWeight = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                const weightA = severityWeight[a.severity as keyof typeof severityWeight] || 0;
                const weightB = severityWeight[b.severity as keyof typeof severityWeight] || 0;
                return (weightA - weightB) * direction;
            }

            if (sortConfig.key === 'title') {
                return a.title.localeCompare(b.title) * direction;
            }

            return 0;
        });
    }, [asset, sortConfig]);

    const handleSort = (key: SortKey) => {
        setSortConfig(current => ({
            key,
            direction: current.key === key && current.direction === 'desc' ? 'asc' : 'desc'
        }));
    };

    if (isLoading) {
        return <div className="flex h-[50vh] items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
    }

    if (error || !asset) {
        return (
            <div className="flex h-[50vh] flex-col items-center justify-center gap-4 text-destructive">
                <AlertTriangle className="h-12 w-12" />
                <h3 className="text-lg font-semibold">Asset not found or error loading details</h3>
                <Link to="/assets">
                    <Button variant="outline">Back to Assets</Button>
                </Link>
            </div>
        );
    }

    return (
        <div className="space-y-6 animate-in fade-in duration-500">
            <div className="flex items-center gap-4">
                <Link to="/assets">
                    <Button variant="outline" size="icon">
                        <ArrowLeft className="h-4 w-4" />
                    </Button>
                </Link>
                <div>
                    <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
                        {asset.value}
                        <Badge variant={asset.is_active ? 'default' : 'secondary'}>
                            {asset.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                    </h2>
                    <p className="text-muted-foreground text-sm">
                        Type: <span className="capitalize">{asset.asset_type}</span> • Last Seen: {format(new Date(asset.last_seen), 'MMM d, yyyy HH:mm')}
                    </p>
                </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Services</CardTitle>
                        <Server className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{asset.services?.length || 0}</div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
                        <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{asset.vulnerabilities?.length || 0}</div>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Vulnerabilities</CardTitle>
                    <CardDescription>Security issues found on this asset.</CardDescription>
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
                                <TableHead>Description</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {sortedVulns.map((vuln, index) => (
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
                                    <TableCell className="text-muted-foreground text-sm max-w-md truncate" title={vuln.description}>
                                        {vuln.description || '-'}
                                    </TableCell>
                                </TableRow>
                            ))}
                            {sortedVulns.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={3} className="text-center text-muted-foreground py-8">
                                        No vulnerabilities found.
                                    </TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Services</CardTitle>
                    <CardDescription>Open ports and services.</CardDescription>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Port</TableHead>
                                <TableHead>Protocol</TableHead>
                                <TableHead>Service</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {asset.services?.map((service, index) => (
                                <TableRow key={`${service.id}-${index}`}>
                                    <TableCell className="font-medium">{service.port}</TableCell>
                                    <TableCell className="uppercase">{service.protocol}</TableCell>
                                    <TableCell>{service.service_name}</TableCell>
                                </TableRow>
                            ))}
                            {(!asset.services || asset.services.length === 0) && (
                                <TableRow>
                                    <TableCell colSpan={3} className="text-center text-muted-foreground py-8">
                                        No services found.
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
