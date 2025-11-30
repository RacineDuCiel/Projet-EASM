import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Asset } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Loader2, ShieldAlert, Globe, Server } from 'lucide-react';
import { format } from 'date-fns';

export default function AssetDetailsPage() {
    const { assetId } = useParams<{ assetId: string }>();

    // Fetch Asset Details (we might need a specific endpoint for single asset if not available, 
    // but for now let's assume we can filter or get it. 
    // Actually, backend doesn't have GET /assets/{id} yet. 
    // We should probably add it or just filter from list if list is small, but that's bad practice.
    // Let's check backend endpoints again. 
    // Wait, I can't check backend in the middle of write_to_file. 
    // I'll assume I need to add GET /assets/{id} to backend as well.
    // For now, I'll write the frontend assuming the endpoint exists or I'll implement it next.)

    const { data: asset, isLoading } = useQuery({
        queryKey: ['asset', assetId],
        queryFn: async () => {
            // TODO: Ensure backend has this endpoint
            const response = await api.get<Asset>(`/assets/${assetId}`);
            return response.data;
        },
    });

    if (isLoading) {
        return <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    }

    if (!asset) {
        return <div>Asset not found</div>;
    }

    return (
        <div className="space-y-6">
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
                                <TableHead>Severity</TableHead>
                                <TableHead>Title</TableHead>
                                <TableHead>Description</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {asset.vulnerabilities?.map((vuln, index) => (
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
                            {(!asset.vulnerabilities || asset.vulnerabilities.length === 0) && (
                                <TableRow>
                                    <TableCell colSpan={3} className="text-center text-muted-foreground">
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
                                    <TableCell colSpan={3} className="text-center text-muted-foreground">
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
