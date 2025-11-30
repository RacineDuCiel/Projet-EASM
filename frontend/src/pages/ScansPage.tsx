import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Scan, Program } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Link } from 'react-router-dom';
import { Play, Loader2, RefreshCw, Eye } from 'lucide-react';
import { format } from 'date-fns';

export default function ScansPage() {
    const queryClient = useQueryClient();
    const [isCreateOpen, setIsCreateOpen] = useState(false);
    const [selectedScope, setSelectedScope] = useState('');
    const [selectedType, setSelectedType] = useState('passive');

    // Fetch Scans
    const { data: scans, isLoading: isLoadingScans } = useQuery({
        queryKey: ['scans'],
        queryFn: async () => {
            const response = await api.get<Scan[]>('/scans/');
            return response.data;
        },
        refetchInterval: 5000, // Poll every 5s
    });

    // Fetch Programs (to get scopes)
    const { data: programs } = useQuery({
        queryKey: ['programs'],
        queryFn: async () => {
            const response = await api.get<Program[]>('/programs/');
            return response.data;
        },
    });

    // Flatten scopes for selection
    const allScopes = programs?.flatMap(p => p.scopes.map(s => ({ ...s, programName: p.name }))) || [];

    // Create Scan Mutation
    const createScanMutation = useMutation({
        mutationFn: async () => {
            await api.post('/scans/', {
                scope_id: selectedScope,
                scan_type: selectedType
            });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['scans'] });
            setIsCreateOpen(false);
            setSelectedScope('');
        },
    });

    const handleCreateScan = () => {
        if (selectedScope) {
            createScanMutation.mutate();
        }
    };

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'completed': return 'bg-green-100 text-green-800 hover:bg-green-100';
            case 'running': return 'bg-blue-100 text-blue-800 hover:bg-blue-100';
            case 'failed': return 'bg-red-100 text-red-800 hover:bg-red-100';
            default: return 'bg-gray-100 text-gray-800 hover:bg-gray-100';
        }
    };

    return (
        <div className="space-y-8">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-3xl font-bold tracking-tight">Scans</h2>
                    <p className="text-muted-foreground">
                        Manage and monitor security scans.
                    </p>
                </div>
                <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
                    <DialogTrigger asChild>
                        <Button>
                            <Play className="mr-2 h-4 w-4" />
                            Launch Scan
                        </Button>
                    </DialogTrigger>
                    <DialogContent>
                        <DialogHeader>
                            <DialogTitle>Launch New Scan</DialogTitle>
                            <DialogDescription>
                                Select a target scope and scan type to start immediately.
                            </DialogDescription>
                        </DialogHeader>
                        <div className="grid gap-4 py-4">
                            <div className="grid gap-2">
                                <Label>Target Scope</Label>
                                <Select value={selectedScope} onValueChange={setSelectedScope}>
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select a scope..." />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {allScopes.map(scope => (
                                            <SelectItem key={scope.id} value={scope.id}>
                                                {scope.value} ({scope.scope_type})
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="grid gap-2">
                                <Label>Scan Type</Label>
                                <Select value={selectedType} onValueChange={setSelectedType}>
                                    <SelectTrigger>
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="passive">Passive Discovery</SelectItem>
                                        <SelectItem value="active">Active Scan (Port/Vuln)</SelectItem>
                                        <SelectItem value="full">Full Scan</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>
                        <DialogFooter>
                            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>Cancel</Button>
                            <Button onClick={handleCreateScan} disabled={createScanMutation.isPending || !selectedScope}>
                                {createScanMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                Launch
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                </Dialog>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Recent Scans</CardTitle>
                    <CardDescription>History of all launched scans.</CardDescription>
                </CardHeader>
                <CardContent>
                    {isLoadingScans ? (
                        <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Target</TableHead>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Started At</TableHead>
                                    <TableHead>Duration</TableHead>
                                    <TableHead>Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {scans?.map((scan) => (
                                    <TableRow key={scan.id}>
                                        <TableCell className="font-medium">
                                            {allScopes.find(s => s.id === scan.scope_id)?.value || scan.scope_id}
                                        </TableCell>
                                        <TableCell className="capitalize">{scan.scan_type}</TableCell>
                                        <TableCell>
                                            <Badge variant="secondary" className={getStatusColor(scan.status)}>
                                                {scan.status === 'running' && <RefreshCw className="mr-1 h-3 w-3 animate-spin" />}
                                                {scan.status}
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            {format(new Date(scan.started_at), 'MMM d, yyyy HH:mm')}
                                        </TableCell>
                                        <TableCell>
                                            {scan.completed_at ?
                                                `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)}s`
                                                : '-'}
                                        </TableCell>
                                        <TableCell>
                                            <Link to={`/scans/${scan.id}`}>
                                                <Button variant="ghost" size="sm">
                                                    <Eye className="h-4 w-4 mr-2" />
                                                    View
                                                </Button>
                                            </Link>
                                        </TableCell>
                                    </TableRow>
                                ))}
                                {scans?.length === 0 && (
                                    <TableRow>
                                        <TableCell colSpan={5} className="text-center text-muted-foreground">
                                            No scans found.
                                        </TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
