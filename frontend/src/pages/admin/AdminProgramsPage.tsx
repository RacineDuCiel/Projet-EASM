import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Program } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Plus, Trash2, Globe, Server, Network, Loader2 } from 'lucide-react';

export default function AdminProgramsPage() {
    const queryClient = useQueryClient();
    const [newProgramName, setNewProgramName] = useState('');

    // State for new scope input per program (map of programId -> scopeValue)
    const [scopeValues, setScopeValues] = useState<Record<string, string>>({});
    const [scopeTypes, setScopeTypes] = useState<Record<string, 'domain' | 'ip_range' | 'hostname'>>({});

    // Fetch Programs
    const { data: programs, isLoading, error } = useQuery({
        queryKey: ['programs'],
        queryFn: async () => {
            const response = await api.get<Program[]>('/programs/');
            return response.data;
        },
    });

    // Create Program Mutation
    const createProgramMutation = useMutation({
        mutationFn: async (name: string) => {
            await api.post('/programs/', { name });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
            setNewProgramName('');
        },
    });

    // Delete Program Mutation
    const deleteProgramMutation = useMutation({
        mutationFn: async (programId: string) => {
            console.log("Deleting program:", programId);
            await api.delete(`/programs/${programId}`);
        },
        onSuccess: () => {
            console.log("Program deleted successfully");
            queryClient.invalidateQueries({ queryKey: ['programs'] });
        },
        onError: (err) => {
            console.error("Failed to delete program:", err);
            alert("Failed to delete program");
        }
    });

    // Add Scope Mutation
    const addScopeMutation = useMutation({
        mutationFn: async ({ programId, value, type }: { programId: string, value: string, type: string }) => {
            await api.post(`/programs/${programId}/scopes/`, { value, scope_type: type });
        },
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
            setScopeValues(prev => ({ ...prev, [variables.programId]: '' }));
        },
    });

    // Delete Scope Mutation
    const deleteScopeMutation = useMutation({
        mutationFn: async ({ programId, scopeId }: { programId: string, scopeId: string }) => {
            await api.delete(`/programs/${programId}/scopes/${scopeId}`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
        },
    });

    const handleCreateProgram = (e: React.FormEvent) => {
        e.preventDefault();
        if (newProgramName) {
            createProgramMutation.mutate(newProgramName);
        }
    };

    const handleAddScope = (programId: string) => {
        const value = scopeValues[programId];
        const type = scopeTypes[programId] || 'domain';
        if (value) {
            addScopeMutation.mutate({ programId, value, type });
        }
    };

    if (isLoading) return <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    if (error) return <div className="p-8 text-destructive">Error loading programs.</div>;

    return (
        <div className="space-y-8">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Program Management</h2>
                <p className="text-muted-foreground">
                    Create and manage client programs and their scopes.
                </p>
            </div>

            {/* Create Program Form */}
            <Card>
                <CardHeader>
                    <CardTitle>Create New Program</CardTitle>
                    <CardDescription>Add a new client or project to the platform.</CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleCreateProgram} className="flex gap-4 items-end">
                        <div className="grid w-full max-w-sm items-center gap-1.5">
                            <Label htmlFor="programName">Program Name</Label>
                            <Input
                                id="programName"
                                placeholder="e.g., Client A"
                                value={newProgramName}
                                onChange={(e) => setNewProgramName(e.target.value)}
                            />
                        </div>
                        <Button type="submit" disabled={createProgramMutation.isPending}>
                            {createProgramMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Create Program
                        </Button>
                    </form>
                </CardContent>
            </Card>

            {/* Programs List */}
            <div className="grid gap-6">
                {programs?.map((program) => (
                    <Card key={program.id}>
                        <CardHeader className="flex flex-row items-center justify-between">
                            <div>
                                <CardTitle>{program.name}</CardTitle>
                                <CardDescription>Created on {new Date(program.created_at).toLocaleDateString()}</CardDescription>
                            </div>
                            <div className="flex items-center gap-2">
                                <Button variant="ghost" size="icon" className="text-destructive" onClick={() => deleteProgramMutation.mutate(program.id)}>
                                    <Trash2 className="h-4 w-4" />
                                </Button>
                            </div>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-4">
                                <div className="flex items-center justify-between">
                                    <h4 className="text-sm font-semibold">Scopes</h4>
                                </div>

                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Type</TableHead>
                                            <TableHead>Value</TableHead>
                                            <TableHead className="w-[100px]">Actions</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {program.scopes.map((scope) => (
                                            <TableRow key={scope.id}>
                                                <TableCell className="flex items-center gap-2">
                                                    {scope.scope_type === 'domain' && <Globe className="h-4 w-4" />}
                                                    {scope.scope_type === 'ip_range' && <Network className="h-4 w-4" />}
                                                    {scope.scope_type === 'hostname' && <Server className="h-4 w-4" />}
                                                    <span className="capitalize">{scope.scope_type.replace('_', ' ')}</span>
                                                </TableCell>
                                                <TableCell>{scope.value}</TableCell>
                                                <TableCell>
                                                    <Button variant="ghost" size="icon" className="text-destructive" onClick={() => deleteScopeMutation.mutate({ programId: program.id, scopeId: scope.id })}>
                                                        <Trash2 className="h-4 w-4" />
                                                    </Button>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                        {program.scopes.length === 0 && (
                                            <TableRow>
                                                <TableCell colSpan={3} className="text-center text-muted-foreground">
                                                    No scopes defined yet.
                                                </TableCell>
                                            </TableRow>
                                        )}
                                    </TableBody>
                                </Table>

                                {/* Add Scope Form */}
                                <div className="flex gap-2 items-end pt-4 border-t">
                                    <div className="grid w-[150px] items-center gap-1.5">
                                        <Label>Type</Label>
                                        <select
                                            className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                                            value={scopeTypes[program.id] || 'domain'}
                                            onChange={(e) => setScopeTypes(prev => ({ ...prev, [program.id]: e.target.value as any }))}
                                        >
                                            <option value="domain">Domain</option>
                                            <option value="ip_range">IP Range</option>
                                            <option value="hostname">Hostname</option>
                                        </select>
                                    </div>
                                    <div className="grid w-full max-w-sm items-center gap-1.5">
                                        <Label>Value</Label>
                                        <Input
                                            placeholder={scopeTypes[program.id] === 'ip_range' ? '192.168.1.0/24' : 'example.com'}
                                            value={scopeValues[program.id] || ''}
                                            onChange={(e) => setScopeValues(prev => ({ ...prev, [program.id]: e.target.value }))}
                                        />
                                    </div>
                                    <Button
                                        variant="secondary"
                                        onClick={() => handleAddScope(program.id)}
                                        disabled={addScopeMutation.isPending || !scopeValues[program.id]}
                                    >
                                        {addScopeMutation.isPending && addScopeMutation.variables?.programId === program.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
                                        Add Scope
                                    </Button>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>
        </div>
    );
}
