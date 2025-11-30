import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { programsService } from '@/services/programs.service';
import type { Program } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { useToast } from "@/components/ui/use-toast";
import { Plus, Trash2, Globe, Server, Network, Loader2, AlertCircle } from 'lucide-react';

// --- Schemas ---
const programSchema = z.object({
    name: z.string().min(2, "Name must be at least 2 characters"),
});

type ProgramFormValues = z.infer<typeof programSchema>;

const scopeSchema = z.object({
    value: z.string().min(1, "Value is required"),
    type: z.enum(['domain', 'ip_range', 'hostname']),
});

type ScopeFormValues = z.infer<typeof scopeSchema>;

// --- Components ---

function CreateProgramForm() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<ProgramFormValues>({
        resolver: zodResolver(programSchema),
    });

    const createMutation = useMutation({
        mutationFn: programsService.create,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
            toast({ title: "Success", description: "Program created successfully." });
            reset();
        },
        onError: () => {
            toast({ variant: "destructive", title: "Error", description: "Failed to create program." });
        }
    });

    const onSubmit = (data: ProgramFormValues) => {
        createMutation.mutate(data.name);
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle>Create New Program</CardTitle>
                <CardDescription>Add a new client or project to the platform.</CardDescription>
            </CardHeader>
            <CardContent>
                <form onSubmit={handleSubmit(onSubmit)} className="flex gap-4 items-start">
                    <div className="grid w-full max-w-sm items-center gap-1.5">
                        <Label htmlFor="programName">Program Name</Label>
                        <Input
                            id="programName"
                            placeholder="e.g., Client A"
                            {...register('name')}
                            className={errors.name ? "border-destructive" : ""}
                        />
                        {errors.name && <span className="text-xs text-destructive">{errors.name.message}</span>}
                    </div>
                    <Button type="submit" disabled={isSubmitting} className="mt-6">
                        {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Create Program
                    </Button>
                </form>
            </CardContent>
        </Card>
    );
}

function ProgramCard({ program }: { program: Program }) {
    const queryClient = useQueryClient();
    const { toast } = useToast();

    // Scope Form
    const { register, handleSubmit, reset, setValue, watch, formState: { errors, isSubmitting } } = useForm<ScopeFormValues>({
        resolver: zodResolver(scopeSchema),
        defaultValues: { type: 'domain', value: '' }
    });

    const scopeType = watch('type');

    const deleteProgramMutation = useMutation({
        mutationFn: programsService.delete,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
            toast({ title: "Success", description: "Program deleted successfully." });
        },
        onError: () => {
            toast({ variant: "destructive", title: "Error", description: "Failed to delete program." });
        }
    });

    const addScopeMutation = useMutation({
        mutationFn: (data: ScopeFormValues) => programsService.addScope(program.id, data.value, data.type),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
            toast({ title: "Success", description: "Scope added successfully." });
            reset({ type: scopeType, value: '' }); // Keep the selected type
        },
        onError: () => {
            toast({ variant: "destructive", title: "Error", description: "Failed to add scope." });
        }
    });

    const deleteScopeMutation = useMutation({
        mutationFn: (scopeId: string) => programsService.deleteScope(program.id, scopeId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
            toast({ title: "Success", description: "Scope deleted successfully." });
        },
        onError: () => {
            toast({ variant: "destructive", title: "Error", description: "Failed to delete scope." });
        }
    });

    const onAddScope = (data: ScopeFormValues) => {
        addScopeMutation.mutate(data);
    };

    return (
        <Card>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>{program.name}</CardTitle>
                    <CardDescription>Created on {new Date(program.created_at).toLocaleDateString()}</CardDescription>
                </div>
                <AlertDialog>
                    <AlertDialogTrigger asChild>
                        <Button variant="ghost" size="icon" className="text-destructive hover:text-destructive/90 hover:bg-destructive/10">
                            <Trash2 className="h-4 w-4" />
                        </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                        <AlertDialogHeader>
                            <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                            <AlertDialogDescription>
                                This action cannot be undone. This will permanently delete the program
                                <strong> {program.name} </strong> and all associated data (scopes, scans, assets).
                            </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteProgramMutation.mutate(program.id)} className="bg-destructive hover:bg-destructive/90">
                                Delete
                            </AlertDialogAction>
                        </AlertDialogFooter>
                    </AlertDialogContent>
                </AlertDialog>
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
                                        {scope.scope_type === 'domain' && <Globe className="h-4 w-4 text-blue-500" />}
                                        {scope.scope_type === 'ip_range' && <Network className="h-4 w-4 text-green-500" />}
                                        {scope.scope_type === 'hostname' && <Server className="h-4 w-4 text-orange-500" />}
                                        <span className="capitalize">{scope.scope_type.replace('_', ' ')}</span>
                                    </TableCell>
                                    <TableCell className="font-mono text-sm">{scope.value}</TableCell>
                                    <TableCell>
                                        <Button
                                            variant="ghost"
                                            size="icon"
                                            className="text-muted-foreground hover:text-destructive"
                                            onClick={() => deleteScopeMutation.mutate(scope.id)}
                                            disabled={deleteScopeMutation.isPending}
                                        >
                                            {deleteScopeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                            {program.scopes.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={3} className="text-center text-muted-foreground py-6">
                                        No scopes defined yet. Add one below.
                                    </TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                    </Table>

                    {/* Add Scope Form */}
                    <form onSubmit={handleSubmit(onAddScope)} className="flex gap-2 items-start pt-4 border-t">
                        <div className="grid w-[150px] items-center gap-1.5">
                            <Label>Type</Label>
                            <Select
                                value={scopeType}
                                onValueChange={(val) => setValue('type', val as any)}
                            >
                                <SelectTrigger>
                                    <SelectValue placeholder="Select type" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="domain">Domain</SelectItem>
                                    <SelectItem value="ip_range">IP Range</SelectItem>
                                    <SelectItem value="hostname">Hostname</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="grid w-full max-w-sm items-center gap-1.5">
                            <Label>Value</Label>
                            <Input
                                placeholder={scopeType === 'ip_range' ? '192.168.1.0/24' : 'example.com'}
                                {...register('value')}
                                className={errors.value ? "border-destructive" : ""}
                            />
                            {errors.value && <span className="text-xs text-destructive">{errors.value.message}</span>}
                        </div>
                        <Button
                            type="submit"
                            variant="secondary"
                            className="mt-6"
                            disabled={isSubmitting}
                        >
                            {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
                            Add Scope
                        </Button>
                    </form>
                </div>
            </CardContent>
        </Card>
    );
}

// --- Main Page Component ---

export default function AdminProgramsPage() {
    const { data: programs, isLoading, error } = useQuery({
        queryKey: ['programs'],
        queryFn: programsService.getAll,
    });

    if (isLoading) return <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
    if (error) return (
        <div className="p-8 flex flex-col items-center gap-4 text-destructive">
            <AlertCircle className="h-12 w-12" />
            <p>Error loading programs. Please try again later.</p>
        </div>
    );

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Program Management</h2>
                <p className="text-muted-foreground">
                    Create and manage client programs and their scopes.
                </p>
            </div>

            <CreateProgramForm />

            <div className="grid gap-6">
                {programs?.map((program) => (
                    <ProgramCard key={program.id} program={program} />
                ))}
                {programs?.length === 0 && (
                    <div className="text-center p-12 border-2 border-dashed rounded-lg text-muted-foreground">
                        No programs found. Create your first one above.
                    </div>
                )}
            </div>
        </div>
    );
}
