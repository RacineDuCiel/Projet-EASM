import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import type { User, Program } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { UserPlus, Trash2, Shield, User as UserIcon, Loader2 } from 'lucide-react';

export default function AdminUsersPage() {
    const queryClient = useQueryClient();
    const [newUser, setNewUser] = useState({ username: '', password: '', role: 'user', program_id: '' });
    const [createError, setCreateError] = useState('');

    // Fetch Users
    const { data: users, isLoading: isLoadingUsers, error: usersError } = useQuery({
        queryKey: ['users'],
        queryFn: async () => {
            const response = await api.get<User[]>('/auth/users/');
            return response.data;
        },
    });

    // Fetch Programs for selection
    const { data: programs } = useQuery({
        queryKey: ['programs'],
        queryFn: async () => {
            const response = await api.get<Program[]>('/programs/');
            return response.data;
        },
    });

    // Create User Mutation
    const createUserMutation = useMutation({
        mutationFn: async (userData: typeof newUser) => {
            const payload = {
                ...userData,
                program_id: userData.role === 'admin' ? null : userData.program_id || null
            };
            await api.post('/auth/users/', payload);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
            setNewUser({ username: '', password: '', role: 'user', program_id: '' });
            setCreateError('');
        },
        onError: (error: any) => {
            setCreateError(error.response?.data?.detail || 'Failed to create user');
        }
    });

    // Delete User Mutation
    const deleteUserMutation = useMutation({
        mutationFn: async (userId: string) => {
            console.log("Deleting user:", userId);
            await api.delete(`/auth/users/${userId}`);
        },
        onSuccess: () => {
            console.log("User deleted successfully");
            queryClient.invalidateQueries({ queryKey: ['users'] });
        },
        onError: (err) => {
            console.error("Failed to delete user:", err);
            alert("Failed to delete user");
        }
    });

    const handleCreateUser = (e: React.FormEvent) => {
        e.preventDefault();
        setCreateError('');
        createUserMutation.mutate(newUser);
    };

    if (isLoadingUsers) return <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    if (usersError) return <div className="p-8 text-destructive">Error loading users. Please check backend logs.</div>;

    return (
        <div className="space-y-8">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">User Management</h2>
                <p className="text-muted-foreground">
                    Manage platform access and assign users to programs.
                </p>
            </div>

            {/* Create User Form */}
            <Card>
                <CardHeader>
                    <CardTitle>Create New User</CardTitle>
                    <CardDescription>Add a new administrator or client user.</CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleCreateUser} className="grid gap-4 md:grid-cols-5 items-end">
                        <div className="grid w-full items-center gap-1.5">
                            <Label htmlFor="username">Username</Label>
                            <Input
                                id="username"
                                value={newUser.username}
                                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                                required
                            />
                        </div>
                        <div className="grid w-full items-center gap-1.5">
                            <Label htmlFor="password">Password</Label>
                            <Input
                                id="password"
                                type="password"
                                value={newUser.password}
                                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                                required
                            />
                        </div>
                        <div className="grid w-full items-center gap-1.5">
                            <Label htmlFor="role">Role</Label>
                            <select
                                id="role"
                                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                                value={newUser.role}
                                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                            >
                                <option value="user">User (Client)</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <div className="grid w-full items-center gap-1.5">
                            <Label htmlFor="program">Program</Label>
                            <select
                                id="program"
                                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                                value={newUser.program_id}
                                onChange={(e) => setNewUser({ ...newUser, program_id: e.target.value })}
                                disabled={newUser.role === 'admin'}
                            >
                                <option value="">Select Program...</option>
                                {programs?.map(p => (
                                    <option key={p.id} value={p.id}>{p.name}</option>
                                ))}
                            </select>
                        </div>
                        <Button type="submit" disabled={createUserMutation.isPending}>
                            {createUserMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="mr-2 h-4 w-4" />}
                            Create
                        </Button>
                    </form>
                    {createError && (
                        <div className="mt-4 p-3 text-sm text-destructive bg-destructive/10 rounded-md">
                            {createError}
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Users List */}
            <Card>
                <CardHeader>
                    <CardTitle>Users Directory</CardTitle>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Username</TableHead>
                                <TableHead>Role</TableHead>
                                <TableHead>Program</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead className="w-[100px]">Actions</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {users?.map((user) => (
                                <TableRow key={user.id}>
                                    <TableCell className="font-medium">{user.username}</TableCell>
                                    <TableCell>
                                        <div className="flex items-center gap-2">
                                            {user.role === 'admin' ? <Shield className="h-4 w-4 text-primary" /> : <UserIcon className="h-4 w-4 text-muted-foreground" />}
                                            <span className="capitalize">{user.role}</span>
                                        </div>
                                    </TableCell>
                                    <TableCell>
                                        {user.program ? user.program.name : '-'}
                                    </TableCell>
                                    <TableCell>
                                        <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${user.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                            {user.is_active ? 'Active' : 'Inactive'}
                                        </span>
                                    </TableCell>
                                    <TableCell>
                                        <Button variant="ghost" size="icon" className="text-destructive" onClick={() => deleteUserMutation.mutate(user.id)}>
                                            <Trash2 className="h-4 w-4" />
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    );
}
