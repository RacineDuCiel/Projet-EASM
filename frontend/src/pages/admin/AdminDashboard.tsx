import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Activity, Users, Shield, Database, Loader2 } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { SystemLog, User, Program } from '@/types';
import { formatDistanceToNow } from 'date-fns';

export default function AdminDashboard() {
    const { data: logs } = useQuery<SystemLog[]>({
        queryKey: ['system-logs'],
        queryFn: async () => {
            const response = await api.get('/logs/?limit=10');
            return response.data;
        },
        refetchInterval: 30000, // Refresh every 30s
    });

    // Fetch real users data
    const { data: users, isLoading: usersLoading } = useQuery<User[]>({
        queryKey: ['admin-users'],
        queryFn: async () => {
            const response = await api.get('/auth/users/');
            return response.data;
        },
        refetchInterval: 30000,
    });

    // Fetch real programs data
    const { data: programs, isLoading: programsLoading } = useQuery<Program[]>({
        queryKey: ['admin-programs'],
        queryFn: async () => {
            const response = await api.get('/programs/');
            return response.data;
        },
        refetchInterval: 30000,
    });

    // Calculate user stats
    const totalUsers = users?.length ?? 0;
    const adminCount = users?.filter(u => u.role === 'admin').length ?? 0;
    const clientCount = users?.filter(u => u.role === 'user').length ?? 0;
    const activeUsers = users?.filter(u => u.is_active).length ?? 0;

    // Calculate program stats
    const totalPrograms = programs?.length ?? 0;
    const programNames = programs?.slice(0, 3).map(p => p.name).join(', ') || 'No programs';

    return (
        <div className="space-y-8">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Admin Console</h2>
                <p className="text-muted-foreground">
                    Global system management and monitoring.
                </p>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">System Status</CardTitle>
                        <Activity className="h-4 w-4 text-green-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">Healthy</div>
                        <p className="text-xs text-muted-foreground">
                            All services operational
                        </p>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Users</CardTitle>
                        <Users className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        {usersLoading ? (
                            <Loader2 className="h-6 w-6 animate-spin" />
                        ) : (
                            <>
                                <div className="text-2xl font-bold">{totalUsers}</div>
                                <p className="text-xs text-muted-foreground">
                                    {adminCount} Admin{adminCount !== 1 ? 's' : ''}, {clientCount} Client{clientCount !== 1 ? 's' : ''} ({activeUsers} active)
                                </p>
                            </>
                        )}
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Active Programs</CardTitle>
                        <Shield className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        {programsLoading ? (
                            <Loader2 className="h-6 w-6 animate-spin" />
                        ) : (
                            <>
                                <div className="text-2xl font-bold">{totalPrograms}</div>
                                <p className="text-xs text-muted-foreground truncate" title={programNames}>
                                    {programNames}
                                </p>
                            </>
                        )}
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Database</CardTitle>
                        <Database className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">Connected</div>
                        <p className="text-xs text-muted-foreground">
                            PostgreSQL v15
                        </p>
                    </CardContent>
                </Card>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
                <Card className="col-span-4">
                    <CardHeader>
                        <CardTitle>Recent System Logs</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-4">
                            {logs?.length === 0 && (
                                <p className="text-sm text-muted-foreground">No logs available.</p>
                            )}
                            {logs?.map((log) => (
                                <div key={log.id} className="flex items-center">
                                    <div className="ml-4 space-y-1">
                                        <p className="text-sm font-medium leading-none">{log.message}</p>
                                        <p className="text-sm text-muted-foreground">
                                            {formatDistanceToNow(new Date(log.created_at), { addSuffix: true })}
                                        </p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
