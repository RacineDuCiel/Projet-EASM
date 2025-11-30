import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { DashboardStats, Vulnerability, Asset } from '@/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2 } from 'lucide-react';
import { SeverityChart } from '@/components/dashboard/SeverityChart';
import { TrendChart } from '@/components/dashboard/TrendChart';
import { RecentVulns } from '@/components/dashboard/RecentVulns';
import { RecentAssets } from '@/components/dashboard/RecentAssets';

export default function DashboardPage() {
    const { data: stats, isLoading: isLoadingStats } = useQuery({
        queryKey: ['dashboard-stats'],
        queryFn: async () => {
            const response = await api.get<DashboardStats>('/monitoring/stats');
            return response.data;
        },
    });

    const { data: severityData } = useQuery({
        queryKey: ['severity-distribution'],
        queryFn: async () => {
            const response = await api.get<{ name: string, value: number }[]>('/monitoring/severity-distribution');
            return response.data;
        },
    });

    const { data: trendData } = useQuery({
        queryKey: ['vuln-trend'],
        queryFn: async () => {
            const response = await api.get<{ date: string, count: number }[]>('/monitoring/vuln-trend');
            return response.data;
        },
    });

    const { data: recentVulns } = useQuery({
        queryKey: ['recent-vulns'],
        queryFn: async () => {
            const response = await api.get<Vulnerability[]>('/monitoring/recent-vulns');
            return response.data;
        },
    });

    const { data: recentAssets } = useQuery({
        queryKey: ['recent-assets'],
        queryFn: async () => {
            const response = await api.get<Asset[]>('/monitoring/recent-assets');
            return response.data;
        },
    });

    if (isLoadingStats) {
        return <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    }

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
                <p className="text-muted-foreground">
                    Overview of your attack surface and security posture.
                </p>
            </div>

            {/* KPI Cards */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Assets</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats?.assets.total}</div>
                        <p className="text-xs text-muted-foreground">
                            Discovered across all programs
                        </p>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats?.scans.running}</div>
                        <p className="text-xs text-muted-foreground">
                            {stats?.scans.total} total scans performed
                        </p>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats?.vulnerabilities.total}</div>
                        <p className="text-xs text-muted-foreground">
                            {stats?.vulnerabilities.critical} Critical, {stats?.vulnerabilities.high} High
                        </p>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Programs</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stats?.programs.total}</div>
                        <p className="text-xs text-muted-foreground">
                            Active scopes
                        </p>
                    </CardContent>
                </Card>
            </div>

            {/* Charts Section */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
                <div className="col-span-4">
                    <TrendChart data={trendData || []} />
                </div>
                <div className="col-span-3">
                    <SeverityChart data={severityData || []} />
                </div>
            </div>

            {/* Recent Activity Section */}
            <div className="grid gap-4 md:grid-cols-2">
                <RecentVulns vulns={recentVulns || []} />
                <RecentAssets assets={recentAssets || []} />
            </div>
        </div>
    );
}
