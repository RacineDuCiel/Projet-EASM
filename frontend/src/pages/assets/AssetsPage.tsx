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

// Actually, I'll use a simple span for badges for now or create a Badge component.
// Let's create a simple Badge component inline or use basic Tailwind classes.

export default function AssetsPage() {
    const { data: assets, isLoading, error } = useQuery({
        queryKey: ['assets'],
        queryFn: async () => {
            const response = await api.get<Asset[]>('/assets/');
            return response.data;
        },
    });

    if (isLoading) {
        return <div className="p-8">Loading assets...</div>;
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
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {assets?.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={6} className="h-24 text-center">
                                    No assets found.
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
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </div>
        </div>
    );
}
