import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { Asset } from '@/types';
import { formatDistanceToNow } from 'date-fns';

interface RecentAssetsProps {
    assets: Asset[];
}

export function RecentAssets({ assets }: RecentAssetsProps) {
    return (
        <Card className="col-span-1">
            <CardHeader>
                <CardTitle>
                    New Assets Discovered
                </CardTitle>
            </CardHeader>
            <CardContent>
                <ScrollArea className="h-[300px] pr-4">
                    <div className="space-y-4">
                        {assets.map((asset) => (
                            <div key={asset.id} className="flex items-start gap-4 border-b pb-4 last:border-0">
                                <div className="space-y-1">
                                    <p className="text-sm font-medium leading-none">
                                        {asset.value}
                                    </p>
                                    <p className="text-xs text-muted-foreground">
                                        First seen {formatDistanceToNow(new Date(asset.first_seen), { addSuffix: true })}
                                    </p>
                                </div>
                            </div>
                        ))}
                        {assets.length === 0 && (
                            <p className="text-sm text-muted-foreground text-center py-4">No new assets recently.</p>
                        )}
                    </div>
                </ScrollArea>
            </CardContent>
        </Card>
    );
}
