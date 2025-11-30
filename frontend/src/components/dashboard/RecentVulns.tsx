import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { Vulnerability } from '@/types';
import { formatDistanceToNow } from 'date-fns';
import { Badge } from '@/components/ui/badge';

interface RecentVulnsProps {
    vulns: Vulnerability[];
}

export function RecentVulns({ vulns }: RecentVulnsProps) {
    return (
        <Card className="col-span-1">
            <CardHeader>
                <CardTitle>
                    Recent Critical/High Vulns
                </CardTitle>
            </CardHeader>
            <CardContent>
                <ScrollArea className="h-[300px] pr-4">
                    <div className="space-y-4">
                        {vulns.map((vuln) => (
                            <div key={vuln.id} className="flex items-start gap-4 border-b pb-4 last:border-0">
                                <div className="space-y-1 w-full">
                                    <div className="flex justify-between items-start">
                                        <p className="text-sm font-medium leading-none truncate max-w-[200px]" title={vuln.title}>
                                            {vuln.title}
                                        </p>
                                        <Badge variant={vuln.severity === 'critical' ? 'destructive' : 'default'} className="text-[10px] px-1 py-0 h-5">
                                            {vuln.severity}
                                        </Badge>
                                    </div>
                                    <p className="text-xs text-muted-foreground">
                                        Found {formatDistanceToNow(new Date(vuln.created_at), { addSuffix: true })}
                                    </p>
                                </div>
                            </div>
                        ))}
                        {vulns.length === 0 && (
                            <p className="text-sm text-muted-foreground text-center py-4">No recent critical vulnerabilities found.</p>
                        )}
                    </div>
                </ScrollArea>
            </CardContent>
        </Card>
    );
}
