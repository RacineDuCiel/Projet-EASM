import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import type { AssetPassiveIntel, PassiveIntelSummary } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
    Loader2,
    Globe,
    ShieldCheck,
    Lock,
    Network,
    History,
    Server,
    Search,
    FileCode,
    AlertTriangle,
    CheckCircle,
    XCircle,
    ExternalLink
} from 'lucide-react';
import { format } from 'date-fns';

interface PassiveIntelTabsProps {
    assetId: string;
}

export default function PassiveIntelTabs({ assetId }: PassiveIntelTabsProps) {
    const { data: summary, isLoading: summaryLoading } = useQuery({
        queryKey: ['passive-intel-summary', assetId],
        queryFn: async () => {
            const response = await api.get<PassiveIntelSummary>(`/passive-intel/assets/${assetId}/summary`);
            return response.data;
        },
    });

    const { data: intel, isLoading: intelLoading } = useQuery({
        queryKey: ['passive-intel', assetId],
        queryFn: async () => {
            const response = await api.get<AssetPassiveIntel>(`/passive-intel/assets/${assetId}`);
            return response.data;
        },
    });

    if (summaryLoading || intelLoading) {
        return (
            <div className="flex h-32 items-center justify-center">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
        );
    }

    const hasData = summary && (
        summary.dns_record_count > 0 ||
        summary.certificate_count > 0 ||
        summary.has_whois ||
        summary.has_asn ||
        summary.has_shodan ||
        summary.endpoint_count > 0 ||
        summary.historical_url_count > 0
    );

    if (!hasData) {
        return (
            <Card>
                <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                    <Search className="h-12 w-12 mb-4 opacity-50" />
                    <p className="text-lg font-medium">No passive intelligence data available</p>
                    <p className="text-sm mt-2">Run a scan to collect OSINT data for this asset</p>
                </CardContent>
            </Card>
        );
    }

    return (
        <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid gap-4 md:grid-cols-4 lg:grid-cols-6">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">DNS Records</CardTitle>
                        <Globe className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{summary?.dns_record_count || 0}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Certificates</CardTitle>
                        <Lock className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{summary?.certificate_count || 0}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Endpoints</CardTitle>
                        <FileCode className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{summary?.endpoint_count || 0}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Historical URLs</CardTitle>
                        <History className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{summary?.historical_url_count || 0}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Security Grade</CardTitle>
                        <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {summary?.security_header_grade || '-'}
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Data Sources</CardTitle>
                        <Server className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="flex gap-1 flex-wrap">
                            {summary?.has_whois && <Badge variant="outline" className="text-xs">WHOIS</Badge>}
                            {summary?.has_asn && <Badge variant="outline" className="text-xs">ASN</Badge>}
                            {summary?.has_shodan && <Badge variant="outline" className="text-xs">Shodan</Badge>}
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Detailed Tabs */}
            <Card>
                <Tabs defaultValue="dns" className="w-full">
                    <CardHeader>
                        <TabsList className="grid w-full grid-cols-4 lg:grid-cols-7">
                            <TabsTrigger value="dns">DNS</TabsTrigger>
                            <TabsTrigger value="whois">WHOIS</TabsTrigger>
                            <TabsTrigger value="certs">Certificates</TabsTrigger>
                            <TabsTrigger value="headers">Headers</TabsTrigger>
                            <TabsTrigger value="asn">ASN</TabsTrigger>
                            <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
                            <TabsTrigger value="shodan">Shodan</TabsTrigger>
                        </TabsList>
                    </CardHeader>

                    <CardContent>
                        {/* DNS Records Tab */}
                        <TabsContent value="dns" className="mt-0">
                            <CardDescription className="mb-4">DNS records discovered for this asset</CardDescription>
                            <ScrollArea className="h-[400px]">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Type</TableHead>
                                            <TableHead>Value</TableHead>
                                            <TableHead>TTL</TableHead>
                                            <TableHead>Priority</TableHead>
                                            <TableHead>Last Seen</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {intel?.dns_records?.map((record) => (
                                            <TableRow key={record.id}>
                                                <TableCell>
                                                    <Badge variant="outline">{record.record_type}</Badge>
                                                </TableCell>
                                                <TableCell className="font-mono text-sm max-w-md truncate">
                                                    {record.record_value}
                                                </TableCell>
                                                <TableCell>{record.ttl || '-'}</TableCell>
                                                <TableCell>{record.priority || '-'}</TableCell>
                                                <TableCell className="text-muted-foreground text-sm">
                                                    {format(new Date(record.last_seen), 'MMM d, HH:mm')}
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                        {(!intel?.dns_records || intel.dns_records.length === 0) && (
                                            <TableRow>
                                                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                                                    No DNS records found
                                                </TableCell>
                                            </TableRow>
                                        )}
                                    </TableBody>
                                </Table>
                            </ScrollArea>
                        </TabsContent>

                        {/* WHOIS Tab */}
                        <TabsContent value="whois" className="mt-0">
                            <CardDescription className="mb-4">Domain registration information</CardDescription>
                            {intel?.whois_record ? (
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-3">
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Registrar</label>
                                            <p className="font-medium">{intel.whois_record.registrar || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Organization</label>
                                            <p className="font-medium">{intel.whois_record.registrant_org || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Country</label>
                                            <p className="font-medium">{intel.whois_record.registrant_country || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">DNSSEC</label>
                                            <p className="font-medium">
                                                {intel.whois_record.dnssec ? (
                                                    <Badge variant="default" className="bg-green-600">Enabled</Badge>
                                                ) : (
                                                    <Badge variant="secondary">Disabled</Badge>
                                                )}
                                            </p>
                                        </div>
                                    </div>
                                    <div className="space-y-3">
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Creation Date</label>
                                            <p className="font-medium">{intel.whois_record.creation_date || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Expiration Date</label>
                                            <p className="font-medium">{intel.whois_record.expiration_date || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Updated Date</label>
                                            <p className="font-medium">{intel.whois_record.updated_date || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Name Servers</label>
                                            <p className="font-mono text-sm">{intel.whois_record.name_servers || '-'}</p>
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                <div className="text-center text-muted-foreground py-8">
                                    No WHOIS data available
                                </div>
                            )}
                        </TabsContent>

                        {/* Certificates Tab */}
                        <TabsContent value="certs" className="mt-0">
                            <CardDescription className="mb-4">SSL/TLS certificates from Certificate Transparency logs</CardDescription>
                            <ScrollArea className="h-[400px]">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Subject</TableHead>
                                            <TableHead>Issuer</TableHead>
                                            <TableHead>Valid Until</TableHead>
                                            <TableHead>Status</TableHead>
                                            <TableHead>Source</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {intel?.certificates?.map((cert) => (
                                            <TableRow key={cert.id}>
                                                <TableCell className="max-w-xs">
                                                    <div className="font-medium truncate">{cert.subject_cn || '-'}</div>
                                                    {cert.is_wildcard && <Badge variant="outline" className="text-xs mt-1">Wildcard</Badge>}
                                                </TableCell>
                                                <TableCell className="text-sm text-muted-foreground truncate max-w-xs">
                                                    {cert.issuer_org || cert.issuer_cn || '-'}
                                                </TableCell>
                                                <TableCell className="text-sm">
                                                    {cert.not_after || '-'}
                                                </TableCell>
                                                <TableCell>
                                                    {cert.is_expired ? (
                                                        <Badge variant="destructive" className="flex items-center gap-1 w-fit">
                                                            <XCircle className="h-3 w-3" /> Expired
                                                        </Badge>
                                                    ) : (
                                                        <Badge variant="default" className="flex items-center gap-1 w-fit bg-green-600">
                                                            <CheckCircle className="h-3 w-3" /> Valid
                                                        </Badge>
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    <Badge variant="outline" className="text-xs">{cert.source || 'unknown'}</Badge>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                        {(!intel?.certificates || intel.certificates.length === 0) && (
                                            <TableRow>
                                                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                                                    No certificates found
                                                </TableCell>
                                            </TableRow>
                                        )}
                                    </TableBody>
                                </Table>
                            </ScrollArea>
                        </TabsContent>

                        {/* Security Headers Tab */}
                        <TabsContent value="headers" className="mt-0">
                            <CardDescription className="mb-4">HTTP security headers analysis</CardDescription>
                            {intel?.security_headers && intel.security_headers.length > 0 ? (
                                <div className="space-y-4">
                                    {intel.security_headers.map((header) => (
                                        <div key={header.id} className="border rounded-lg p-4">
                                            <div className="flex items-center justify-between mb-4">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-sm text-muted-foreground">{header.url}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-sm text-muted-foreground">Score:</span>
                                                    <Badge variant={
                                                        header.grade === 'A' || header.grade === 'A+' ? 'default' :
                                                        header.grade === 'B' ? 'default' :
                                                        header.grade === 'C' ? 'secondary' :
                                                        'destructive'
                                                    } className={
                                                        header.grade === 'A' || header.grade === 'A+' ? 'bg-green-600' :
                                                        header.grade === 'B' ? 'bg-yellow-600' : ''
                                                    }>
                                                        {header.grade || '-'} ({header.score || 0}/100)
                                                    </Badge>
                                                </div>
                                            </div>
                                            <div className="grid gap-3 md:grid-cols-2">
                                                <HeaderStatus label="Content-Security-Policy" value={header.content_security_policy} />
                                                <HeaderStatus label="Strict-Transport-Security" value={header.strict_transport_security} />
                                                <HeaderStatus label="X-Frame-Options" value={header.x_frame_options} />
                                                <HeaderStatus label="X-Content-Type-Options" value={header.x_content_type_options} />
                                                <HeaderStatus label="Referrer-Policy" value={header.referrer_policy} />
                                                <HeaderStatus label="Permissions-Policy" value={header.permissions_policy} />
                                            </div>
                                            {header.missing_headers && (
                                                <div className="mt-4 p-3 bg-destructive/10 rounded-md">
                                                    <div className="flex items-center gap-2 text-destructive text-sm font-medium mb-2">
                                                        <AlertTriangle className="h-4 w-4" />
                                                        Missing Headers
                                                    </div>
                                                    <p className="text-sm text-muted-foreground">{header.missing_headers}</p>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="text-center text-muted-foreground py-8">
                                    No security headers data available
                                </div>
                            )}
                        </TabsContent>

                        {/* ASN Tab */}
                        <TabsContent value="asn" className="mt-0">
                            <CardDescription className="mb-4">Autonomous System Number information</CardDescription>
                            <ScrollArea className="h-[400px]">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>IP Address</TableHead>
                                            <TableHead>ASN</TableHead>
                                            <TableHead>Organization</TableHead>
                                            <TableHead>BGP Prefix</TableHead>
                                            <TableHead>Country</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {intel?.asn_info?.map((asn) => (
                                            <TableRow key={asn.id}>
                                                <TableCell className="font-mono">{asn.ip_address}</TableCell>
                                                <TableCell>
                                                    <Badge variant="outline">AS{asn.asn_number}</Badge>
                                                </TableCell>
                                                <TableCell className="max-w-xs truncate">
                                                    {asn.asn_name || asn.asn_description || '-'}
                                                </TableCell>
                                                <TableCell className="font-mono text-sm">{asn.bgp_prefix || '-'}</TableCell>
                                                <TableCell>{asn.asn_country || '-'}</TableCell>
                                            </TableRow>
                                        ))}
                                        {(!intel?.asn_info || intel.asn_info.length === 0) && (
                                            <TableRow>
                                                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                                                    No ASN data available
                                                </TableCell>
                                            </TableRow>
                                        )}
                                    </TableBody>
                                </Table>
                            </ScrollArea>
                        </TabsContent>

                        {/* Endpoints Tab */}
                        <TabsContent value="endpoints" className="mt-0">
                            <CardDescription className="mb-4">
                                Discovered endpoints from crawling and URL aggregation
                            </CardDescription>
                            <ScrollArea className="h-[400px]">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>URL</TableHead>
                                            <TableHead>Method</TableHead>
                                            <TableHead>Status</TableHead>
                                            <TableHead>Type</TableHead>
                                            <TableHead>Source</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {intel?.crawled_endpoints?.map((endpoint) => (
                                            <TableRow key={endpoint.id}>
                                                <TableCell className="max-w-md">
                                                    <a
                                                        href={endpoint.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="font-mono text-sm text-primary hover:underline flex items-center gap-1 truncate"
                                                    >
                                                        {endpoint.url}
                                                        <ExternalLink className="h-3 w-3 flex-shrink-0" />
                                                    </a>
                                                </TableCell>
                                                <TableCell>
                                                    <Badge variant="outline">{endpoint.method}</Badge>
                                                </TableCell>
                                                <TableCell>
                                                    {endpoint.status_code ? (
                                                        <Badge variant={
                                                            endpoint.status_code >= 200 && endpoint.status_code < 300 ? 'default' :
                                                            endpoint.status_code >= 300 && endpoint.status_code < 400 ? 'secondary' :
                                                            'destructive'
                                                        } className={
                                                            endpoint.status_code >= 200 && endpoint.status_code < 300 ? 'bg-green-600' : ''
                                                        }>
                                                            {endpoint.status_code}
                                                        </Badge>
                                                    ) : '-'}
                                                </TableCell>
                                                <TableCell>
                                                    {endpoint.is_api_endpoint && <Badge variant="outline" className="mr-1">API</Badge>}
                                                    {endpoint.is_js_file && <Badge variant="outline">JS</Badge>}
                                                    {!endpoint.is_api_endpoint && !endpoint.is_js_file && '-'}
                                                </TableCell>
                                                <TableCell>
                                                    <Badge variant="outline" className="text-xs">{endpoint.source || 'unknown'}</Badge>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                        {(!intel?.crawled_endpoints || intel.crawled_endpoints.length === 0) && (
                                            <TableRow>
                                                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                                                    No endpoints discovered
                                                </TableCell>
                                            </TableRow>
                                        )}
                                    </TableBody>
                                </Table>
                            </ScrollArea>
                        </TabsContent>

                        {/* Shodan Tab */}
                        <TabsContent value="shodan" className="mt-0">
                            <CardDescription className="mb-4">Shodan intelligence data</CardDescription>
                            {intel?.shodan_data ? (
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-3">
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">IP Address</label>
                                            <p className="font-mono">{intel.shodan_data.ip_address}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Organization</label>
                                            <p className="font-medium">{intel.shodan_data.org || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">ISP</label>
                                            <p className="font-medium">{intel.shodan_data.isp || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">OS</label>
                                            <p className="font-medium">{intel.shodan_data.os || '-'}</p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Open Ports</label>
                                            <div className="flex gap-1 flex-wrap mt-1">
                                                {intel.shodan_data.open_ports ? (
                                                    JSON.parse(intel.shodan_data.open_ports).map((port: number) => (
                                                        <Badge key={port} variant="outline">{port}</Badge>
                                                    ))
                                                ) : '-'}
                                            </div>
                                        </div>
                                    </div>
                                    <div className="space-y-3">
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Location</label>
                                            <p className="font-medium">
                                                {[intel.shodan_data.city, intel.shodan_data.region, intel.shodan_data.country]
                                                    .filter(Boolean).join(', ') || '-'}
                                            </p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Hostnames</label>
                                            <p className="font-mono text-sm">{intel.shodan_data.hostnames || '-'}</p>
                                        </div>
                                        {intel.shodan_data.vulns && (
                                            <div>
                                                <label className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                                                    <AlertTriangle className="h-4 w-4 text-destructive" />
                                                    Known Vulnerabilities
                                                </label>
                                                <div className="flex gap-1 flex-wrap mt-1">
                                                    {JSON.parse(intel.shodan_data.vulns).map((cve: string) => (
                                                        <Badge key={cve} variant="destructive">{cve}</Badge>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                        <div>
                                            <label className="text-sm font-medium text-muted-foreground">Last Update</label>
                                            <p className="text-sm text-muted-foreground">{intel.shodan_data.last_update || '-'}</p>
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                <div className="text-center text-muted-foreground py-8">
                                    No Shodan data available (requires API key)
                                </div>
                            )}
                        </TabsContent>
                    </CardContent>
                </Tabs>
            </Card>
        </div>
    );
}

// Helper component for header status display
function HeaderStatus({ label, value }: { label: string; value?: string }) {
    return (
        <div className="flex items-center justify-between p-2 rounded bg-muted/50">
            <span className="text-sm font-medium">{label}</span>
            {value ? (
                <Badge variant="default" className="bg-green-600">
                    <CheckCircle className="h-3 w-3 mr-1" />
                    Set
                </Badge>
            ) : (
                <Badge variant="secondary">
                    <XCircle className="h-3 w-3 mr-1" />
                    Missing
                </Badge>
            )}
        </div>
    );
}
