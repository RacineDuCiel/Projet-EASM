import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { ShieldCheck, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import type { FrameworkScore, ComplianceGap } from '@/types';

interface ComplianceCardProps {
    framework: string;
    scoreData: FrameworkScore;
    gaps: ComplianceGap[];
}

export function ComplianceCard({ framework, scoreData, gaps }: ComplianceCardProps) {
    const getFrameworkName = (fw: string) => {
        const names: Record<string, string> = {
            'iso_27001': 'ISO 27001:2022',
            'soc2': 'SOC 2 Type II',
            'nist_csf': 'NIST CSF 2.0',
            'pci_dss': 'PCI-DSS 4.0'
        };
        return names[fw] || fw;
    };

    const getScoreColor = (score: number) => {
        if (score >= 90) return 'text-green-600';
        if (score >= 70) return 'text-yellow-600';
        return 'text-red-600';
    };

    return (
        <Card>
            <CardHeader className="pb-2">
                <div className="flex justify-between items-start">
                    <div>
                        <CardTitle className="text-lg font-bold">{getFrameworkName(framework)}</CardTitle>
                        <CardDescription>Compliance Status</CardDescription>
                    </div>
                    <div className={`text-2xl font-bold ${getScoreColor(scoreData.score)}`}>
                        {scoreData.score}%
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <div className="space-y-4">
                    <Progress value={scoreData.score} className="h-2" />
                    
                    <div className="grid grid-cols-2 gap-4 text-sm">
                        <div className="flex flex-col">
                            <span className="text-muted-foreground">Controls Assessed</span>
                            <span className="font-medium">{scoreData.total_controls}</span>
                        </div>
                        <div className="flex flex-col">
                            <span className="text-muted-foreground">Compliant</span>
                            <span className="font-medium text-green-600">{scoreData.compliant_controls}</span>
                        </div>
                        <div className="flex flex-col">
                            <span className="text-muted-foreground">Affected</span>
                            <span className="font-medium text-red-600">{scoreData.affected_controls}</span>
                        </div>
                    </div>

                    {gaps.length > 0 && (
                        <div className="pt-4">
                            <h4 className="text-sm font-semibold mb-2">Top Gaps</h4>
                            <Accordion type="single" collapsible className="w-full">
                                {gaps.slice(0, 3).map((gap, idx) => (
                                    <AccordionItem key={idx} value={`gap-${idx}`}>
                                        <AccordionTrigger className="text-sm py-2">
                                            <div className="flex items-center gap-2 text-left">
                                                <AlertTriangle className="h-4 w-4 text-yellow-500 flex-shrink-0" />
                                                <span>{gap.control_id}: {gap.title}</span>
                                            </div>
                                        </AccordionTrigger>
                                        <AccordionContent>
                                            <div className="space-y-2 text-sm text-muted-foreground pl-6">
                                                <p><strong>Impact:</strong> {gap.business_impact}</p>
                                                <p><strong>Findings:</strong> {gap.finding_count} vulnerabilities</p>
                                                <p><strong>Effort:</strong> <Badge variant="outline">{gap.effort}</Badge></p>
                                            </div>
                                        </AccordionContent>
                                    </AccordionItem>
                                ))}
                            </Accordion>
                        </div>
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
