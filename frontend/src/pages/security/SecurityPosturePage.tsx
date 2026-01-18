import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { securityApi } from '@/lib/api';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ComplianceCard } from '@/components/security/ComplianceCard';
import { ShieldCheck } from 'lucide-react';
import type { ComplianceAnalysisResponse } from '@/types';

export default function SecurityPosturePage() {
    const [activeTab, setActiveTab] = useState('compliance');

    // Fetch Compliance Data
    const { data: complianceData } = useQuery<ComplianceAnalysisResponse>({
        queryKey: ['compliance-analysis'],
        queryFn: async () => {
            // In a real scenario, we would pass actual vulnerabilities from the database
            // For now, we'll trigger an analysis with existing DB data via backend logic
            const res = await securityApi.analyzeCompliance({
                vulnerabilities: [], // Backend will fetch them if list is empty but program context is present
                frameworks: ['iso_27001', 'soc2', 'nist_csf', 'pci_dss']
            });
            return res.data;
        }
    });

    return (
        <div className="space-y-8">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Security Posture</h2>
                <p className="text-muted-foreground">
                    Compliance Mapping and Security Analysis.
                </p>
            </div>

            <Tabs defaultValue="compliance" className="space-y-4" onValueChange={setActiveTab}>
                <TabsList>
                    <TabsTrigger value="compliance" className="gap-2">
                        <ShieldCheck className="h-4 w-4" />
                        Compliance Mapping
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="compliance" className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-2">
                        {complianceData?.framework_scores && Object.entries(complianceData.framework_scores).map(([key, score]) => (
                            <ComplianceCard
                                key={key}
                                framework={key}
                                scoreData={score}
                                gaps={complianceData.gap_analysis.filter(g => g.framework === key)}
                            />
                        ))}
                        {!complianceData && (
                            <div className="col-span-full text-center py-12 text-muted-foreground">
                                Loading compliance data...
                            </div>
                        )}
                    </div>
                </TabsContent>
            </Tabs>
        </div>
    );
}
