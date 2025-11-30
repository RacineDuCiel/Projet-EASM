import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const COLORS = {
    critical: '#ef4444', // red-500
    high: '#f97316',     // orange-500
    medium: '#eab308',   // yellow-500
    low: '#3b82f6',      // blue-500
    info: '#94a3b8',     // slate-400
};

interface SeverityData {
    name: string;
    value: number;
}

interface SeverityChartProps {
    data: SeverityData[];
}

export function SeverityChart({ data }: SeverityChartProps) {
    // Filter out zero values for cleaner chart
    const activeData = data.filter(d => d.value > 0);

    return (
        <Card className="col-span-1">
            <CardHeader>
                <CardTitle>Vulnerabilities by Severity</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={activeData}
                                cx="50%"
                                cy="50%"
                                innerRadius={60}
                                outerRadius={80}
                                paddingAngle={5}
                                dataKey="value"
                            >
                                {activeData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[entry.name as keyof typeof COLORS] || '#8884d8'} />
                                ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </CardContent>
        </Card>
    );
}
