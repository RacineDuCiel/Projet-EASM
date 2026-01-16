import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Program } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Bell, Save, Loader2, Send, Radar, Clock, Info, ShieldCheck } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';

export default function SettingsPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();

    // Notifications state
    const [webhookUrl, setWebhookUrl] = useState('');

    // Automated monitoring state
    const [autoScanEnabled, setAutoScanEnabled] = useState(false);
    const [scanFrequency, setScanFrequency] = useState<string>('daily');
    const [deltaScanEnabled, setDeltaScanEnabled] = useState(false);
    const [deltaScanThresholdHours, setDeltaScanThresholdHours] = useState(24);

    // Fetch Settings (Program)
    const { data: program, isLoading, error } = useQuery({
        queryKey: ['settings'],
        queryFn: async () => {
            const response = await api.get<Program>('/settings/');
            return response.data;
        },
        retry: false
    });

    // Initialize state when data loads
    useEffect(() => {
        if (program) {
            if (program.discord_webhook_url) setWebhookUrl(program.discord_webhook_url);
            setAutoScanEnabled(program.auto_scan_enabled ?? false);
            if (program.scan_frequency && program.scan_frequency !== 'never') {
                setScanFrequency(program.scan_frequency);
            }
            setDeltaScanEnabled(program.delta_scan_enabled ?? false);
            setDeltaScanThresholdHours(program.delta_scan_threshold_hours ?? 24);
        }
    }, [program]);

    // Update Settings Mutation
    const updateSettingsMutation = useMutation({
        mutationFn: async (data: {
            discord_webhook_url: string;
            auto_scan_enabled: boolean;
            scan_frequency: string;
            delta_scan_enabled: boolean;
            delta_scan_threshold_hours: number;
        }) => {
            await api.patch('/settings/', data);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['settings'] });
            toast({
                title: "Settings saved",
                description: "Your configuration has been updated.",
            });
        },
        onError: () => {
            toast({
                title: "Error",
                description: "Failed to save settings.",
                variant: "destructive",
            });
        }
    });

    // Test Notification Mutation
    const testNotificationMutation = useMutation({
        mutationFn: async () => {
            await api.post('/settings/test-notification');
        },
        onSuccess: () => {
            toast({
                title: "Test sent",
                description: "Check your Discord channel for the test message.",
            });
        },
        onError: (error: any) => {
            toast({
                title: "Test failed",
                description: error.response?.data?.detail || "Failed to send test notification.",
                variant: "destructive",
            });
        }
    });

    const handleSave = () => {
        updateSettingsMutation.mutate({
            discord_webhook_url: webhookUrl,
            auto_scan_enabled: autoScanEnabled,
            scan_frequency: autoScanEnabled ? scanFrequency : 'never',
            delta_scan_enabled: deltaScanEnabled,
            delta_scan_threshold_hours: deltaScanThresholdHours
        });
    };

    if (isLoading) {
        return <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    }

    if (error) {
        return (
            <div className="space-y-6 animate-in fade-in duration-500">
                <div>
                    <h2 className="text-3xl font-bold tracking-tight">Settings</h2>
                    <p className="text-muted-foreground">
                        Manage your program configuration.
                    </p>
                </div>
                <Card>
                    <CardContent className="flex flex-col items-center justify-center p-12 space-y-4">
                        <div className="p-4 rounded-full bg-muted">
                            <Info className="h-8 w-8 text-muted-foreground" />
                        </div>
                        <div className="text-center space-y-2">
                            <h3 className="text-lg font-semibold">Unable to load settings</h3>
                            <p className="text-muted-foreground max-w-sm">
                                {(error as any)?.response?.status === 404
                                    ? "You are not associated with any program. These settings are for program-specific configurations."
                                    : "An error occurred while loading your settings."}
                            </p>
                        </div>
                    </CardContent>
                </Card>
            </div>
        );
    }

    return (
        <div className="space-y-6 animate-in fade-in duration-500">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Settings</h2>
                <p className="text-muted-foreground">
                    Manage notifications and automated monitoring configuration.
                </p>
            </div>

            <div className="grid gap-6">
                {/* Notifications Card */}
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Bell className="h-5 w-5" />
                            Notifications
                        </CardTitle>
                        <CardDescription>
                            Configure where you want to receive alerts about new vulnerabilities and scan completions.
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="grid gap-2">
                            <Label htmlFor="discord-webhook">Discord Webhook URL</Label>
                            <Input
                                id="discord-webhook"
                                placeholder="https://discord.com/api/webhooks/..."
                                value={webhookUrl}
                                onChange={(e) => setWebhookUrl(e.target.value)}
                            />
                            <p className="text-sm text-muted-foreground">
                                Paste your Discord Webhook URL here to receive real-time alerts.
                            </p>
                        </div>
                    </CardContent>
                    <CardFooter className="flex justify-between border-t px-6 py-4">
                        <Button
                            variant="outline"
                            onClick={() => testNotificationMutation.mutate()}
                            disabled={testNotificationMutation.isPending || !program?.discord_webhook_url}
                        >
                            {testNotificationMutation.isPending ? (
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            ) : (
                                <Send className="mr-2 h-4 w-4" />
                            )}
                            Test Notification
                        </Button>
                    </CardFooter>
                </Card>

                {/* Automated Monitoring Card */}
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Radar className="h-5 w-5" />
                            Automated Monitoring
                        </CardTitle>
                        <CardDescription>
                            Configure automatic scheduled scans. When enabled, scans run at maximum intensity (Full Audit).
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        {/* Enable Toggle */}
                        <div className="flex items-center justify-between">
                            <div className="space-y-0.5">
                                <Label htmlFor="auto-scan-enabled" className="text-base font-medium">
                                    Enable Automatic Scans
                                </Label>
                                <p className="text-sm text-muted-foreground">
                                    When enabled, scans will run automatically based on the schedule below.
                                </p>
                            </div>
                            <Switch
                                id="auto-scan-enabled"
                                checked={autoScanEnabled}
                                onCheckedChange={setAutoScanEnabled}
                            />
                        </div>

                        {autoScanEnabled && (
                            <div className="space-y-6 pt-4 border-t">
                                {/* Frequency Selection */}
                                <div className="grid gap-2">
                                    <Label htmlFor="scan-frequency">Scan Frequency</Label>
                                    <Select value={scanFrequency} onValueChange={setScanFrequency}>
                                        <SelectTrigger id="scan-frequency" className="w-[200px]">
                                            <SelectValue placeholder="Select frequency" />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="daily">Daily</SelectItem>
                                            <SelectItem value="weekly">Weekly</SelectItem>
                                            <SelectItem value="monthly">Monthly</SelectItem>
                                        </SelectContent>
                                    </Select>
                                    <p className="text-sm text-muted-foreground">
                                        Scans run at midnight UTC based on this schedule.
                                    </p>
                                </div>

                                {/* Intensity Info */}
                                <div className="flex items-start gap-3 p-4 rounded-lg bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-800">
                                    <ShieldCheck className="h-5 w-5 text-purple-600 dark:text-purple-400 mt-0.5 shrink-0" />
                                    <div className="space-y-1">
                                        <p className="text-sm font-medium text-purple-900 dark:text-purple-100">
                                            Full Audit Intensity
                                        </p>
                                        <p className="text-sm text-purple-700 dark:text-purple-300">
                                            Automatic scans run with comprehensive coverage: all ports, all Nuclei templates, and extended passive reconnaissance.
                                        </p>
                                    </div>
                                </div>

                                {/* Delta Mode Toggle */}
                                <div className="flex items-center justify-between pt-4 border-t">
                                    <div className="space-y-0.5">
                                        <Label htmlFor="delta-scan-enabled" className="text-base font-medium">
                                            Delta Scanning Mode
                                        </Label>
                                        <p className="text-sm text-muted-foreground">
                                            Only scan assets that haven't been scanned within the threshold period.
                                            Optimizes performance for large inventories.
                                        </p>
                                    </div>
                                    <Switch
                                        id="delta-scan-enabled"
                                        checked={deltaScanEnabled}
                                        onCheckedChange={setDeltaScanEnabled}
                                    />
                                </div>

                                {deltaScanEnabled && (
                                    <div className="ml-6 pl-4 border-l-2 border-muted space-y-2">
                                        <Label htmlFor="delta-threshold">Delta Threshold</Label>
                                        <div className="flex items-center gap-2">
                                            <Clock className="h-4 w-4 text-muted-foreground" />
                                            <Input
                                                id="delta-threshold"
                                                type="number"
                                                min={1}
                                                max={720}
                                                className="w-[100px]"
                                                value={deltaScanThresholdHours}
                                                onChange={(e) => setDeltaScanThresholdHours(parseInt(e.target.value) || 24)}
                                            />
                                            <span className="text-sm text-muted-foreground">hours</span>
                                        </div>
                                        <p className="text-sm text-muted-foreground">
                                            Assets scanned within this period will be skipped.
                                        </p>
                                    </div>
                                )}
                            </div>
                        )}
                    </CardContent>
                </Card>

                {/* Save Button */}
                <div className="flex justify-end">
                    <Button onClick={handleSave} disabled={updateSettingsMutation.isPending} size="lg">
                        {updateSettingsMutation.isPending ? (
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        ) : (
                            <Save className="mr-2 h-4 w-4" />
                        )}
                        Save All Changes
                    </Button>
                </div>
            </div>
        </div>
    );
}
