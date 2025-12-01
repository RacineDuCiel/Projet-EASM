import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Program } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Bell, Save, Loader2, Send, CalendarClock, Settings } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';

export default function SettingsPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [webhookUrl, setWebhookUrl] = useState('');
    const [scanFrequency, setScanFrequency] = useState<string>('never');

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
            if (program.scan_frequency) setScanFrequency(program.scan_frequency);
        }
    }, [program]);

    // Update Settings Mutation
    const updateSettingsMutation = useMutation({
        mutationFn: async (data: { discord_webhook_url: string; scan_frequency: string }) => {
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
            scan_frequency: scanFrequency
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
                            <Settings className="h-8 w-8 text-muted-foreground" />
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
                    Manage your program configuration, notifications, and scheduling.
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

                {/* Scheduling Card */}
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <CalendarClock className="h-5 w-5" />
                            Scan Scheduling
                        </CardTitle>
                        <CardDescription>
                            Automate your security scans. Choose how often you want the platform to scan your assets.
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="grid gap-2">
                            <Label htmlFor="scan-frequency">Automatic Scan Frequency</Label>
                            <Select value={scanFrequency} onValueChange={setScanFrequency}>
                                <SelectTrigger id="scan-frequency" className="w-[240px]">
                                    <SelectValue placeholder="Select frequency" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="never">Never (Manual only)</SelectItem>
                                    <SelectItem value="daily">Daily</SelectItem>
                                    <SelectItem value="weekly">Weekly</SelectItem>
                                    <SelectItem value="monthly">Monthly</SelectItem>
                                </SelectContent>
                            </Select>
                            <p className="text-sm text-muted-foreground">
                                Automated scans will run at midnight UTC based on the selected frequency.
                            </p>
                        </div>
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
