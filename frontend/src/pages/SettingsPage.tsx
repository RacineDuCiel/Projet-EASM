import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import type { Program } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Bell, Save, Loader2, Send } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';

export default function SettingsPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [webhookUrl, setWebhookUrl] = useState('');

    // Fetch Settings (Program)
    const { data: program, isLoading } = useQuery({
        queryKey: ['settings'],
        queryFn: async () => {
            const response = await api.get<Program>('/settings/');
            return response.data;
        },
    });

    // Update Settings Mutation
    const updateSettingsMutation = useMutation({
        mutationFn: async (url: string) => {
            await api.patch('/settings/', {
                discord_webhook_url: url
            });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['settings'] });
            toast({
                title: "Settings saved",
                description: "Your notification settings have been updated.",
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

    // Initialize state when data loads
    if (program && webhookUrl === '' && program.discord_webhook_url) {
        setWebhookUrl(program.discord_webhook_url);
    }

    const handleSave = () => {
        updateSettingsMutation.mutate(webhookUrl);
    };

    if (isLoading) {
        return <div className="flex justify-center p-8"><Loader2 className="h-8 w-8 animate-spin" /></div>;
    }

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Settings</h2>
                <p className="text-muted-foreground">
                    Manage your program configuration and notifications.
                </p>
            </div>

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
                            value={webhookUrl || (program?.discord_webhook_url || '')}
                            onChange={(e) => setWebhookUrl(e.target.value)}
                        />
                        <p className="text-sm text-muted-foreground">
                            Paste your Discord Webhook URL here to receive real-time alerts.
                        </p>
                    </div>
                </CardContent>
                <CardFooter className="flex justify-between">
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
                    <Button onClick={handleSave} disabled={updateSettingsMutation.isPending}>
                        {updateSettingsMutation.isPending ? (
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        ) : (
                            <Save className="mr-2 h-4 w-4" />
                        )}
                        Save Changes
                    </Button>
                </CardFooter>
            </Card>
        </div>
    );
}
