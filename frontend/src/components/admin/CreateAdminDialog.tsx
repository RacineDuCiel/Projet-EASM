import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import api from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, ShieldAlert } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const adminSchema = z.object({
    username: z.string().min(3, "Username must be at least 3 characters"),
    password: z.string().min(8, "Password must be at least 8 characters"),
    current_password: z.string().min(1, "Current password is required"),
});

type AdminFormValues = z.infer<typeof adminSchema>;

interface CreateAdminDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function CreateAdminDialog({ open, onOpenChange }: CreateAdminDialogProps) {
    const { toast } = useToast();
    const queryClient = useQueryClient();
    const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<AdminFormValues>({
        resolver: zodResolver(adminSchema),
    });

    const createMutation = useMutation({
        mutationFn: async (data: AdminFormValues) => {
            await api.post('/auth/users/', {
                ...data,
                role: 'admin',
                program_id: null
            });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
            toast({ title: "Success", description: "Administrator created successfully." });
            reset();
            onOpenChange(false);
        },
        onError: (error: any) => {
            toast({
                variant: "destructive",
                title: "Error",
                description: error.response?.data?.detail || "Failed to create administrator."
            });
        }
    });

    const onSubmit = (data: AdminFormValues) => {
        createMutation.mutate(data);
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle>Create Administrator</DialogTitle>
                    <DialogDescription>
                        Create a new user with full administrative privileges.
                    </DialogDescription>
                </DialogHeader>

                <Alert variant="destructive">
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Security Check</AlertTitle>
                    <AlertDescription>
                        You must enter your <strong>current password</strong> to verify your identity.
                    </AlertDescription>
                </Alert>

                <form onSubmit={handleSubmit(onSubmit)} className="grid gap-4 py-4">
                    <div className="grid gap-2">
                        <Label htmlFor="username">New Admin Username</Label>
                        <Input
                            id="username"
                            {...register("username")}
                            className={errors.username ? "border-destructive" : ""}
                        />
                        {errors.username && <span className="text-xs text-destructive">{errors.username.message}</span>}
                    </div>

                    <div className="grid gap-2">
                        <Label htmlFor="password">New Admin Password</Label>
                        <Input
                            id="password"
                            type="password"
                            {...register("password")}
                            className={errors.password ? "border-destructive" : ""}
                        />
                        {errors.password && <span className="text-xs text-destructive">{errors.password.message}</span>}
                    </div>

                    <div className="grid gap-2">
                        <Label htmlFor="current_password">Your Current Password</Label>
                        <Input
                            id="current_password"
                            type="password"
                            placeholder="Verify your identity"
                            {...register("current_password")}
                            className={errors.current_password ? "border-destructive" : ""}
                        />
                        {errors.current_password && <span className="text-xs text-destructive">{errors.current_password.message}</span>}
                    </div>

                    <DialogFooter>
                        <Button type="submit" disabled={createMutation.isPending} variant="destructive">
                            {createMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Create Administrator
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
}
