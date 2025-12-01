import { useState, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import api from "@/lib/api";
import type { User, Program } from "@/types";
import { Button } from "@/components/ui/button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2 } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";

const userSchema = z.object({
    username: z.string().min(3, "Username must be at least 3 characters"),
    password: z.string().optional(), // Optional for update
    role: z.enum(["admin", "user"]),
    program_id: z.string().optional().nullable(),
    is_active: z.boolean(),
});

type UserFormValues = z.infer<typeof userSchema>;

interface EditUserDialogProps {
    user: User | null;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    programs: Program[];
}

export function EditUserDialog({ user, open, onOpenChange, programs }: EditUserDialogProps) {
    const { toast } = useToast();
    const queryClient = useQueryClient();
    const { register, handleSubmit, reset, setValue, watch, formState: { errors, isSubmitting } } = useForm<UserFormValues>({
        resolver: zodResolver(userSchema),
        defaultValues: {
            username: "",
            role: "user",
            program_id: "",
            is_active: true,
        }
    });

    const role = watch("role");

    useEffect(() => {
        if (user) {
            reset({
                username: user.username,
                role: user.role,
                program_id: user.program_id || "",
                is_active: user.is_active,
            });
        }
    }, [user, reset]);

    const updateMutation = useMutation({
        mutationFn: async (data: UserFormValues) => {
            if (!user) return;
            // Clean up data
            const payload: any = { ...data };
            if (!payload.password) delete payload.password;
            if (payload.role === 'admin') payload.program_id = null;
            if (payload.program_id === "") payload.program_id = null;

            await api.put(`/auth/users/${user.id}`, payload);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
            toast({ title: "Success", description: "User updated successfully." });
            onOpenChange(false);
        },
        onError: (error: any) => {
            toast({
                variant: "destructive",
                title: "Error",
                description: error.response?.data?.detail || "Failed to update user."
            });
        }
    });

    const onSubmit = (data: UserFormValues) => {
        updateMutation.mutate(data);
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle>Edit User</DialogTitle>
                    <DialogDescription>
                        Make changes to the user profile here.
                    </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleSubmit(onSubmit)} className="grid gap-4 py-4">
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="username" className="text-right">
                            Username
                        </Label>
                        <div className="col-span-3">
                            <Input
                                id="username"
                                {...register("username")}
                                className={errors.username ? "border-destructive" : ""}
                            />
                            {errors.username && <span className="text-xs text-destructive">{errors.username.message}</span>}
                        </div>
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="password" className="text-right">
                            Password
                        </Label>
                        <div className="col-span-3">
                            <Input
                                id="password"
                                type="password"
                                placeholder="(Leave blank to keep current)"
                                {...register("password")}
                            />
                        </div>
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="role" className="text-right">
                            Role
                        </Label>
                        <div className="col-span-3">
                            <Select
                                value={role}
                                onValueChange={(val) => setValue("role", val as "admin" | "user")}
                            >
                                <SelectTrigger>
                                    <SelectValue placeholder="Select role" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="user">User</SelectItem>
                                    <SelectItem value="admin">Admin</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="program" className="text-right">
                            Program
                        </Label>
                        <div className="col-span-3">
                            <Select
                                value={watch("program_id") || ""}
                                onValueChange={(val) => setValue("program_id", val === "none" ? null : val)}
                                disabled={role === 'admin'}
                            >
                                <SelectTrigger>
                                    <SelectValue placeholder="Select program" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="none">None</SelectItem>
                                    {programs.map((p) => (
                                        <SelectItem key={p.id} value={p.id}>
                                            {p.name}
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="active" className="text-right">
                            Status
                        </Label>
                        <div className="col-span-3 flex items-center gap-2">
                            <Button
                                type="button"
                                variant={watch("is_active") ? "default" : "destructive"}
                                size="sm"
                                onClick={() => setValue("is_active", !watch("is_active"))}
                            >
                                {watch("is_active") ? "Active" : "Inactive"}
                            </Button>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button type="submit" disabled={updateMutation.isPending}>
                            {updateMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Save changes
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
}
