import { useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import api from "@/lib/api";
import type { Program, ScanProfile } from "@/types";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Loader2, Search, Zap, BarChart3, ShieldCheck } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";

const SCAN_PROFILES: { value: ScanProfile; label: string; description: string; icon: typeof Search }[] = [
    { value: 'discovery', label: 'Discovery', description: 'Passive reconnaissance only', icon: Search },
    { value: 'quick_assessment', label: 'Quick Assessment', description: 'Fast scan with prioritized templates', icon: Zap },
    { value: 'standard_assessment', label: 'Standard Assessment', description: 'Balanced approach (recommended)', icon: BarChart3 },
    { value: 'full_audit', label: 'Full Audit', description: 'Comprehensive scan with all templates', icon: ShieldCheck },
];

const programSchema = z.object({
    name: z.string().min(2, "Name must be at least 2 characters"),
    default_scan_profile: z.enum(["discovery", "quick_assessment", "standard_assessment", "full_audit"]),
    custom_ports: z.string().optional(),
    nuclei_rate_limit: z.coerce.number().int().positive().optional().or(z.literal("")),
    nuclei_timeout: z.coerce.number().int().positive().optional().or(z.literal("")),
});

type ProgramFormValues = z.infer<typeof programSchema>;

interface EditProgramDialogProps {
    program: Program | null;
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function EditProgramDialog({ program, open, onOpenChange }: EditProgramDialogProps) {
    const { toast } = useToast();
    const queryClient = useQueryClient();
    const { register, handleSubmit, reset, setValue, watch, formState: { errors } } = useForm<ProgramFormValues>({
        resolver: zodResolver(programSchema),
        defaultValues: {
            name: "",
            default_scan_profile: "standard_assessment",
            custom_ports: "",
            nuclei_rate_limit: "",
            nuclei_timeout: "",
        }
    });

    const selectedProfile = watch("default_scan_profile");

    useEffect(() => {
        if (program) {
            reset({
                name: program.name,
                default_scan_profile: program.default_scan_profile || "standard_assessment",
                custom_ports: program.custom_ports || "",
                nuclei_rate_limit: program.nuclei_rate_limit || "",
                nuclei_timeout: program.nuclei_timeout || "",
            });
        }
    }, [program, reset]);

    const updateMutation = useMutation({
        mutationFn: async (data: ProgramFormValues) => {
            if (!program) return;
            await api.put(`/programs/${program.id}`, data);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['programs'] });
            toast({ title: "Success", description: "Program updated successfully." });
            onOpenChange(false);
        },
        onError: (error: any) => {
            toast({
                variant: "destructive",
                title: "Error",
                description: error.response?.data?.detail || "Failed to update program."
            });
        }
    });

    const onSubmit = (data: ProgramFormValues) => {
        // Clean up empty values before sending
        const cleanData = {
            ...data,
            custom_ports: data.custom_ports || null,
            nuclei_rate_limit: data.nuclei_rate_limit || null,
            nuclei_timeout: data.nuclei_timeout || null,
        };
        updateMutation.mutate(cleanData as ProgramFormValues);
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[550px]">
                <DialogHeader>
                    <DialogTitle>Edit Program</DialogTitle>
                    <DialogDescription>
                        Configure program settings and scan parameters.
                    </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleSubmit(onSubmit)} className="grid gap-4 py-4">
                    {/* Program Name */}
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="name" className="text-right">
                            Name
                        </Label>
                        <div className="col-span-3">
                            <Input
                                id="name"
                                {...register("name")}
                                className={errors.name ? "border-destructive" : ""}
                            />
                            {errors.name && <span className="text-xs text-destructive">{errors.name.message}</span>}
                        </div>
                    </div>

                    {/* Default Scan Profile */}
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label className="text-right">
                            Default Profile
                        </Label>
                        <div className="col-span-3">
                            <Select
                                value={selectedProfile}
                                onValueChange={(v) => setValue("default_scan_profile", v as ScanProfile)}
                            >
                                <SelectTrigger>
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    {SCAN_PROFILES.map(({ value, label, icon: Icon }) => (
                                        <SelectItem key={value} value={value}>
                                            <div className="flex items-center gap-2">
                                                <Icon className="h-4 w-4 text-muted-foreground" />
                                                <span>{label}</span>
                                            </div>
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                            <p className="text-xs text-muted-foreground mt-1">
                                {SCAN_PROFILES.find(p => p.value === selectedProfile)?.description}
                            </p>
                        </div>
                    </div>

                    {/* Custom Ports */}
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="custom_ports" className="text-right">
                            Custom Ports
                        </Label>
                        <div className="col-span-3">
                            <Input
                                id="custom_ports"
                                placeholder="80,443,8080-8090"
                                {...register("custom_ports")}
                            />
                            <p className="text-xs text-muted-foreground mt-1">
                                Leave empty to use default ports based on profile
                            </p>
                        </div>
                    </div>

                    {/* Nuclei Rate Limit */}
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="nuclei_rate_limit" className="text-right">
                            Rate Limit
                        </Label>
                        <div className="col-span-3">
                            <Input
                                id="nuclei_rate_limit"
                                type="number"
                                placeholder={selectedProfile === 'full_audit' ? '100' : '150'}
                                {...register("nuclei_rate_limit")}
                            />
                            <p className="text-xs text-muted-foreground mt-1">
                                Nuclei requests per second (leave empty for default)
                            </p>
                        </div>
                    </div>

                    {/* Nuclei Timeout */}
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="nuclei_timeout" className="text-right">
                            Timeout (s)
                        </Label>
                        <div className="col-span-3">
                            <Input
                                id="nuclei_timeout"
                                type="number"
                                placeholder={selectedProfile === 'full_audit' ? '10' : '5'}
                                {...register("nuclei_timeout")}
                            />
                            <p className="text-xs text-muted-foreground mt-1">
                                Per-request timeout in seconds (leave empty for default)
                            </p>
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
