import api from '@/lib/api';
import type { Program } from '@/types';

export const programsService = {
    getAll: async () => {
        const response = await api.get<Program[]>('/programs/');
        return response.data;
    },
    create: async (name: string) => {
        const response = await api.post<Program>('/programs/', { name });
        return response.data;
    },
    delete: async (id: string) => {
        await api.delete(`/programs/${id}`);
    },
    addScope: async (programId: string, value: string, type: string) => {
        const response = await api.post(`/programs/${programId}/scopes/`, { value, scope_type: type });
        return response.data;
    },
    deleteScope: async (programId: string, scopeId: string) => {
        await api.delete(`/programs/${programId}/scopes/${scopeId}`);
    }
};
