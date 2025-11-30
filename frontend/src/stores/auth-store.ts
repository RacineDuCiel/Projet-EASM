import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import api from '@/lib/api';

export interface User {
    id: string;
    username: string;
    role: 'admin' | 'user';
    program_id?: string | null;
    is_active: boolean;
}

interface LoginResponse {
    access_token: string;
    token_type: string;
    user: User;
}

interface AuthState {
    token: string | null;
    user: User | null;
    isAuthenticated: boolean;
    setToken: (token: string | null) => void;
    setUser: (user: User | null) => void;
    login: (params: { username: string; password: string }) => Promise<void>;
    logout: () => void;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set) => ({
            token: null,
            user: null,
            isAuthenticated: false,
            setToken: (token) => set({ token, isAuthenticated: !!token }),
            setUser: (user) => set({ user }),
            login: async ({ username, password }) => {
                try {
                    const params = new URLSearchParams();
                    params.append('username', username);
                    params.append('password', password);

                    const response = await api.post<LoginResponse>('/auth/token', params, {
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                    });

                    const { access_token, user } = response.data;
                    set({ token: access_token, isAuthenticated: true, user: user });
                } catch (error) {
                    console.error('Login failed:', error);
                    throw error;
                }
            },
            logout: () => set({ token: null, user: null, isAuthenticated: false }),
        }),
        {
            name: 'auth-storage',
        }
    )
);
