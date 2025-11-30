import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import api from '@/lib/api';

interface User {
    id: string;
    email: string;
    role: string;
}

interface LoginResponse {
    access_token: string;
    token_type: string;
}

interface AuthState {
    token: string | null;
    user: User | null;
    isAuthenticated: boolean;
    setToken: (token: string) => void;
    setUser: (user: User) => void;
    login: (username: string, password: string) => Promise<void>;
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
            login: async (username, password) => {
                const params = new URLSearchParams();
                params.append('username', username);
                params.append('password', password);

                const response = await api.post<LoginResponse>('/auth/token', params, {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                });

                const { access_token } = response.data;
                set({ token: access_token, isAuthenticated: true, user: { id: '1', email: username, role: 'admin' } }); // Mock user for now
            },
            logout: () => set({ token: null, user: null, isAuthenticated: false }),
        }),
        {
            name: 'auth-storage',
        }
    )
);
