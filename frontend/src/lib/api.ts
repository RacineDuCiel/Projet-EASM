import axios from 'axios';
import type { AxiosError, InternalAxiosRequestConfig } from 'axios';

// Create an Axios instance
const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || `http://${window.location.hostname}:8000/api/v1`,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Lazy import to break circular dependency (api <-> auth-store)
const getAuthStore = () => import('@/stores/auth-store').then(m => m.useAuthStore);
let _authStore: Awaited<ReturnType<typeof getAuthStore>> | null = null;

async function authStore() {
    if (!_authStore) {
        _authStore = await getAuthStore();
    }
    return _authStore;
}

// Track whether a token refresh is in progress to avoid concurrent refreshes
let isRefreshing = false;
let failedQueue: Array<{
    resolve: (value: unknown) => void;
    reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: unknown, token: string | null = null) => {
    failedQueue.forEach((prom) => {
        if (error) {
            prom.reject(error);
        } else {
            prom.resolve(token);
        }
    });
    failedQueue = [];
};

// Request interceptor for adding auth token
api.interceptors.request.use(
    async (config) => {
        const store = await authStore();
        const token = store.getState().token;
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Response interceptor for handling errors (e.g., 401 Unauthorized)
// Implements automatic token refresh before logging out
api.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
        const store = await authStore();

        // Only attempt refresh on 401 errors, not on auth endpoints themselves
        if (
            error.response?.status === 401 &&
            originalRequest &&
            !originalRequest._retry &&
            !originalRequest.url?.includes('/auth/token') &&
            !originalRequest.url?.includes('/auth/refresh')
        ) {
            if (isRefreshing) {
                // If a refresh is already in progress, queue this request
                return new Promise((resolve, reject) => {
                    failedQueue.push({ resolve, reject });
                }).then((token) => {
                    originalRequest.headers.Authorization = `Bearer ${token}`;
                    return api(originalRequest);
                }).catch((err) => {
                    return Promise.reject(err);
                });
            }

            originalRequest._retry = true;
            isRefreshing = true;

            const refreshToken = store.getState().refreshToken;

            if (!refreshToken) {
                // No refresh token available, log out immediately
                isRefreshing = false;
                processQueue(error, null);
                store.getState().logout();
                return Promise.reject(error);
            }

            try {
                // Attempt to refresh the access token
                const response = await axios.post(
                    `${api.defaults.baseURL}/auth/refresh`,
                    {},
                    {
                        headers: {
                            Authorization: `Bearer ${refreshToken}`,
                            'Content-Type': 'application/json',
                        },
                        timeout: 10000,
                    }
                );

                const { access_token } = response.data;

                // Update the stored access token
                store.getState().setToken(access_token);

                // Process the queued requests with the new token
                processQueue(null, access_token);

                // Retry the original request with the new token
                originalRequest.headers.Authorization = `Bearer ${access_token}`;
                return api(originalRequest);
            } catch (refreshError) {
                // Refresh failed -- log out
                processQueue(refreshError, null);
                store.getState().logout();
                return Promise.reject(refreshError);
            } finally {
                isRefreshing = false;
            }
        }

        // For non-401 errors, or if already retried, just reject
        return Promise.reject(error);
    }
);

// Security Posture API methods
export const securityApi = {
    // Compliance
    analyzeCompliance: (data: any) =>
        api.post('/security/compliance/analyze', data),

    getComplianceFrameworks: () =>
        api.get('/security/compliance/frameworks'),

    generateReport: (data: any) =>
        api.post('/security/compliance/report', data),
};

export default api;
