import axios from 'axios';

// Create an Axios instance
const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1',
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

import { useAuthStore } from '@/stores/auth-store';

// Request interceptor for adding auth token
api.interceptors.request.use(
    (config) => {
        const token = useAuthStore.getState().token;
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
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            // Clear token and redirect to login if needed
            useAuthStore.getState().logout();
            // window.location.href = '/login'; // Uncomment when routing is ready
        }
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
