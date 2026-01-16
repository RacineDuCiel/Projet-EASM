import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Layouts & Auth (eager loaded - needed immediately)
import Layout from '@/components/layout/Layout';
import ProtectedRoute from '@/components/auth/ProtectedRoute';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { useAuthStore } from '@/stores/auth-store';

// Login page - eager loaded for fast first paint
import LoginPage from '@/pages/auth/LoginPage';

// Lazy loaded pages - code splitting for better initial load
const DashboardPage = lazy(() => import('@/pages/dashboard/DashboardPage'));
const AssetsPage = lazy(() => import('@/pages/assets/AssetsPage'));
const AssetDetailsPage = lazy(() => import('@/pages/assets/AssetDetailsPage'));
const ScansPage = lazy(() => import('@/pages/ScansPage'));
const ScanDetailsPage = lazy(() => import('@/pages/ScanDetailsPage'));
const VulnerabilitiesPage = lazy(() => import('@/pages/vulns/VulnerabilitiesPage'));
const SettingsPage = lazy(() => import('@/pages/SettingsPage'));

// Admin pages - lazy loaded
const AdminDashboard = lazy(() => import('@/pages/admin/AdminDashboard'));
const AdminProgramsPage = lazy(() => import('@/pages/admin/AdminProgramsPage'));
const AdminUsersPage = lazy(() => import('@/pages/admin/AdminUsersPage'));

// Loading fallback component
const PageLoader = () => (
  <div className="flex items-center justify-center h-64">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
  </div>
);

// Optimized React Query client with caching
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30 * 1000,      // Data is fresh for 30 seconds
      gcTime: 5 * 60 * 1000,     // Cache garbage collection after 5 minutes
    },
  },
});

function App() {
  const user = useAuthStore((state) => state.user);

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Suspense fallback={<PageLoader />}>
            <Routes>
            {/* Public Routes */}
            <Route path="/login" element={<LoginPage />} />

            {/* Protected Routes */}
            <Route element={<ProtectedRoute />}>
              {user?.role === 'admin' ? (
                /* Admin Routes */
                <Route path="/" element={<Layout />}>
                  <Route index element={<Navigate to="/admin" replace />} />
                  <Route path="admin" element={<AdminDashboard />} />
                  <Route path="admin/programs" element={<AdminProgramsPage />} />
                  <Route path="admin/users" element={<AdminUsersPage />} />
                  <Route path="admin/scans" element={<ScansPage />} />
                  <Route path="admin/scans/:scanId" element={<ScanDetailsPage />} />
                  <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
                  <Route path="settings" element={<SettingsPage />} />
                </Route>
              ) : (
                /* Standard User Routes */
                <Route path="/" element={<Layout />}>
                  <Route index element={<DashboardPage />} />
                  <Route path="assets" element={<AssetsPage />} />
                  <Route path="assets/:assetId" element={<AssetDetailsPage />} />
                  <Route path="scans" element={<ScansPage />} />
                  <Route path="scans/:scanId" element={<ScanDetailsPage />} />
                  <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
                  <Route path="settings" element={<SettingsPage />} />
                </Route>
              )}
            </Route>

            {/* Catch-all */}
            <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
