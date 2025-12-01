import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Layouts & Auth
import Layout from '@/components/layout/Layout';
import ProtectedRoute from '@/components/auth/ProtectedRoute';
import { useAuthStore } from '@/stores/auth-store';

// Pages - Auth
import LoginPage from '@/pages/auth/LoginPage';

// Pages - Dashboard & Core
import DashboardPage from '@/pages/dashboard/DashboardPage';
import AssetsPage from '@/pages/assets/AssetsPage';
import AssetDetailsPage from '@/pages/assets/AssetDetailsPage';
import ScansPage from '@/pages/ScansPage';
import ScanDetailsPage from '@/pages/ScanDetailsPage';
import VulnerabilitiesPage from '@/pages/vulns/VulnerabilitiesPage';
import SettingsPage from '@/pages/SettingsPage';

// Pages - Admin
import AdminDashboard from '@/pages/admin/AdminDashboard';
import AdminProgramsPage from '@/pages/admin/AdminProgramsPage';
import AdminUsersPage from '@/pages/admin/AdminUsersPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  const user = useAuthStore((state) => state.user);

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
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
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
