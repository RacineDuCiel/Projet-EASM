import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from '@/components/layout/Layout';
import LoginPage from '@/pages/auth/LoginPage';
import ProtectedRoute from '@/components/auth/ProtectedRoute';
import { useAuthStore } from '@/stores/auth-store';

import DashboardPage from '@/pages/dashboard/DashboardPage';
import AssetsPage from '@/pages/assets/AssetsPage';
import AdminDashboard from '@/pages/admin/AdminDashboard';

// Placeholder pages
const Scans = () => <div><h2 className="text-2xl font-bold mb-4">Scans</h2><p className="text-muted-foreground">Launch and monitor security scans.</p></div>;
const Settings = () => <div><h2 className="text-2xl font-bold mb-4">Settings</h2><p className="text-muted-foreground">Configure platform settings.</p></div>;

const queryClient = new QueryClient();

function App() {
  const user = useAuthStore((state) => state.user);

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          {/* Admin Routes */}
          <Route element={<ProtectedRoute />}>
            {user?.role === 'admin' ? (
              <Route path="/" element={<Layout />}>
                <Route index element={<Navigate to="/admin" replace />} />
                <Route path="admin" element={<AdminDashboard />} />
                <Route path="settings" element={<Settings />} />
              </Route>
            ) : (
              /* User Routes */
              <Route path="/" element={<Layout />}>
                <Route index element={<DashboardPage />} />
                <Route path="assets" element={<AssetsPage />} />
                <Route path="scans" element={<Scans />} />
                <Route path="settings" element={<Settings />} />
              </Route>
            )}
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
