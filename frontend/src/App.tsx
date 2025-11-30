import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from '@/lib/react-query';
import Layout from '@/components/layout/Layout';
import LoginPage from '@/pages/auth/LoginPage';
import ProtectedRoute from '@/components/auth/ProtectedRoute';

// Placeholder pages
const Dashboard = () => <div><h2 className="text-2xl font-bold mb-4">Overview</h2><p className="text-muted-foreground">Welcome to your EASM Dashboard.</p></div>;
const Assets = () => <div><h2 className="text-2xl font-bold mb-4">Assets</h2><p className="text-muted-foreground">Manage your infrastructure assets here.</p></div>;
const Scans = () => <div><h2 className="text-2xl font-bold mb-4">Scans</h2><p className="text-muted-foreground">Launch and monitor security scans.</p></div>;
const Settings = () => <div><h2 className="text-2xl font-bold mb-4">Settings</h2><p className="text-muted-foreground">Configure platform settings.</p></div>;

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="assets" element={<Assets />} />
              <Route path="scans" element={<Scans />} />
              <Route path="settings" element={<Settings />} />
            </Route>
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
