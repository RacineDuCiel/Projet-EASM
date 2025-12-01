import { Outlet, useNavigate, Link } from 'react-router-dom';
import { Shield, LayoutDashboard, Database, Activity, Settings, LogOut, Users, ShieldAlert } from 'lucide-react';
import { useAuthStore } from '@/stores/auth-store';
import { Button } from '@/components/ui/button';
import { Toaster } from '@/components/ui/toaster';

export default function Layout() {
    const { user, logout } = useAuthStore();
    const navigate = useNavigate();

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    return (
        <div className="flex h-screen bg-background">
            {/* Sidebar */}
            <aside className="w-64 border-r bg-card hidden md:flex flex-col">
                <div className="p-6 flex items-center gap-2 border-b">
                    <Shield className="h-6 w-6 text-primary" />
                    <span className="font-bold text-xl">EASM Platform</span>
                </div>

                <nav className="flex-1 p-4 space-y-2">
                    {user?.role === 'admin' ? (
                        <>
                            <Link to="/admin" className="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors">
                                <LayoutDashboard className="h-4 w-4" />
                                Admin Console
                            </Link>
                            <Link to="/admin/programs" className="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors">
                                <Shield className="h-4 w-4" />
                                Programs
                            </Link>
                            <Link to="/admin/users" className="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors">
                                <Users className="h-4 w-4" />
                                Users
                            </Link>
                            <Link to="/admin/scans" className="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors">
                                <Activity className="h-4 w-4" />
                                Scans
                            </Link>
                            <Link to="/settings" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                                <Settings className="h-4 w-4" />
                                Settings
                            </Link>
                        </>
                    ) : (
                        <>
                            <Link to="/" className="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors">
                                <LayoutDashboard className="h-4 w-4" />
                                Dashboard
                            </Link>
                            <Link to="/assets" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                                <Database className="h-4 w-4" />
                                Assets
                            </Link>
                            <Link to="/scans" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                                <Activity className="h-4 w-4" />
                                Scans
                            </Link>
                            <Link to="/vulnerabilities" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                                <ShieldAlert className="h-4 w-4" />
                                Vulnerabilities
                            </Link>
                            <Link to="/settings" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                                <Settings className="h-4 w-4" />
                                Settings
                            </Link>
                        </>
                    )}
                </nav>

                <div className="p-4 border-t space-y-4">
                    <div className="flex items-center gap-3">
                        <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center text-xs font-bold uppercase">
                            {user?.username?.substring(0, 2) || 'US'}
                        </div>
                        <div className="text-sm overflow-hidden">
                            <p className="font-medium truncate">{user?.username || 'User'}</p>
                            <p className="text-xs text-muted-foreground capitalize">{user?.role || 'Role'}</p>
                        </div>
                    </div>
                    <Button variant="outline" className="w-full justify-start gap-2" onClick={handleLogout}>
                        <LogOut className="h-4 w-4" />
                        Logout
                    </Button>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 overflow-auto">
                <header className="h-16 border-b flex items-center px-6 bg-card/50 backdrop-blur-sm sticky top-0 z-10 justify-between">
                    <h1 className="text-lg font-semibold capitalize">
                        {user?.role === 'admin' ? 'Administration' : 'Dashboard'}
                    </h1>
                </header>
                <div className="p-6">
                    <Outlet />
                </div>
            </main>
            <Toaster />
        </div>
    );
}
