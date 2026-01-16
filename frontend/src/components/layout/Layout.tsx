import { useState } from 'react';
import { Outlet, useNavigate, Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Database, Activity, Settings, LogOut, Users, ShieldAlert, Menu, X } from 'lucide-react';
import { useAuthStore } from '@/stores/auth-store';
import { Button } from '@/components/ui/button';
import { Toaster } from '@/components/ui/toaster';

export default function Layout() {
    const { user, logout } = useAuthStore();
    const navigate = useNavigate();
    const location = useLocation();
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    const closeMobileMenu = () => {
        setMobileMenuOpen(false);
    };

    const NavLinks = () => (
        <>
            {user?.role === 'admin' ? (
                <>
                    <Link
                        to="/admin"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname === '/admin' ? 'bg-accent' : ''}`}
                    >
                        <LayoutDashboard className="h-4 w-4" />
                        Admin Console
                    </Link>
                    <Link
                        to="/admin/programs"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname === '/admin/programs' ? 'bg-accent' : ''}`}
                    >
                        <Shield className="h-4 w-4" />
                        Programs
                    </Link>
                    <Link
                        to="/admin/users"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname === '/admin/users' ? 'bg-accent' : ''}`}
                    >
                        <Users className="h-4 w-4" />
                        Users
                    </Link>
                    <Link
                        to="/admin/scans"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname.startsWith('/admin/scans') ? 'bg-accent' : ''}`}
                    >
                        <Activity className="h-4 w-4" />
                        Scans
                    </Link>
                    <Link
                        to="/settings"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname === '/settings' ? 'bg-accent' : ''}`}
                    >
                        <Settings className="h-4 w-4" />
                        Settings
                    </Link>
                </>
            ) : (
                <>
                    <Link
                        to="/"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname === '/' ? 'bg-accent' : ''}`}
                    >
                        <LayoutDashboard className="h-4 w-4" />
                        Dashboard
                    </Link>
                    <Link
                        to="/assets"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname.startsWith('/assets') ? 'bg-accent' : ''}`}
                    >
                        <Database className="h-4 w-4" />
                        Assets
                    </Link>
                    <Link
                        to="/scans"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname.startsWith('/scans') ? 'bg-accent' : ''}`}
                    >
                        <Activity className="h-4 w-4" />
                        Scans
                    </Link>
                    <Link
                        to="/vulnerabilities"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname === '/vulnerabilities' ? 'bg-accent' : ''}`}
                    >
                        <ShieldAlert className="h-4 w-4" />
                        Vulnerabilities
                    </Link>
                    <Link
                        to="/settings"
                        onClick={closeMobileMenu}
                        className={`flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors ${location.pathname === '/settings' ? 'bg-accent' : ''}`}
                    >
                        <Settings className="h-4 w-4" />
                        Settings
                    </Link>
                </>
            )}
        </>
    );

    const UserInfo = () => (
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
    );

    return (
        <div className="flex h-screen bg-background">
            {/* Mobile menu backdrop */}
            {mobileMenuOpen && (
                <div
                    className="fixed inset-0 bg-black/50 z-40 md:hidden"
                    onClick={closeMobileMenu}
                    aria-hidden="true"
                />
            )}

            {/* Sidebar - Desktop */}
            <aside className="w-64 border-r bg-card hidden md:flex flex-col" role="navigation" aria-label="Main navigation">
                <div className="p-6 flex items-center gap-2 border-b">
                    <Shield className="h-6 w-6 text-primary" />
                    <span className="font-bold text-xl">EASM Platform</span>
                </div>

                <nav className="flex-1 p-4 space-y-2">
                    <NavLinks />
                </nav>

                <UserInfo />
            </aside>

            {/* Sidebar - Mobile */}
            <aside
                className={`fixed inset-y-0 left-0 w-64 border-r bg-card flex flex-col z-50 transform transition-transform duration-200 ease-in-out md:hidden ${
                    mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
                }`}
                role="navigation"
                aria-label="Mobile navigation"
            >
                <div className="p-6 flex items-center justify-between border-b">
                    <div className="flex items-center gap-2">
                        <Shield className="h-6 w-6 text-primary" />
                        <span className="font-bold text-xl">EASM</span>
                    </div>
                    <Button
                        variant="ghost"
                        size="icon"
                        onClick={closeMobileMenu}
                        aria-label="Close menu"
                    >
                        <X className="h-5 w-5" />
                    </Button>
                </div>

                <nav className="flex-1 p-4 space-y-2">
                    <NavLinks />
                </nav>

                <UserInfo />
            </aside>

            {/* Main Content */}
            <main className="flex-1 overflow-auto">
                <header className="h-16 border-b flex items-center px-4 md:px-6 bg-card/50 backdrop-blur-sm sticky top-0 z-10 justify-between">
                    {/* Mobile menu button */}
                    <Button
                        variant="ghost"
                        size="icon"
                        className="md:hidden"
                        onClick={() => setMobileMenuOpen(true)}
                        aria-label="Open menu"
                    >
                        <Menu className="h-5 w-5" />
                    </Button>
                    <h1 className="text-lg font-semibold capitalize">
                        {user?.role === 'admin' ? 'Administration' : 'Dashboard'}
                    </h1>
                    {/* Spacer for mobile to center title */}
                    <div className="w-10 md:hidden" />
                </header>
                <div className="p-4 md:p-6">
                    <Outlet />
                </div>
            </main>
            <Toaster />
        </div>
    );
}
