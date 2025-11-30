import { Outlet } from 'react-router-dom';
import { Shield, LayoutDashboard, Database, Activity, Settings } from 'lucide-react';

export default function Layout() {
    return (
        <div className="flex h-screen bg-background">
            {/* Sidebar */}
            <aside className="w-64 border-r bg-card hidden md:flex flex-col">
                <div className="p-6 flex items-center gap-2 border-b">
                    <Shield className="h-6 w-6 text-primary" />
                    <span className="font-bold text-xl">EASM Platform</span>
                </div>

                <nav className="flex-1 p-4 space-y-2">
                    <a href="/" className="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md bg-primary/10 text-primary">
                        <LayoutDashboard className="h-4 w-4" />
                        Dashboard
                    </a>
                    <a href="/assets" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                        <Database className="h-4 w-4" />
                        Assets
                    </a>
                    <a href="/scans" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                        <Activity className="h-4 w-4" />
                        Scans
                    </a>
                    <a href="/settings" className="flex items-center gap-3 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground rounded-md transition-colors">
                        <Settings className="h-4 w-4" />
                        Settings
                    </a>
                </nav>

                <div className="p-4 border-t">
                    <div className="flex items-center gap-3">
                        <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center text-xs font-bold">
                            AD
                        </div>
                        <div className="text-sm">
                            <p className="font-medium">Admin User</p>
                            <p className="text-xs text-muted-foreground">admin@example.com</p>
                        </div>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 overflow-auto">
                <header className="h-16 border-b flex items-center px-6 bg-card/50 backdrop-blur-sm sticky top-0 z-10">
                    <h1 className="text-lg font-semibold">Dashboard</h1>
                </header>
                <div className="p-6">
                    <Outlet />
                </div>
            </main>
        </div>
    );
}
