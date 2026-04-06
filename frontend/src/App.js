import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import RoleRoute from './components/RoleRoute';
import Navigation from './components/Navigation';
import Login from './pages/Login';
import Scanner from './pages/Scanner';
import History from './pages/History';
import Dashboard from './pages/Dashboard';
import ScanDetails from './pages/ScanDetails';
import RemediationQueue from './pages/RemediationQueue';
import Analytics from './pages/Analytics';
import ChainExplorer from './pages/ChainExplorer';
import ClientPortal from './pages/ClientPortal';
import AdminDashboard from './pages/admin/AdminDashboard';
import Users from './pages/admin/Users';
import Assets from './pages/admin/Assets';
import AuditLogs from './pages/admin/AuditLogs';
import Settings from './pages/admin/Settings';
import './App.css';

// Root gate redirector
const RootRedirector = () => {
  const { user, loading } = useAuth();

  if (loading) return null;

  if (!user) return <Navigate to="/login" replace />;
  const role = user.role || 'User';

  if (role === 'Admin') return <Navigate to="/dashboard/admin" replace />;
  if (role === 'Analyst') return <Navigate to="/dashboard/analyst" replace />;
  return <Navigate to="/dashboard/user" replace />;
};

// Layout for authenticated pages — navigation sidebar + routed content area
const AppLayout = () => (
  <div style={{ display: 'flex' }}>
    <Navigation />
    <main className="sg-main">
      <Outlet />
    </main>
  </div>
);

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* Public */}
          <Route path="/login" element={<Login />} />

          {/* Protected — auth gate first, then layout, then pages */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route index element={<RootRedirector />} />

              {/* Role-Specific Dashboards */}
              <Route element={<RoleRoute allowedRoles={['Admin']} />}>
                <Route path="dashboard/admin" element={<AdminDashboard />} />
                <Route path="admin/users" element={<Users />} />
                <Route path="admin/assets" element={<Assets />} />
                <Route path="admin/audit-logs" element={<AuditLogs />} />
                <Route path="admin/settings" element={<Settings />} />
              </Route>

              <Route element={<RoleRoute allowedRoles={['Analyst']} />}>
                <Route path="dashboard/analyst" element={<Dashboard type="analyst" />} />
              </Route>

              <Route element={<RoleRoute allowedRoles={['User']} />}>
                <Route path="dashboard/user" element={<Dashboard type="user" />} />
              </Route>

              {/* Shared Protected Features */}
              <Route path="scan" element={<Scanner />} />
              <Route path="history" element={<History />} />
              <Route path="scan/:id" element={<ScanDetails />} />
              <Route path="remediation" element={<RemediationQueue />} />
              <Route path="analytics" element={<Analytics />} />
              <Route path="chains/:id" element={<ChainExplorer />} />
              <Route path="portal" element={<ClientPortal />} />

              <Route path="*" element={<RootRedirector />} />

            </Route>
          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;