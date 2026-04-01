import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = () => {
    const { token, loading } = useAuth();

    if (loading) {
        return (
            <div className="sg-loading" style={{ height: '100vh' }}>
                <div className="sg-spinner" />
                <span>Loading…</span>
            </div>
        );
    }

    return token ? <Outlet /> : <Navigate to="/login" replace />;
};

export default ProtectedRoute;
