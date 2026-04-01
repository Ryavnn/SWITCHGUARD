import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const RoleRoute = ({ allowedRoles }) => {
    const { user, loading } = useAuth();

    if (loading) {
        return (
            <div className="sg-loading">
                <div className="sg-spinner"></div>
                <span>Checking permissions...</span>
            </div>
        );
    }

    if (!user) {
        return <Navigate to="/login" replace />;
    }

    // Default to 'User' if no role specific exists in the object payload
    const userRole = user?.role || 'User';

    if (!allowedRoles.includes(userRole)) {
        // Redirect unauthorized access to the user's correct dashboard
        const dashboardPath = userRole === 'Admin' ? '/dashboard/admin' : 
                              userRole === 'Analyst' ? '/dashboard/analyst' : '/dashboard/user';
        return <Navigate to={dashboardPath} replace />;
    }

    return <Outlet />;
};

export default RoleRoute;
