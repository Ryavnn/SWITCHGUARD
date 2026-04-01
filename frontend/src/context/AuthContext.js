import React, { createContext, useContext, useState, useEffect } from 'react';
import authService from '../services/authService';
import api from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
    const [user, setUser]       = useState(null);
    const [token, setToken]     = useState(null);
    const [loading, setLoading] = useState(true);

    // Restore session from authService on mount
    useEffect(() => {
        const savedToken = authService.getToken();
        const savedUser  = authService.getCurrentUser();

        if (savedToken && savedUser) {
            setToken(savedToken);
            setUser(savedUser);
            // Bearer header handled by interceptor in services/api.js automatically
        } else {
            authService.logout();
        }
        setLoading(false);
    }, []);

    const login = async (email, password) => {
        const data = await authService.login(email, password);
        setToken(data.access_token);
        setUser(data.user);
    };

    const register = async (name, email, password) => {
        const data = await authService.register(name, email, password);
        setToken(data.access_token);
        setUser(data.user);
    };

    const logout = () => {
        authService.logout();
        setToken(null);
        setUser(null);
        // Interceptor handles header removal on reload or next call context
    };

    return (
        <AuthContext.Provider value={{ user, token, loading, login, register, logout }}>
            {children}
        </AuthContext.Provider>
    );
}

export const useAuth = () => useContext(AuthContext);
