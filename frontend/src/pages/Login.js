import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Login = () => {
    const [tab, setTab] = useState('login'); // 'login' | 'signup'
    const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' });
    const [errors, setErrors] = useState({});
    const [serverErr, setServerErr] = useState('');
    const [loading, setLoading] = useState(false);

    const { login, register } = useAuth();
    const navigate = useNavigate();

    const switchTab = (t) => {
        setTab(t);
        setErrors({});
        setServerErr('');
    };

    const set = (field) => (e) => {
        setForm((f) => ({ ...f, [field]: e.target.value }));
        setErrors((er) => ({ ...er, [field]: '' }));
        setServerErr('');
    };

    const validate = () => {
        const errs = {};
        if (tab === 'signup' && !form.name.trim()) errs.name = 'Full name is required';
        if (!form.email.trim()) errs.email = 'Email is required';
        else if (!/\S+@\S+\.\S+/.test(form.email)) errs.email = 'Enter a valid email';
        if (!form.password) errs.password = 'Password is required';
        else if (form.password.length < 6) errs.password = 'Minimum 6 characters';
        if (tab === 'signup' && form.password !== form.confirm)
            errs.confirm = 'Passwords do not match';
        return errs;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const errs = validate();
        if (Object.keys(errs).length) { setErrors(errs); return; }

        setLoading(true);
        setServerErr('');
        try {
            if (tab === 'login') {
                await login(form.email, form.password);
            } else {
                await register(form.name, form.email, form.password);
            }
            navigate('/');
        } catch (err) {
            setServerErr(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="auth-page">
            {/* Left brand panel */}
            <div className="auth-brand">
                <div className="auth-brand-inner">
                    <div className="auth-brand-logo">
                        Switch<span>Guard</span>
                    </div>
                    <div className="auth-brand-tagline">
                        Enterprise-Grade Network &amp;<br />Web Security Platform
                    </div>
                    <div className="auth-features">
                        {[
                            { icon: '🛡️', label: 'Real-time threat detection' },
                            { icon: '🌐', label: 'Deep web vulnerability scanning' },
                            { icon: '📊', label: 'Comprehensive audit reports' },
                            { icon: '🔒', label: 'Zero-trust security model' },
                        ].map(({ icon, label }) => (
                            <div className="auth-feature-item" key={label}>
                                <span className="auth-feature-icon">{icon}</span>
                                <span>{label}</span>
                            </div>
                        ))}
                    </div>
                </div>
                {/* Decorative orbs */}
                <div className="auth-orb auth-orb-1" />
                <div className="auth-orb auth-orb-2" />
            </div>

            {/* Right form panel */}
            <div className="auth-form-panel">
                <div className="auth-card">
                    {/* Tab bar */}
                    <div className="auth-tabs">
                        <button
                            className={`auth-tab ${tab === 'login' ? 'active' : ''}`}
                            onClick={() => switchTab('login')}
                            type="button"
                        >
                            Sign In
                        </button>
                        <button
                            className={`auth-tab ${tab === 'signup' ? 'active' : ''}`}
                            onClick={() => switchTab('signup')}
                            type="button"
                        >
                            Create Account
                        </button>
                        <div className={`auth-tab-indicator ${tab === 'signup' ? 'right' : 'left'}`} />
                    </div>

                    <div className="auth-card-body">
                        <h1 className="auth-title">
                            {tab === 'login' ? 'Welcome back' : 'Get started today'}
                        </h1>
                        <p className="auth-subtitle">
                            {tab === 'login'
                                ? 'Sign in to your SwitchGuard account'
                                : 'Create your free SwitchGuard account'}
                        </p>

                        {serverErr && (
                            <div className="auth-server-error">
                                <span>⚠</span> {serverErr}
                            </div>
                        )}

                        <form onSubmit={handleSubmit} noValidate>
                            {/* Name (sign up only) */}
                            <div
                                className={`auth-field-wrap ${tab === 'signup' ? 'visible' : 'hidden'}`}
                                aria-hidden={tab !== 'signup'}
                            >
                                <div className="sg-form-group">
                                    <label className="sg-label" htmlFor="auth-name">Full Name</label>
                                    <input
                                        id="auth-name"
                                        className={`sg-input auth-input ${errors.name ? 'input-error' : ''}`}
                                        type="text"
                                        placeholder="Jane Smith"
                                        value={form.name}
                                        onChange={set('name')}
                                        autoComplete="name"
                                        tabIndex={tab === 'signup' ? 0 : -1}
                                    />
                                    {errors.name && <span className="auth-field-error">{errors.name}</span>}
                                </div>
                            </div>

                            {/* Email */}
                            <div className="sg-form-group">
                                <label className="sg-label" htmlFor="auth-email">Email Address</label>
                                <input
                                    id="auth-email"
                                    className={`sg-input auth-input ${errors.email ? 'input-error' : ''}`}
                                    type="email"
                                    placeholder="you@company.com"
                                    value={form.email}
                                    onChange={set('email')}
                                    autoComplete="email"
                                />
                                {errors.email && <span className="auth-field-error">{errors.email}</span>}
                            </div>

                            {/* Password */}
                            <div className="sg-form-group">
                                <label className="sg-label" htmlFor="auth-password">Password</label>
                                <input
                                    id="auth-password"
                                    className={`sg-input auth-input ${errors.password ? 'input-error' : ''}`}
                                    type="password"
                                    placeholder="••••••••"
                                    value={form.password}
                                    onChange={set('password')}
                                    autoComplete={tab === 'login' ? 'current-password' : 'new-password'}
                                />
                                {errors.password && <span className="auth-field-error">{errors.password}</span>}
                            </div>

                            {/* Confirm password (sign up only) */}
                            <div
                                className={`auth-field-wrap ${tab === 'signup' ? 'visible' : 'hidden'}`}
                                aria-hidden={tab !== 'signup'}
                            >
                                <div className="sg-form-group">
                                    <label className="sg-label" htmlFor="auth-confirm">Confirm Password</label>
                                    <input
                                        id="auth-confirm"
                                        className={`sg-input auth-input ${errors.confirm ? 'input-error' : ''}`}
                                        type="password"
                                        placeholder="••••••••"
                                        value={form.confirm}
                                        onChange={set('confirm')}
                                        autoComplete="new-password"
                                        tabIndex={tab === 'signup' ? 0 : -1}
                                    />
                                    {errors.confirm && <span className="auth-field-error">{errors.confirm}</span>}
                                </div>
                            </div>

                            {tab === 'login' && (
                                <div className="auth-forgot-row">
                                    <button type="button" className="auth-forgot-btn">
                                        Forgot password?
                                    </button>
                                </div>
                            )}

                            <button
                                id="auth-submit"
                                type="submit"
                                className="sg-btn sg-btn-primary auth-submit-btn"
                                disabled={loading}
                            >
                                {loading ? (
                                    <>
                                        <span className="auth-btn-spinner" />
                                        {tab === 'login' ? 'Signing in…' : 'Creating account…'}
                                    </>
                                ) : (
                                    tab === 'login' ? 'Sign In →' : 'Create Account →'
                                )}
                            </button>
                        </form>

                        <p className="auth-switch-text">
                            {tab === 'login' ? "Don't have an account? " : 'Already have an account? '}
                            <button
                                type="button"
                                className="auth-switch-btn"
                                onClick={() => switchTab(tab === 'login' ? 'signup' : 'login')}
                            >
                                {tab === 'login' ? 'Sign up free' : 'Sign in'}
                            </button>
                        </p>
                    </div>
                </div>

                <p className="auth-footer-text">
                    © 2026 SwitchGuard · Enterprise Security Platform
                </p>
            </div>
        </div>
    );
};

export default Login;
