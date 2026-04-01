import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { getNavItems } from '../utils/navigation';

const Navigation = () => {
  const { pathname } = useLocation();
  const { user, logout } = useAuth();

  return (
    <aside className="sg-sidebar">
      <div className="sg-logo">
        <div className="sg-logo-text">
          Switch<span>Guard</span>
        </div>
        <div className="sg-logo-sub">Security Platform</div>
      </div>

      <div className="sg-nav-section">
        <div className="sg-nav-label">Main Menu</div>
        {getNavItems(user?.role || 'User').map(({ to, icon, label }) => (
          <Link
            key={to}
            to={to}
            className={`sg-nav-link ${pathname === to ? 'active' : ''}`}
          >
            <span className="nav-icon">{icon}</span>
            {label}
          </Link>
        ))}
      </div>

      <div className="sg-sidebar-footer">
        {user && (
          <div className="sg-user-info">
            <div className="sg-user-avatar">{user.name.charAt(0).toUpperCase()}</div>
            <div className="sg-user-details">
              <div className="sg-user-name">{user.name} <span style={{fontSize: '0.65rem', background: 'rgba(255,255,255,0.1)', padding: '2px 4px', borderRadius: 4, marginLeft: 4}}>{user.role || 'User'}</span></div>
              <div className="sg-user-email" title={user.email}>{user.email}</div>
            </div>
          </div>
        )}
        <button className="sg-logout-btn" onClick={logout} title="Sign out">
          <span>⏻</span> Sign Out
        </button>
        <span className="sg-version-badge" style={{ marginTop: '10px' }}>
          <span>●</span> v2.0 Live
        </span>
      </div>
    </aside>
  );
};

export default Navigation;