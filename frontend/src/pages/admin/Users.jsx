import React, { useState, useEffect } from 'react';
import api from '../../services/api';
import { ShieldAlert, CheckCircle, PauseCircle, Trash2 } from 'lucide-react';

const Users = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await api.get('/api/admin/users');
      setUsers(res.data.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const toggleStatus = async (userId, currentStatus) => {
    try {
      await api.patch(`/api/admin/users/${userId}/status?is_active=${!currentStatus}`);
      fetchUsers(); // Refresh immediately
    } catch (err) {
      alert("Failed to update user status");
    }
  };

  const deleteUser = async (userId) => {
    if (!window.confirm("Are you sure you want to permanently delete this user?")) return;
    try {
      await api.delete(`/api/admin/users/${userId}`);
      fetchUsers();
    } catch (err) {
      alert("Failed to delete user");
    }
  };

  if (loading) return <div className="sg-loading"><div className="sg-spinner"></div>Loading Users...</div>;

  return (
    <div className="admin-page-layout fade-in">
      <div className="sg-page-header">
        <h1 className="sg-page-title">User Management</h1>
        <p className="sg-page-subtitle">Governance over all SwitchGuard platform accounts</p>
      </div>

      <div className="sg-card">
        <table className="sg-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Last Login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id}>
                <td><span className="sg-mono">{u.id.substring(0,8)}</span></td>
                <td style={{ fontWeight: 500 }}>{u.email}</td>
                <td>
                  <span className={`sg-status ${u.role === 'Admin' ? 'failed' : 'completed'}`} style={{background: 'rgba(255,255,255,0.05)', color: u.role === 'Admin' ? '#f43f5e' : '#1e6fff'}}>
                    {u.role === 'Admin' ? <ShieldAlert size={12} style={{marginRight: 4}}/> : null}
                    {u.role}
                  </span>
                </td>
                <td>
                  {u.is_active ? 
                    <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 4 }}><CheckCircle size={14}/> Active</span> : 
                    <span style={{ color: '#f59e0b', display: 'flex', alignItems: 'center', gap: 4 }}><PauseCircle size={14}/> Suspended</span>
                  }
                </td>
                <td style={{ color: 'var(--text-muted)' }}>
                  {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button 
                      onClick={() => toggleStatus(u.id, u.is_active)}
                      className="sg-btn sg-btn-ghost" 
                      style={{ padding: '4px 8px', fontSize: '0.75rem', color: u.is_active ? '#f59e0b' : '#10b981' }}
                    >
                      {u.is_active ? 'Suspend' : 'Activate'}
                    </button>
                    <button 
                      onClick={() => deleteUser(u.id)}
                      className="sg-btn sg-btn-ghost" 
                      style={{ padding: '4px 8px', fontSize: '0.75rem', color: '#f43f5e' }}
                    >
                      <Trash2 size={14}/>
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Users;
