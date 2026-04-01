import React, { useState, useEffect } from 'react';
import api from '../../services/api';
import { Activity } from 'lucide-react';

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const res = await api.get(`/api/admin/audit-logs`);
      setLogs(res.data.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="sg-loading"><div className="sg-spinner"></div>Loading Logs...</div>;

  return (
    <div className="admin-page-layout fade-in">
      <div className="sg-page-header">
        <h1 className="sg-page-title">Enterprise Audit Trail</h1>
        <p className="sg-page-subtitle">Immutable ledger of administrative actions and platform metadata</p>
      </div>

      <div className="sg-card">
        <table className="sg-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Administrator</th>
              <th>Action Category</th>
              <th>Target Scope</th>
            </tr>
          </thead>
          <tbody>
            {logs.map(log => (
              <tr key={log.id}>
                <td style={{ color: 'var(--text-muted)' }}>{new Date(log.timestamp).toLocaleString()}</td>
                <td style={{ fontWeight: 500, color: '#1e6fff' }}>{log.user}</td>
                <td>
                  <span className="sg-status running" style={{ padding: '4px 10px', textTransform: 'none' }}>
                     {log.action}
                  </span>
                </td>
                <td className="sg-mono">{log.target_id || '<global>'}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr>
                <td colSpan="4" style={{textAlign: 'center', padding: '40px', color: 'var(--text-muted)'}}>The audit ledger is currently empty.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AuditLogs;
