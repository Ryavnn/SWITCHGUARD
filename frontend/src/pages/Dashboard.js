import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const COLORS = ['#1e6fff', '#10b981', '#f59e0b', '#ef4444'];

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{ background: '#0f1f3d', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: '8px 14px', fontSize: '0.82rem', color: '#f0f4ff' }}>
        {payload[0].name}: <strong>{payload[0].value}</strong>
      </div>
    );
  }
  return null;
};

const StatCard = ({ icon, value, label, color }) => (
  <div className="sg-stat-card">
    <div className={`sg-stat-icon ${color}`}>{icon}</div>
    <div>
      <div className="sg-stat-value">{value}</div>
      <div className="sg-stat-label">{label}</div>
    </div>
  </div>
);

const StatusRow = ({ label, status }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
    <span style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', fontWeight: 500 }}>{label}</span>
    <span className="sg-status completed">{status}</span>
  </div>
);

const Dashboard = ({ type }) => {
  const [metrics, setMetrics] = useState(null);
  const [recent, setRecent]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [health, setHealth]   = useState(null);

  useEffect(() => {
    api.get('/api/dashboard/me')
      .then(res => { 
        setMetrics(res.data.metrics); 
        setRecent(res.data.recent_activity); 
        setLoading(false); 
      })
      .catch(() => setLoading(false));

    api.get('/api/health')
      .then(res => setHealth(res.data))
      .catch(() => {});
  }, []);

  const chartData = recent.reduce((acc, job) => {
    const existing = acc.find(item => item.name === job.type);
    if (existing) {
      existing.value += 1;
    } else {
      acc.push({ name: job.type, value: 1 });
    }
    return acc;
  }, []);


  if (loading) return (
    <div className="sg-loading">
      <div className="sg-spinner"></div>
      <span>Loading dashboard...</span>
    </div>
  );

  return (
    <>
      <div className="sg-page-header">
        <h1 className="sg-page-title">
          {type === 'admin' ? 'Admin Dashboard' : type === 'analyst' ? 'Analyst Dashboard' : 'My Dashboard'}
        </h1>
        <p className="sg-page-subtitle">Security posture and scan overview</p>
      </div>

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 16, marginBottom: 24 }}>
        <StatCard icon="⬡" value={metrics?.total_scans || 0} label="Total Scans" color="blue" />
        <StatCard icon="💻" value={metrics?.total_assets || 0} label="Total Assets" color="blue" />
        <StatCard icon="⚠" value={metrics?.total_vulnerabilities || 0} label="Vulnerabilities" color="amber" />
        <StatCard icon="✗" value={metrics?.critical_findings || 0} label="Critical Vulns" color="red" />
        <StatCard icon="🎯" value={metrics?.risk_score || 0} label="Overall Risk Score" color={metrics?.risk_score > 50 ? "red" : "green"} />
      </div>

      {/* Charts + Status Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20, marginBottom: 24 }}>

        {/* Pie Chart */}
        <div className="sg-card">
          <div className="sg-card-header">
            <span className="sg-card-title">Scan Distribution</span>
          </div>
          <div className="sg-card-body" style={{ height: 280, display: 'flex', alignItems: 'center' }}>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={chartData} cx="50%" cy="50%" innerRadius={65} outerRadius={100} dataKey="value" paddingAngle={4} stroke="none">
                    {chartData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="sg-empty" style={{ width: '100%' }}>
                <div className="sg-empty-icon">📊</div>
                <div>No scan data to display yet.</div>
              </div>
            )}
            {chartData.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 130, marginLeft: 8 }}>
                {chartData.map((d, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.82rem' }}>
                    <span style={{ width: 10, height: 10, borderRadius: 3, background: COLORS[i], flexShrink: 0 }}></span>
                    <span style={{ color: 'var(--text-secondary)' }}>{d.name}</span>
                    <span style={{ marginLeft: 'auto', fontWeight: 700, color: 'var(--text-primary)' }}>{d.value}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Engine Status */}
        <div className="sg-card">
          <div className="sg-card-header">
            <span className="sg-card-title">Engine Status</span>
          </div>
          <div className="sg-card-body" style={{ padding: '8px 24px' }}>
            {[
              { label: 'FastAPI Backend', ok: true },
              { label: 'PostgreSQL DB',   ok: health?.database },
              { label: 'Nmap Engine',     ok: health?.nmap, detail: health?.nmap_version },
              { label: 'OWASP ZAP',       ok: health?.zap },
            ].map(({ label, ok, detail }) => (
              <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', fontWeight: 500 }}>{label}</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {health === null
                    ? <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>checking…</span>
                    : ok
                      ? <span className="sg-status completed">{detail ? `v${detail}` : 'Online'}</span>
                      : <span className="sg-status failed">Offline</span>}
                </span>
              </div>
            ))}
            <div style={{ paddingTop: 16 }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', fontWeight: 700 }}>Platform</div>
              <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: 6 }}>SwitchGuard Security v2.0</div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      {recent.length > 0 && (
        <div className="sg-card">
          <div className="sg-card-header">
            <span className="sg-card-title">Recent Activity</span>
          </div>
          <table className="sg-table">
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {recent.map(job => (
                <tr key={job.id}>
                  <td><span className="sg-mono">{job.id.substring(0, 8)}</span></td>
                  <td style={{ color: 'var(--text-secondary)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{job.target}</td>
                  <td><span className={`sg-type-badge ${job.type}`}>{job.type}</span></td>
                  <td><span className={`sg-status ${job.status}`}>{job.status}</span></td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>{new Date(job.date).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
};

export default Dashboard;