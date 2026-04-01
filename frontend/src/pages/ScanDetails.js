import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import { formatDate } from '../utils/formatters';
import { getRiskLevel } from '../utils/riskUtils';

const RiskBadge = ({ risk }) => {
  const level = getRiskLevel(risk);
  return <span className={`vuln-risk-badge ${level.toLowerCase()}`}>{level}</span>;
};

const ScanDetails = () => {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showRaw, setShowRaw] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  const loadData = () => {
    api.get(`/api/jobs/${id}`)
      .then(res => { setData(res.data); setLoading(false); })
      .catch(err => {
        console.error('[ScanDetails] Load failed:', err);
        setError('Failed to load scan report.');
        setLoading(false);
      });
  };

  useEffect(() => { loadData(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCancel = async () => {
    if (!window.confirm('Are you sure you want to cancel this scan?')) return;
    setCancelling(true);
    try {
      await api.patch(`/api/jobs/${id}/cancel`);
      await loadData();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to cancel scan.');
    } finally {
      setCancelling(false);
    }
  };

  if (loading) return (
    <div className="sg-loading">
      <div className="sg-spinner"></div>
      <span>Loading report...</span>
    </div>
  );

  if (error) return (
    <div style={{ padding: 40 }}>
      <div className="sg-alert error">{error}</div>
      <Link to="/history" className="sg-btn sg-btn-ghost" style={{ marginTop: 16 }}>&larr; Back to Archive</Link>
    </div>
  );

  const { job, assets = [], vulnerabilities = [] } = data;
  const isNetwork = job.scan_type === 'network';

  // Parse raw results
  let parsed = null;
  if (job.raw_results) {
    try {
      parsed = typeof job.raw_results === 'string' ? JSON.parse(job.raw_results) : job.raw_results;
    } catch { /* ignore */ }
  }

  // Extract nmap hosts with port info
  const nmapHosts = parsed?.scan ? Object.entries(parsed.scan) : [];

  // Extract ZAP alerts (array or { alerts: [] })
  let zapAlerts = [];
  if (Array.isArray(parsed)) zapAlerts = parsed;
  else if (parsed?.alerts) zapAlerts = parsed.alerts;
  else if (vulnerabilities.length > 0) zapAlerts = vulnerabilities;

  const riskOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
  zapAlerts = [...zapAlerts].sort((a, b) => {
    const ar = getRiskLevel(a.risk || a.severity);
    const br = getRiskLevel(b.risk || b.severity);
    return (riskOrder[ar] ?? 9) - (riskOrder[br] ?? 9);
  });

  const highCount = zapAlerts.filter(a => getRiskLevel(a.risk || a.severity) === 'High').length;
  const mediumCount = zapAlerts.filter(a => getRiskLevel(a.risk || a.severity) === 'Medium').length;
  const lowCount = zapAlerts.filter(a => getRiskLevel(a.risk || a.severity) === 'Low').length;

  return (
    <>
      {/* Breadcrumb */}
      <div style={{ marginBottom: 20 }}>
        <Link to="/history" className="sg-btn sg-btn-ghost" style={{ padding: '7px 14px', fontSize: '0.8rem' }}>
          ← Back to Archive
        </Link>
      </div>

      {/* Hero */}
      <div className="sg-hero">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <span className={`sg-type-badge ${job.scan_type}`}>{job.scan_type}</span>
              <span className={`sg-status ${job.status}`}>{job.status}</span>
            </div>
            <h1 className="sg-page-title" style={{ fontSize: '1.4rem', marginBottom: 6 }}>
              {isNetwork ? '📡' : '🛡️'} Security Report
            </h1>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 4 }}>
              Target: <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{job.target}</span>
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>
              Job {job.job_id} · {formatDate(job.created_at)}
            </div>

            {/* Cancel button — only for active scans */}
            {(job.status === 'running' || job.status === 'pending') && (
              <button
                className="sg-btn sg-btn-danger"
                style={{ marginTop: 14, padding: '7px 16px', fontSize: '0.82rem' }}
                disabled={cancelling}
                onClick={handleCancel}
              >
                {cancelling ? '⏳ Cancelling...' : '✕ Cancel Scan'}
              </button>
            )}
          </div>

          {/* Stats summary if web scan */}
          {!isNetwork && (
            <div style={{ display: 'flex', gap: 12 }}>
              {[['High', highCount, 'var(--sg-red)'], ['Medium', mediumCount, 'var(--sg-amber)'], ['Low', lowCount, 'var(--sg-green)']].map(([label, count, color]) => (
                <div key={label} style={{ textAlign: 'center', background: 'rgba(0,0,0,0.3)', borderRadius: 10, padding: '12px 18px', minWidth: 72 }}>
                  <div style={{ fontSize: '1.6rem', fontWeight: 800, color }}>{count}</div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700, marginTop: 4 }}>{label}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* === NETWORK RESULTS === */}
      {isNetwork && (
        <div className="sg-card" style={{ marginBottom: 20 }}>
          <div className="sg-card-header">
            <span className="sg-card-title">Open Ports &amp; Services</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              {nmapHosts.length === 0 ? 'No active hosts detected' : `${nmapHosts.length} host(s) scanned`}
            </span>
          </div>

          {nmapHosts.length === 0 ? (
            <div className="sg-empty">
              <div className="sg-empty-icon">🔒</div>
              <div>No open ports found or host appears to be down.</div>
            </div>
          ) : (
            nmapHosts.map(([host, info]) => {
              const tcp = info.tcp || {};
              const ports = Object.entries(tcp);
              return (
                <div key={host}>
                  <div style={{ padding: '14px 24px 10px', display: 'flex', alignItems: 'center', gap: 10, borderBottom: '1px solid var(--border)' }}>
                    <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{host}</span>
                    {info.hostnames?.[0]?.name && (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>({info.hostnames[0].name})</span>
                    )}
                    <span style={{ marginLeft: 'auto' }}><span className="sg-status completed">{ports.filter(([, p]) => p.state === 'open').length} open ports</span></span>
                  </div>
                  {ports.length === 0 ? (
                    <div style={{ padding: '16px 24px', color: 'var(--text-muted)', fontSize: '0.875rem' }}>No TCP port data.</div>
                  ) : (
                    <table className="sg-port-table">
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>State</th>
                          <th>Service</th>
                          <th>Product</th>
                          <th>Version</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ports.map(([port, p]) => (
                          <tr key={port}>
                            <td><span className="sg-mono">{port}/tcp</span></td>
                            <td>
                              <span className={`sg-status ${p.state === 'open' ? 'completed' : 'pending'}`}>{p.state}</span>
                            </td>
                            <td style={{ fontWeight: 600 }}>{p.name || '—'}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{p.product || '—'}</td>
                            <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{p.version || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* === WEB VULN RESULTS === */}
      {!isNetwork && (
        <>
          {zapAlerts.length === 0 ? (
            <div className="sg-card" style={{ marginBottom: 20 }}>
              <div className="sg-empty">
                <div className="sg-empty-icon">✅</div>
                <div style={{ fontWeight: 700, marginBottom: 4 }}>No vulnerabilities discovered</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>The scan completed cleanly.</div>
              </div>
            </div>
          ) : (
            <div style={{ marginBottom: 20 }}>
              {zapAlerts.map((alert, i) => {
                const level = getRiskLevel(alert.risk || alert.severity);
                const risk = level.toLowerCase();
                const title = alert.alert || alert.title || 'Unknown Issue';
                const desc = alert.description || '';
                const url = alert.url || '';
                const solution = alert.solution || '';
                const evidence = alert.evidence || '';

                return (
                  <div key={i} className={`vuln-card ${risk}`}>
                    <RiskBadge risk={alert.risk || alert.severity} />
                    <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)', marginBottom: 8 }}>{title}</div>
                    {url && (
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 10, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        🔗 {url}
                      </div>
                    )}
                    {desc && <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: solution ? 12 : 0 }}>{desc}</p>}
                    {solution && (
                      <div style={{ background: 'rgba(16,185,129,0.08)', borderLeft: '3px solid var(--sg-green)', padding: '10px 14px', borderRadius: '0 6px 6px 0', marginTop: 8 }}>
                        <div style={{ fontSize: '0.7rem', fontWeight: 800, color: 'var(--sg-green)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 4 }}>Remediation</div>
                        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{solution}</div>
                      </div>
                    )}
                    {evidence && (
                      <div style={{ marginTop: 10, fontSize: '0.77rem', fontFamily: 'monospace', color: 'var(--text-muted)', background: 'var(--sg-navy)', padding: '8px 12px', borderRadius: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        Evidence: {evidence}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {/* Raw Output Toggle */}
      <div className="sg-card">
        <div
          className="sg-card-header"
          onClick={() => setShowRaw(!showRaw)}
          style={{ cursor: 'pointer', userSelect: 'none' }}
        >
          <span className="sg-card-title">🛠 Raw Engine Output</span>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>{showRaw ? '▲ Collapse' : '▼ Expand'}</span>
        </div>
        {showRaw && (
          <div style={{ padding: 20 }}>
            <pre className="pre-code">{parsed ? JSON.stringify(parsed, null, 2) : 'No raw data attached to this scan.'}</pre>
          </div>
        )}
      </div>
    </>
  );
};

export default ScanDetails;