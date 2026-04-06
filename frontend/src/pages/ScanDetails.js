import React, { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import { formatDate } from '../utils/formatters';
import { getRiskLevel } from '../utils/riskUtils';
import CorrelationGraph from '../components/CorrelationGraph';
import reportService from '../services/reportService';

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
  const [correlationData, setCorrelationData] = useState(null);
  const [overriding, setOverriding] = useState({});   // track per-vuln-id override state
  const [downloading, setDownloading] = useState(null);
  const pollRef = useRef(null);

  const loadData = () => {
    Promise.all([
      api.get(`/api/jobs/${id}`),
      api.get(`/api/jobs/${id}/correlation`).catch(() => ({ data: { nodes: [], edges: [] } }))
    ])
    .then(([jobRes, corrRes]) => {
      setData(jobRes.data);
      setCorrelationData(corrRes.data);
      setLoading(false);
    })
    .catch(err => {
      console.error('[ScanDetails] Load failed:', err);
      setError('Failed to load scan report.');
      setLoading(false);
    });
  };

  useEffect(() => { loadData(); }, [id]);

  // FIX: Polling fallback — refreshes every 5s while scan is running
  // Prevents "Failed to load" when WebSocket events are missed.
  useEffect(() => {
    if (data?.job?.status === 'running' || data?.job?.status === 'pending') {
      pollRef.current = setInterval(loadData, 5000);
    } else {
      clearInterval(pollRef.current);
    }
    return () => clearInterval(pollRef.current);
  }, [data?.job?.status]);

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

  const handleOverride = async (vulnId, overrideData) => {
    setOverriding(prev => ({ ...prev, [vulnId]: true }));
    try {
      await api.patch(`/api/vulnerabilities/${vulnId}`, overrideData);
      await loadData(); // refresh to show updated severity
    } catch (err) {
      alert(err.response?.data?.detail || 'Override failed.');
    } finally {
      setOverriding(prev => ({ ...prev, [vulnId]: false }));
    }
  };

  const handleDownload = async (type) => {
    try {
      setDownloading(type);
      await reportService.download(id, type);
    } catch (err) {
      alert(err.response?.status === 404 ? 'Report not yet generated.' : 'Download failed.');
    } finally {
      setDownloading(null);
    }
  };

  if (loading) return (
    <div className="sg-loading">
      <div className="sg-spinner"></div>
      <span>Loading report...</span>
    </div>
  );

  const { job, assets = [], vulnerabilities = [] } = data || {};
  
  if (!job) return (
    <div style={{ padding: 40, textAlign: 'center' }}>
      <div className="sg-alert error">Data integrity error: Scan metadata missing.</div>
      <Link to="/history" className="sg-btn sg-btn-ghost" style={{ marginTop: 16 }}>&larr; Back to Archive</Link>
    </div>
  );

  const isNetwork = job.scan_type === 'network';

  // Parse raw results safely
  let parsed = null;
  if (job?.raw_results) {
    try {
      parsed = typeof job.raw_results === 'string' ? JSON.parse(job.raw_results) : job.raw_results;
    } catch (e) {
      console.warn("[ScanDetails] Failed to parse raw results:", e);
    }
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

      {/* === CORRELATION GRAPH === */}
      {correlationData && correlationData.nodes?.length > 0 && (
        <div className="sg-card" style={{ marginBottom: 20 }}>
          <div className="sg-card-header">
            <span className="sg-card-title">🔗 Correlation Graph &amp; Attack Chain</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Cross-layer vulnerability links</span>
          </div>
          <div style={{ padding: '0 20px 20px' }}>
            <CorrelationGraph data={correlationData} />
            <div style={{ marginTop: 12, textAlign: 'center' }}>
                <Link to={`/chains/${id}`} className="sg-btn sg-btn-primary" style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
                    🔍 Open Advanced Chain Explorer
                </Link>
            </div>
          </div>
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
                
                // Advanced Fields
                const cveId = alert.cve_id;
                const cweId = alert.cwe_id;
                const riskScore = alert.risk_score;
                const confidence = alert.confidence_score;

                return (
                  <div key={i} className={`vuln-card ${risk}`}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                      <RiskBadge risk={alert.risk || alert.severity} />
                      {riskScore > 0 && (
                        <div style={{ fontSize: '0.7rem', fontWeight: 800, background: 'rgba(255,255,255,0.1)', padding: '4px 8px', borderRadius: 4, color: 'var(--text-primary)' }}>
                          RISK SCORE: {riskScore}/10
                        </div>
                      )}
                    </div>
                    
                    <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)', marginBottom: 8 }}>{title}</div>
                    
                    {(cveId || cweId) && (
                      <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
                        {cveId && <span style={{ background: '#ef4444', color: '#fff', fontSize: '0.65rem', padding: '2px 6px', borderRadius: 4, fontWeight: 700 }}>{cveId}</span>}
                        {cweId && <span style={{ background: '#1e6fff', color: '#fff', fontSize: '0.65rem', padding: '2px 6px', borderRadius: 4, fontWeight: 700 }}>CWE-{cweId}</span>}
                        {confidence > 0 && <span style={{ background: 'rgba(255,255,255,0.1)', color: 'var(--text-muted)', fontSize: '0.65rem', padding: '2px 6px', borderRadius: 4 }}>CONFIDENCE: {Math.round(confidence * 100)}%</span>}
                      </div>
                    )}

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

                    {/* AI PERSPECTIVE DRAWERS (Phase 3) */}
                    {(alert.ai_summary || alert.ai_impact || alert.ai_remediation) && (
                      <div style={{ marginTop: 16, borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                          <span style={{ color: '#7c3aed', fontSize: '1rem' }}>✨</span>
                          <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#7c3aed', textTransform: 'uppercase', letterSpacing: '1px' }}>AI Security Perspective</span>
                        </div>
                        
                        <div className="sg-ai-grid" style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12 }}>
                          {alert.ai_summary && (
                            <div style={{ background: 'rgba(124,58,237,0.05)', padding: '12px', borderRadius: 12, border: '1px solid rgba(124,58,237,0.1)' }}>
                              <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#9d6eff', marginBottom: 4 }}>CONTEXTUAL SUMMARY</div>
                              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{alert.ai_summary}</div>
                            </div>
                          )}
                          
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                            {alert.ai_impact && (
                              <div style={{ background: 'rgba(239,68,68,0.05)', padding: '12px', borderRadius: 12, border: '1px solid rgba(239,68,68,0.1)' }}>
                                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#f87171', marginBottom: 4 }}>BUSINESS IMPACT</div>
                                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{alert.ai_impact}</div>
                              </div>
                            )}
                            {alert.ai_remediation && (
                              <div style={{ background: 'rgba(16,185,129,0.05)', padding: '12px', borderRadius: 12, border: '1px solid rgba(16,185,129,0.1)' }}>
                                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#34d399', marginBottom: 4 }}>EXPERT REMEDIATION</div>
                                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{alert.ai_remediation}</div>
                              </div>
                            )}
                          </div>
                        </div>
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