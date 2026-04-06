import React, { useState } from 'react';
import api from '../services/api';
import { Link } from 'react-router-dom';

const SCAN_PROFILES = [
  { value: 'fast',     label: '⚡ Fast',        desc: 'Top ports, service detection (~30s)'   },
  { value: 'standard', label: '🔍 Standard',    desc: 'Service versions, common ports (~1–2m)'  },
  { value: 'deep',     label: '🧠 Deep',         desc: 'Full port range, OS, NSE scripts (~10m)' },
  { value: 'udp',      label: '📡 UDP',          desc: 'Top-200 UDP ports + service detection'   },
  { value: 'vuln',     label: '🦠 Vulnerability', desc: 'Vulnerability NSE scripts (SMB, FTP…)'  },
];

const SCAN_TYPES = [
  { value: 'network', icon: '📡', label: 'Network Scan',    desc: 'Port discovery & service enumeration via Nmap' },
  { value: 'web',     icon: '🛡️', label: 'Web App Scan',    desc: 'DAST via OWASP ZAP active scanning' },
  { value: 'nuclei',  icon: '☢️', label: 'Nuclei Scan',     desc: 'Template-based vulnerability scanning' },
];

const Scanner = () => {
  const [target,       setTarget]       = useState('');
  const [scanType,     setScanType]     = useState('network');
  const [profile,      setProfile]      = useState('standard');
  const [useAjax,      setUseAjax]      = useState(false);
  // Auth config (web scans)
  const [showAuth,     setShowAuth]     = useState(false);
  const [loginUrl,     setLoginUrl]     = useState('');
  const [username,     setUsername]     = useState('');
  const [password,     setPassword]     = useState('');
  const [sessionCookie,setSessionCookie]= useState('');

  const [loading,  setLoading]  = useState(false);
  const [message,  setMessage]  = useState(null);
  const [error,    setError]    = useState(null);
  const [jobId,    setJobId]    = useState(null);

  const endpoint = {
    network: '/api/scan/network',
    web:     '/api/scan/web',
    nuclei:  '/api/scan/nuclei',
  }[scanType];

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    setError(null);
    setJobId(null);

    const body = { target, profile };
    if (scanType === 'web') {
      body.use_ajax = useAjax;
      if (loginUrl)       body.login_url      = loginUrl;
      if (username)       body.username        = username;
      if (password)       body.password        = password;
      if (sessionCookie)  body.session_cookie  = sessionCookie;
    }

    try {
      const response = await api.post(endpoint, body);
      setMessage('Scan launched successfully and is running in the background.');
      setJobId(response.data.job_id);
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(detail || 'Failed to start scan. Ensure the backend and scanning engines are running.');
    } finally {
      setLoading(false);
    }
  };

  const selectedProfile = SCAN_PROFILES.find(p => p.value === profile);

  return (
    <>
      <div className="sg-page-header">
        <h1 className="sg-page-title">New Security Scan</h1>
        <p className="sg-page-subtitle">Configure and launch a vulnerability assessment against a target.</p>
      </div>

      <div style={{ maxWidth: 760 }}>

        {/* Scan Engine */}
        <div className="sg-form-group">
          <label className="sg-label">Scan Engine</label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {SCAN_TYPES.map(st => (
              <div
                key={st.value}
                className={`sg-scan-type ${scanType === st.value ? 'selected' : ''}`}
                onClick={() => setScanType(st.value)}
              >
                <div className="sg-scan-type-icon">{st.icon}</div>
                <div className="sg-scan-type-name">{st.label}</div>
                <div className="sg-scan-type-desc">{st.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Scan Profile */}
        {scanType !== 'web' && (
          <div className="sg-form-group">
            <label className="sg-label">Scan Profile</label>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {SCAN_PROFILES.map(p => (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => setProfile(p.value)}
                  className={`sg-btn ${profile === p.value ? 'sg-btn-primary' : 'sg-btn-ghost'}`}
                  style={{ fontSize: '0.82rem', padding: '6px 14px' }}
                >
                  {p.label}
                </button>
              ))}
            </div>
            {selectedProfile && (
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 6 }}>
                {selectedProfile.desc}
              </p>
            )}
          </div>
        )}

        {/* Target + Config */}
        <div className="sg-card" style={{ marginTop: 8 }}>
          <div className="sg-card-header">
            <span className="sg-card-title">Target Configuration</span>
          </div>
          <div className="sg-card-body">
            <form onSubmit={handleScan}>
              <div className="sg-form-group">
                <label className="sg-label">
                  {scanType === 'network' ? 'IP Address / CIDR / Hostname' : 'Target URL'}
                </label>
                <input
                  className="sg-input"
                  type="text"
                  placeholder={
                    scanType === 'network'
                      ? 'e.g. 192.168.1.0/24  or  scanme.nmap.org'
                      : 'e.g. https://example.com'
                  }
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  required
                  autoFocus
                />
              </div>

              {/* Web-scan extra options */}
              {scanType === 'web' && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 12 }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.88rem' }}>
                      <input type="checkbox" checked={useAjax} onChange={e => setUseAjax(e.target.checked)} />
                      Use AJAX Spider (for React / Angular / Vue SPAs)
                    </label>
                    <button
                      type="button"
                      onClick={() => setShowAuth(v => !v)}
                      className="sg-btn sg-btn-ghost"
                      style={{ fontSize: '0.8rem', padding: '5px 12px' }}
                    >
                      {showAuth ? '▲ Hide Auth Config' : '🔐 Configure Auth'}
                    </button>
                  </div>

                  {showAuth && (
                    <div style={{ background: 'rgba(30,111,255,0.07)', border: '1px solid rgba(30,111,255,0.2)', borderRadius: 10, padding: 16, marginBottom: 8 }}>
                      <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 12 }}>
                        Provide login credentials to enable authenticated scanning. Only one auth method is required.
                      </p>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                        <div className="sg-form-group" style={{ marginBottom: 0 }}>
                          <label className="sg-label" style={{ fontSize: '0.8rem' }}>Login URL</label>
                          <input className="sg-input" style={{ fontSize: '0.88rem' }} placeholder="https://example.com/login"
                            value={loginUrl} onChange={e => setLoginUrl(e.target.value)} />
                        </div>
                        <div className="sg-form-group" style={{ marginBottom: 0 }}>
                          <label className="sg-label" style={{ fontSize: '0.8rem' }}>Session Cookie / Bearer Token</label>
                          <input className="sg-input" style={{ fontSize: '0.88rem' }} placeholder="session=abc123 or Bearer token…"
                            value={sessionCookie} onChange={e => setSessionCookie(e.target.value)} />
                        </div>
                        <div className="sg-form-group" style={{ marginBottom: 0 }}>
                          <label className="sg-label" style={{ fontSize: '0.8rem' }}>Username</label>
                          <input className="sg-input" style={{ fontSize: '0.88rem' }} autoComplete="off"
                            value={username} onChange={e => setUsername(e.target.value)} />
                        </div>
                        <div className="sg-form-group" style={{ marginBottom: 0 }}>
                          <label className="sg-label" style={{ fontSize: '0.8rem' }}>Password</label>
                          <input className="sg-input" style={{ fontSize: '0.88rem' }} type="password" autoComplete="off"
                            value={password} onChange={e => setPassword(e.target.value)} />
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <div className="sg-alert info" style={{ marginBottom: 20 }}>
                <span>ℹ️</span>
                <span>
                  {scanType === 'network' && `Nmap will probe ports using the "${profile}" profile.`}
                  {scanType === 'web'     && `ZAP will spider${useAjax ? ' (AJAX mode)' : ''} then actively scan the target.`}
                  {scanType === 'nuclei'  && 'Nuclei will run template-based checks against the target.'}
                </span>
              </div>

              <button
                className="sg-btn sg-btn-primary"
                type="submit"
                disabled={loading}
                style={{ width: '100%', justifyContent: 'center', padding: '12px' }}
              >
                {loading ? (
                  <><span className="sg-spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />Launching Scan...</>
                ) : (
                  <>⚡ Launch {SCAN_TYPES.find(t => t.value === scanType)?.label}</>
                )}
              </button>
            </form>

            {message && (
              <div className="sg-alert success" style={{ marginTop: 20 }}>
                <span>✓</span>
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{message}</div>
                  {jobId && (
                    <span>
                      Job ID: <span className="sg-mono">{jobId}</span>
                      {' — '}
                      <Link to="/history" style={{ color: 'inherit', textDecoration: 'underline', fontWeight: 600 }}>View in Archive →</Link>
                    </span>
                  )}
                </div>
              </div>
            )}

            {error && (
              <div className="sg-alert error" style={{ marginTop: 20 }}>
                <span>✗</span>
                <span>{error}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
};

export default Scanner;