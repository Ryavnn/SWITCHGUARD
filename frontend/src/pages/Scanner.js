import React, { useState } from 'react';
import api from '../services/api';
import { Link } from 'react-router-dom';

const Scanner = () => {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('network');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);
  const [jobId, setJobId] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    setError(null);
    setJobId(null);

    const endpoint = scanType === 'network' ? '/api/scan/network' : '/api/scan/web';

    try {
      const response = await api.post(endpoint, { target });
      setMessage('Scan launched successfully and is running in the background.');
      setJobId(response.data.job_id);
    } catch (err) {
      // Show the specific backend error message when available
      const detail = err.response?.data?.detail;
      setError(detail || 'Failed to start scan. Ensure the backend and scanning engines are running.');
      console.error('[Scanner] Scan request failed:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="sg-page-header">
        <h1 className="sg-page-title">New Security Scan</h1>
        <p className="sg-page-subtitle">Configure and launch a vulnerability assessment against a target.</p>
      </div>

      <div style={{ maxWidth: 720 }}>

        {/* Scan Type Selection */}
        <div className="sg-form-group">
          <label className="sg-label">Scan Engine</label>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div
              className={`sg-scan-type ${scanType === 'network' ? 'selected' : ''}`}
              onClick={() => setScanType('network')}
            >
              <div className="sg-scan-type-icon">📡</div>
              <div className="sg-scan-type-name">Network Scan</div>
              <div className="sg-scan-type-desc">Port discovery & service enumeration via Nmap</div>
            </div>
            <div
              className={`sg-scan-type ${scanType === 'web' ? 'selected' : ''}`}
              onClick={() => setScanType('web')}
            >
              <div className="sg-scan-type-icon">🛡️</div>
              <div className="sg-scan-type-name">Web App Scan</div>
              <div className="sg-scan-type-desc">Vulnerability discovery via OWASP ZAP active scan</div>
            </div>
          </div>
        </div>

        {/* Target Input */}
        <div className="sg-card" style={{ marginTop: 8 }}>
          <div className="sg-card-header">
            <span className="sg-card-title">Target Configuration</span>
          </div>
          <div className="sg-card-body">
            <form onSubmit={handleScan}>
              <div className="sg-form-group">
                <label className="sg-label">
                  {scanType === 'network' ? 'IP Address or Hostname' : 'Target URL'}
                </label>
                <input
                  className="sg-input"
                  type="text"
                  placeholder={scanType === 'network' ? 'e.g. 192.168.1.1 or scanme.nmap.org' : 'e.g. https://example.com'}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                  autoFocus
                />
              </div>

              {/* Info box */}
              <div className="sg-alert info" style={{ marginBottom: 20 }}>
                <span>ℹ️</span>
                <span>
                  {scanType === 'network'
                    ? 'Nmap will probe open ports, service versions, and OS fingerprints. Scan typically takes 30–120 seconds.'
                    : 'ZAP will spider and actively scan the target URL. This can take 5–20 minutes depending on site size.'}
                </span>
              </div>

              <button className="sg-btn sg-btn-primary" type="submit" disabled={loading} style={{ width: '100%', justifyContent: 'center', padding: '12px' }}>
                {loading ? (
                  <>
                    <span className="sg-spinner" style={{ width: 18, height: 18, borderWidth: 2 }}></span>
                    Launching Scan...
                  </>
                ) : (
                  <>⚡ Launch {scanType === 'network' ? 'Network' : 'Web'} Scan</>
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