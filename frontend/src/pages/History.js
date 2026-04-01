import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../services/api';
import reportService from '../services/reportService';

const History = () => {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [cancelling, setCancelling] = useState(null); // job_id being cancelled
  const [downloading, setDownloading] = useState(null); // track job_id loading
  const navigate = useNavigate();

  useEffect(() => { fetchJobs(); }, []);

  const handleDownload = async (e, jobId, type) => {
    e.stopPropagation();
    try {
      setDownloading(jobId + type);
      await reportService.download(jobId, type);
    } catch (err) {
      if (err.response?.status === 404) {
        alert("Report not found. The background generation process might still be running.");
      } else if (err.response?.status === 403) {
        alert("You are not authorized to download this report.");
      } else {
        alert("Failed to download report due to a network error.");
      }
    } finally {
      setDownloading(null);
    }
  };


  const fetchJobs = async () => {
    try {
      const res = await api.get('/api/jobs');
      setJobs(res.data.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
    } catch {
      setError('Failed to load scan archive. Ensure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async (e, jobId) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to cancel this scan?')) return;
    setCancelling(jobId);
    try {
      await api.patch(`/api/jobs/${jobId}/cancel`);
      await fetchJobs();
    } catch (err) {
      const detail = err.response?.data?.detail || 'Failed to cancel scan.';
      alert(detail);
    } finally {
      setCancelling(null);
    }
  };

  const filtered = jobs.filter(j =>
    filter === 'all' || j.scan_type === filter || j.status === filter
  );

  if (loading) return (
    <div className="sg-loading">
      <div className="sg-spinner"></div>
      <span>Loading archive...</span>
    </div>
  );

  return (
    <>
      <div className="sg-page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1 className="sg-page-title">Scan Archive</h1>
          <p className="sg-page-subtitle">{jobs.length} total records — click any row to open the full report</p>
        </div>
        <Link to="/scan" className="sg-btn sg-btn-primary">⚡ New Scan</Link>
      </div>

      {error && <div className="sg-alert error">{error}</div>}

      {/* Filter Controls */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {[['all', 'All'], ['network', 'Network'], ['web', 'Web App'], ['completed', 'Completed'], ['running', 'Running'], ['failed', 'Failed'], ['cancelled', 'Cancelled']].map(([val, label]) => (
          <button
            key={val}
            onClick={() => setFilter(val)}
            className={`sg-btn ${filter === val ? 'sg-btn-primary' : 'sg-btn-ghost'}`}
            style={{ padding: '6px 14px', fontSize: '0.8rem' }}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="sg-card">
        {filtered.length === 0 ? (
          <div className="sg-empty">
            <div className="sg-empty-icon">📂</div>
            <div style={{ fontWeight: 600, marginBottom: 8 }}>No scans match this filter</div>
            <Link to="/scan" className="sg-btn sg-btn-primary" style={{ display: 'inline-flex', marginTop: 8 }}>
              Launch your first scan
            </Link>
          </div>
        ) : (
          <table className="sg-table">
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Date &amp; Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(job => {
                const canCancel = job.status === 'running' || job.status === 'pending';
                return (
                  <tr key={job.job_id} onClick={() => navigate(`/scan/${job.job_id}`)}>
                    <td><span className="sg-mono">{job.job_id.substring(0, 8)}</span></td>
                    <td style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>
                      {job.target}
                    </td>
                    <td><span className={`sg-type-badge ${job.scan_type}`}>{job.scan_type}</span></td>
                    <td><span className={`sg-status ${job.status}`}>{job.status}</span></td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.82rem', whiteSpace: 'nowrap' }}>
                      {new Date(job.created_at).toLocaleString()}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      {canCancel ? (
                        <button
                          className="sg-btn sg-btn-danger"
                          style={{ padding: '5px 12px', fontSize: '0.78rem' }}
                          disabled={cancelling === job.job_id}
                          onClick={(e) => handleCancel(e, job.job_id)}
                        >
                          {cancelling === job.job_id ? '…' : '✕ Cancel'}
                        </button>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>→</span>
                      )}
                      
                      {job.status === 'completed' && (
                        <div style={{ display: 'inline-flex', gap: 6, marginLeft: 12 }}>
                          <button 
                            className="sg-btn sg-btn-ghost" 
                            style={{ padding: '4px 8px', fontSize: '0.75rem', borderColor: 'rgba(255,255,255,0.1)' }}
                            onClick={(e) => handleDownload(e, job.job_id, 'csv')}
                            disabled={downloading === job.job_id + 'csv'}
                          >
                            {downloading === job.job_id + 'csv' ? '...' : '↓ CSV'}
                          </button>
                          <button 
                            className="sg-btn sg-btn-ghost" 
                            style={{ padding: '4px 8px', fontSize: '0.75rem', borderColor: 'rgba(255,255,255,0.1)', color: '#1e6fff' }}
                            onClick={(e) => handleDownload(e, job.job_id, 'pdf')}
                            disabled={downloading === job.job_id + 'pdf'}
                          >
                            {downloading === job.job_id + 'pdf' ? '...' : '↓ PDF'}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
};

export default History;