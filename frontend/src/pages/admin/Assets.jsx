import React, { useState, useEffect } from 'react';
import api from '../../services/api';
import { Server, ShieldAlert } from 'lucide-react';

const Assets = () => {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetchAssets();
  }, [search]);

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const res = await api.get(`/api/admin/assets?search=${search}`);
      setAssets(res.data.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-page-layout fade-in">
      <div className="sg-page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
        <div>
          <h1 className="sg-page-title">Global Asset Inventory</h1>
          <p className="sg-page-subtitle">Unified view of all targets scanned across the platform</p>
        </div>
        <div className="sg-form-group" style={{ margin: 0, width: '300px' }}>
          <input 
            type="text" 
            placeholder="Search IP or Hostname..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="sg-input"
            style={{ borderRadius: '20px' }}
          />
        </div>
      </div>

      <div className="sg-card">
        {loading && assets.length === 0 ? (
           <div className="sg-loading" style={{ height: '300px' }}><div className="sg-spinner"></div></div>
        ) : (
          <table className="sg-table">
            <thead>
              <tr>
                <th><Server size={14} style={{marginRight: 6}}/>Asset</th>
                <th>Hostname</th>
                <th>OS</th>
                <th>Open Ports</th>
                <th>Scan Owner</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a, i) => (
                <tr key={i}>
                  <td><span className="sg-mono">{a.ip_address}</span></td>
                  <td style={{ fontWeight: 500 }}>{a.hostname || 'Unknown'}</td>
                  <td style={{ color: 'var(--text-muted)' }}>{a.os || 'N/A'}</td>
                  <td>
                    <span className="sg-type-badge network" style={{ background: 'rgba(255,255,255,0.05)', color: '#1e6fff'}}>
                       {a.ports}
                    </span>
                  </td>
                  <td>{a.owner}</td>
                  <td>
                    <button className="sg-btn sg-btn-ghost" style={{ padding: '4px 8px', fontSize: '0.75rem' }}>View API Data</button>
                  </td>
                </tr>
              ))}
              {assets.length === 0 && !loading && (
                <tr>
                  <td colSpan="6" style={{textAlign: 'center', padding: '40px', color: 'var(--text-muted)'}}>No assets matching your search query.</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default Assets;
