import React, { useState, useEffect } from 'react';
import api from '../../services/api';
import { Save } from 'lucide-react';

const Settings = () => {
  const [settings, setSettings] = useState({});
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      const res = await api.get(`/api/admin/settings`);
      setSettings(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async (key, value) => {
    setSaving(key);
    try {
      await api.patch(`/api/admin/settings/${key}`, { value: String(value) });
      const current = { ...settings };
      current[key].value = value;
      setSettings(current);
    } catch (err) {
      alert("Failed to patch system setting.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="sg-loading"><div className="sg-spinner"></div>Loading System Configurations...</div>;

  return (
    <div className="admin-page-layout fade-in">
      <div className="sg-page-header">
        <h1 className="sg-page-title">Platform Configuration</h1>
        <p className="sg-page-subtitle">Configure scan tunables, limits, and core environment policies</p>
      </div>

      <div style={{ maxWidth: '800px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        {Object.keys(settings).map((key) => {
          const config = settings[key];
          return (
            <div key={key} className="sg-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '24px' }}>
              <div>
                <h4 style={{ textTransform: 'capitalize', color: 'var(--text-bright)', marginBottom: 8, fontSize: '1rem' }}>
                  {key.replace(/_/g, " ")}
                </h4>
                <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: '0.85rem' }}>{config.desc}</p>
              </div>
              
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <input 
                  type="text"
                  className="sg-input"
                  defaultValue={config.value}
                  style={{ width: '150px', background: 'rgba(0,0,0,0.2)' }}
                  onBlur={(e) => {
                    if (e.target.value !== config.value) {
                       handleUpdate(key, e.target.value);
                    }
                  }}
                />
                <button className="sg-btn sg-btn-primary" style={{ padding: '8px 12px' }} disabled={saving === key}>
                  {saving === key ? '...' : <Save size={16} />}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default Settings;
