import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { 
  Building2, 
  Database, 
  ShieldCheck,
  ShieldAlert,
  FileDown,
  Globe,
  Sparkles
} from 'lucide-react';
import { motion } from 'framer-motion';
import './ClientPortal.css'; // Import the custom structural CSS

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1, delayChildren: 0.1 }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { type: "spring", stiffness: 300, damping: 24 }
  }
};

const ClientPortal = () => {
  const [metrics, setMetrics] = useState(null);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [mRes, aRes] = await Promise.all([
          api.get('/api/portal/metrics'),
          api.get('/api/portal/assets')
        ]);
        setMetrics(mRes.data);
        setAssets(aRes.data);
      } catch (err) {
        console.error("Portal fetch failed", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="sg-loading">
        <div className="sg-spinner"></div>
        Authenticating with Secure Portal...
      </div>
    );
  }

  return (
    <motion.div 
      className="cp-container"
      initial="hidden"
      animate="visible"
      variants={containerVariants}
    >
      {/* Header Section */}
      <motion.header className="cp-header" variants={itemVariants}>
          <div>
            <span className="cp-badge">Client Security Portal</span>
            <h1 className="cp-title">
              <Building2 className="w-10 h-10 text-sg-blue" size={40} />
              {metrics?.tenant_name || "Enterprise"} Security Hub
            </h1>
          </div>
          <div>
            <button className="sg-btn sg-btn-primary">
              <FileDown size={18} />
              Download Monthly Report
            </button>
          </div>
        </motion.header>

        {/* Metrics Grid */}
        <motion.div className="cp-metrics-grid" variants={itemVariants}>
          <div className="sg-stat-card">
            <div className="sg-stat-icon blue">
              <Database size={24} />
            </div>
            <div>
              <div className="sg-stat-value">{metrics?.total_assets || 0}</div>
              <div className="sg-stat-label">Active Assets</div>
            </div>
          </div>
          
          <div className="sg-stat-card">
            <div className="sg-stat-icon amber">
              <ShieldAlert size={24} />
            </div>
            <div>
              <div className="sg-stat-value">{metrics?.total_vulnerabilities || 0}</div>
              <div className="sg-stat-label">Unresolved Vulns</div>
            </div>
          </div>
          
          <div className="sg-stat-card">
            <div className="sg-stat-icon green">
              <ShieldCheck size={24} />
            </div>
            <div>
              <div className="sg-stat-value text-sg-green">94%</div>
              <div className="sg-stat-label">Health Score</div>
            </div>
          </div>
          
          <div className="sg-stat-card">
            <div className="sg-stat-icon blue">
              <Building2 size={24} />
            </div>
            <div>
              <div className="sg-stat-value">100%</div>
              <div className="sg-stat-label">SLA Compliance</div>
            </div>
          </div>
        </motion.div>

        {/* Main Content Layout */}
        <div className="cp-layout-grid">
          
          {/* Managed Assets List */}
          <motion.div className="sg-card" variants={itemVariants}>
            <div className="sg-card-header">
              <h3 className="sg-card-title">Managed Assets</h3>
            </div>
            <div className="sg-card-body">
              {assets.length === 0 ? (
                <div className="sg-empty">No assets managed under this tenant.</div>
              ) : (
                <div className="cp-asset-list">
                  {assets.map(asset => (
                    <motion.div 
                      key={asset.id} 
                      className="cp-asset-card"
                      whileHover={{ scale: 1.01 }}
                      transition={{ type: "spring", stiffness: 400, damping: 25 }}
                    >
                      <div className="cp-asset-info">
                        <div className="cp-asset-icon">
                          <Globe size={20} />
                        </div>
                        <div>
                          <div className="cp-asset-hostname">{asset.hostname || asset.ip_address}</div>
                          <div className="cp-asset-ip">{asset.ip_address}</div>
                        </div>
                      </div>
                      <span className={`cp-criticality ${asset.criticality?.toLowerCase() || 'medium'}`}>
                        {asset.criticality || 'Medium'}
                      </span>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>

          {/* AI Security Insight Panel */}
          <motion.div variants={itemVariants}>
            <div className="cp-insight-card">
              <h3>Security Consultant Insight</h3>
              <div className="cp-insight-quote">
                "Your environment shows strong perimeter defenses. We recommend prioritizing the resolution of two 'Medium' severity items on your production web server within the next 14 days to maintain 100% SLA compliance."
              </div>
              <div className="cp-ai-profile">
                <div className="cp-ai-avatar">
                  <Sparkles size={24} color="#fff" />
                </div>
                <div>
                  <div className="cp-ai-name">SwitchGuard AI</div>
                  <div className="cp-ai-role">Virtual Security Architect</div>
                </div>
              </div>
            </div>
          </motion.div>

        </div>
      </motion.div>
  );
};

export default ClientPortal;
