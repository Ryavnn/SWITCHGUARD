import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, ShieldCheck, Server, AlertTriangle, Users, FileText } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import api from '../../services/api';
import StatCard from '../../components/admin/StatCard';

const COLORS = ['#1e6fff', '#f43f5e', '#f59e0b', '#10b981', '#6b7280'];

const AdminDashboard = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();

    // Secure SOC WebSocket Channel
    const ws = new WebSocket('ws://localhost:8000/ws/admin');
    ws.onopen = () => console.log('SOC Telemetry WebSocket Connected');
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'SCAN_COMPLETED') {
                // Toast notification substitute
                alert(`🚨 SOC ALERT: ${msg.scan_type.toUpperCase()} scan [${msg.job_id.substring(0,8)}] completed!`);
                // Live dashboard refresh
                fetchDashboardData();
            }
        } catch(e) { console.error('WS Parse Error', e); }
    };
    
    return () => {
        if(ws.readyState === 1) ws.close();
    };
  }, []);

  const fetchDashboardData = async () => {
    try {
      const res = await api.get('/api/admin/dashboard/summary');
      setData(res.data);
    } catch (error) {
      console.error("Failed to load admin stats", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !data) {
    return (
      <div className="sg-loading">
        <div className="sg-spinner"></div>
        <span>Initializing SOC Overview...</span>
      </div>
    );
  }

  // Mocked chart data just for visualization if vulns API isn't built yet
  const chartData = [
    { name: 'Critical', value: data.vulnerabilities.critical },
    { name: 'High', value: data.vulnerabilities.high },
    { name: 'Medium', value: 34 },
    { name: 'Low', value: 89 }
  ];

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="admin-soc-layout">
      <div className="sg-page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1 className="sg-page-title">Enterprise Security Operations Center</h1>
            <p className="sg-page-subtitle">Global Platform Telemetry & Vulnerability Intelligence</p>
          </div>
          <div className="sg-status running" style={{ padding: '8px 16px' }}>
            <Activity size={16} style={{marginRight: '8px', verticalAlign: 'middle'}}/>
            <span style={{verticalAlign: 'middle'}}>Live Telemetry Active</span>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px', marginBottom: '32px' }}>
        <StatCard delay={0.1} title="Total Assets" value={data.assets.total} icon={Server} colorClass="text-blue" />
        <StatCard delay={0.2} title="Active Scans" value={data.scans.running} icon={Activity} colorClass="text-green" />
        <StatCard delay={0.3} title="Critical Vulns" value={data.vulnerabilities.critical} icon={AlertTriangle} colorClass="text-red" />
        <StatCard delay={0.4} title="Avg Risk Score" value={`${data.risk_score.average}/100`} icon={ShieldCheck} colorClass="text-orange" />
        <StatCard delay={0.5} title="Total Users" value={data.users.total} icon={Users} colorClass="text-gray" />
        <StatCard delay={0.6} title="Generated Reports" value={data.reports.generated} icon={FileText} colorClass="text-blue" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px' }}>
        <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.7 }} className="sg-card">
          <h3 style={{ marginBottom: '20px' }}>Vulnerability Distribution</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <XAxis dataKey="name" stroke="#6b7280" />
                <YAxis stroke="#6b7280" />
                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ background: '#0f1f3d', border: '1px solid #1e6fff' }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.8 }} className="sg-card">
          <h3 style={{ marginBottom: '20px' }}>Global Scan Activity</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={[
                    { name: 'Completed', value: data.scans.completed },
                    { name: 'Running', value: data.scans.running },
                    { name: 'Failed', value: data.scans.failed }
                  ]}
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                >
                  <Cell fill="#10b981" />
                  <Cell fill="#1e6fff" />
                  <Cell fill="#f43f5e" />
                </Pie>
                <Tooltip contentStyle={{ background: '#0f1f3d', border: 'none' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </motion.div>
      </div>

    </motion.div>
  );
};

export default AdminDashboard;
