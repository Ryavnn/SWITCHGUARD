import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Building2, 
  Database, 
  ShieldCheck,
  ShieldAlert,
  FileDown,
  Globe,
  TrendingUp
} from 'lucide-react';

const ClientPortal = () => {
  const [metrics, setMetrics] = useState(null);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [mRes, aRes] = await Promise.all([
          axios.get('/api/portal/metrics'),
          axios.get('/api/portal/assets')
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

  if (loading) return <div className="p-10 text-center">Authenticating with Secure Portal...</div>;

  return (
    <div className="sg-portal-container p-8 bg-slate-50 min-h-screen">
      <header className="mb-12 flex flex-col md:flex-row justify-between items-end border-b pb-8 border-slate-200">
        <div>
          <span className="text-blue-600 font-black text-xs uppercase tracking-widest mb-2 block">Client Security Portal</span>
          <h1 className="text-4xl font-extrabold text-slate-900 flex items-center">
            <Building2 className="w-10 h-10 mr-4 text-slate-400" />
            {metrics?.tenant_name || "Enterprise"} Security Hub
          </h1>
        </div>
        <div className="mt-4 md:mt-0">
            <button className="bg-slate-900 text-white px-6 py-3 rounded-xl font-bold flex items-center hover:bg-slate-800 transition">
                <FileDown className="w-5 h-5 mr-2" />
                Download Monthly Report
            </button>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 italic">
          <span className="text-slate-400 text-xs font-bold uppercase">Active Assets</span>
          <div className="text-3xl font-black text-slate-900 mt-2 flex items-center">
            <Database className="w-6 h-6 mr-2 text-blue-500" />
            {metrics?.total_assets}
          </div>
        </div>
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 italic">
          <span className="text-slate-400 text-xs font-bold uppercase">Unresolved Vulns</span>
          <div className="text-3xl font-black text-slate-900 mt-2 flex items-center">
            <ShieldAlert className="w-6 h-6 mr-2 text-orange-500" />
            {metrics?.total_vulnerabilities}
          </div>
        </div>
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 italic">
          <span className="text-slate-400 text-xs font-bold uppercase">Health Score</span>
          <div className="text-3xl font-black text-emerald-600 mt-2 flex items-center">
            <ShieldCheck className="w-6 h-6 mr-2 text-emerald-500" />
            94%
          </div>
        </div>
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 italic">
          <span className="text-slate-400 text-xs font-bold uppercase">SLA Compliance</span>
          <div className="text-3xl font-black text-blue-600 mt-2">100%</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
            <div className="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                <h3 className="text-lg font-bold text-slate-900 mb-6">Managed Assets</h3>
                <div className="space-y-4">
                    {assets.map(asset => (
                        <div key={asset.id} className="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <div className="flex items-center">
                                <div className="w-10 h-10 bg-white rounded-lg border border-slate-200 flex items-center justify-center mr-4">
                                    <Globe className="w-6 h-6 text-slate-400" />
                                </div>
                                <div>
                                    <div className="font-bold text-slate-900 text-sm">{asset.hostname || asset.ip_address}</div>
                                    <div className="text-[10px] text-slate-400 font-mono italic">{asset.ip_address}</div>
                                </div>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase ${
                                asset.criticality === 'critical' ? 'bg-red-100 text-red-600' : 
                                asset.criticality === 'high' ? 'bg-orange-100 text-orange-600' : 'bg-slate-100 text-slate-600'
                            }`}>
                                {asset.criticality || 'Medium'}
                            </span>
                        </div>
                    ))}
                </div>
            </div>
        </div>

        <div>
            <div className="bg-indigo-600 rounded-3xl p-8 text-white shadow-xl shadow-indigo-200 sticky top-8">
                <h3 className="text-xl font-bold mb-6">Security Consultant Insight</h3>
                <div className="bg-white/10 rounded-2xl p-4 mb-6 italic text-sm leading-relaxed">
                    "Your environment shows strong perimeter defenses. We recommend prioritizing the resolution of two 'Medium' severity items on your production web server within the next 14 days to maintain 100% SLA compliance."
                </div>
                <div className="flex items-center">
                    <div className="w-10 h-10 bg-indigo-400 rounded-full mr-3 border-2 border-white/20"></div>
                    <div>
                        <div className="font-bold text-sm">SwitchGuard AI</div>
                        <div className="text-indigo-200 text-xs font-medium uppercase tracking-tighter">Virtual Security Architect</div>
                    </div>
                </div>
            </div>
        </div>
      </div>
    </div>
  );
};

export default ClientPortal;
