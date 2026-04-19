import React, { useState, useEffect } from 'react';
import api from '../services/api';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, PieChart, Pie, Cell, Legend
} from 'recharts';
import { 
  BarChart3, 
  TrendingUp, 
  ShieldAlert,
  Globe
} from 'lucide-react';

const COLORS = ['#ef4444', '#f97316', '#f59e0b', '#10b981', '#3b82f6'];

const Analytics = () => {
  const [likelihood, setLikelihood] = useState(null);
  const [forecast, setForecast] = useState([]);
  const [topThreats, setTopThreats] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [lRes, fRes, tRes] = await Promise.all([
          api.get('/api/analytics/breach-likelihood'),
          api.get('/api/analytics/risk-forecast'),
          api.get('/api/analytics/top-threats')
        ]);
        setLikelihood(lRes.data);
        setForecast(fRes.data);
        setTopThreats(tRes.data);
      } catch (err) {
        console.error("Analytics fetch failed", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) return <div className="p-10 text-center animate-pulse">Loading Intelligence...</div>;

  return (
    <div className="sg-analytics-container p-8 bg-gray-50 min-h-screen">
      <header className="mb-10 text-center md:text-left">
        <h1 className="text-4xl font-black text-blue-950 flex items-center justify-center md:justify-start">
          <BarChart3 className="w-10 h-10 mr-4 text-violet-600" />
          Security Intelligence Analytics
        </h1>
        <p className="text-gray-500 mt-2 text-lg">Predictive risk modeling and automated threat correlation.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        {/* Breach Likelihood Card */}
        <div className="bg-white p-6 rounded-3xl shadow-xl border border-white flex flex-col items-center justify-center relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition">
                <ShieldAlert className="w-24 h-24 text-red-500" />
            </div>
            <h3 className="text-gray-400 font-semibold uppercase tracking-widest text-xs mb-4">Breach Likelihood Index</h3>
            <div className="relative">
                <svg className="w-48 h-48">
                    <circle className="text-gray-100" strokeWidth="12" stroke="currentColor" fill="transparent" r="80" cx="96" cy="96" />
                    <circle className="text-red-500 transition-all duration-1000 ease-out" strokeWidth="12" strokeDasharray={502} strokeDashoffset={502 - (502 * (likelihood?.likelihood_score || 0) / 100)} strokeLinecap="round" stroke="currentColor" fill="transparent" r="80" cx="96" cy="96" />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-5xl font-black text-red-600">{likelihood?.likelihood_score}%</span>
                    <span className="text-xs font-bold text-gray-400 mt-1 uppercase">{likelihood?.risk_level} RISK</span>
                </div>
            </div>
            <p className="mt-6 text-sm text-gray-500 text-center italic">
                "{likelihood?.ai_context || "Insufficient data for predictive modeling."}"
            </p>
        </div>

        {/* Risk Forecast Chart */}
        <div className="lg:col-span-2 bg-white p-6 rounded-3xl shadow-xl border border-white">
          <div className="flex justify-between items-center mb-6">
            <h3 className="text-blue-900 font-bold text-xl flex items-center">
              <TrendingUp className="w-6 h-6 mr-2 text-blue-500" />
              7-Day Risk Forecast
            </h3>
            <span className="text-xs font-bold bg-blue-50 text-blue-600 px-3 py-1 rounded-full uppercase">Predictive ML</span>
          </div>
          <div className="h-64 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={forecast}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                <XAxis dataKey="day" axisLine={false} tickLine={false} tick={{fontSize: 10, fill: '#94a3b8'}} />
                <YAxis axisLine={false} tickLine={false} tick={{fontSize: 10, fill: '#94a3b8'}} domain={[0, 100]} />
                <Tooltip 
                    contentStyle={{borderRadius: '16px', border: 'none', boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)'}}
                    itemStyle={{fontWeight: 'bold'}}
                />
                <Area type="monotone" dataKey="risk" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Top Threats List */}
        <div className="bg-white p-8 rounded-3xl shadow-xl border border-white">
          <h3 className="text-blue-900 font-black text-xl mb-6">Critical Remediation Targets</h3>
          <div className="space-y-4">
            {topThreats.map((threat, idx) => (
              <div key={idx} className="flex items-center p-4 bg-gray-50 rounded-2xl hover:translate-x-2 transition-transform cursor-pointer border border-transparent hover:border-blue-100">
                <div className={`w-12 h-12 flex-shrink-0 flex items-center justify-center rounded-xl font-bold text-white shadow-lg
                  ${threat.severity === 'Critical' ? 'bg-red-500 shadow-red-200' : 'bg-orange-500 shadow-orange-200'}`}>
                  {threat.remediation_score.toFixed(1)}
                </div>
                <div className="ml-4 flex-grow">
                  <h4 className="text-sm font-bold text-gray-900 truncate w-64">{threat.title}</h4>
                  <p className="text-xs text-gray-500 font-mono mt-1">{threat.url || "Universal Target"}</p>
                </div>
                <div className="text-right">
                    <span className={`text-[10px] font-black uppercase px-2 py-1 rounded ${threat.severity === 'Critical' ? 'bg-red-50 text-red-600' : 'bg-orange-50 text-orange-600'}`}>
                        {threat.severity}
                    </span>
                </div>
              </div>
            ))}
            {topThreats.length === 0 && <p className="text-center text-gray-400 py-10 italic">No significant threats identified.</p>}
          </div>
        </div>

        {/* Global Distribution Map Placeholder */}
        <div className="bg-blue-900 p-8 rounded-3xl shadow-xl text-white relative overflow-hidden">
            <div className="absolute top-0 right-0 w-64 h-64 bg-white/5 rounded-full -mr-20 -mt-20 blur-3xl"></div>
            <h3 className="text-xl font-bold mb-2 flex items-center">
                <Globe className="w-6 h-6 mr-2 text-blue-300" />
                Asset Exposure Map
            </h3>
            <p className="text-blue-300 text-sm mb-8">Spatial distribution of vulnerable endpoints across the network.</p>
            
            <div className="h-48 flex items-center justify-center border-2 border-white/10 border-dashed rounded-2xl">
                <p className="text-white/30 font-bold uppercase tracking-widest text-xs">Geometric Analysis Pending...</p>
            </div>

            <div className="mt-8 grid grid-cols-2 gap-4">
                <div className="bg-white/10 p-4 rounded-2xl backdrop-blur-sm">
                    <span className="block text-blue-300 text-[10px] uppercase font-black mb-1">Exposure Ratio</span>
                    <span className="text-2xl font-bold">14.2%</span>
                </div>
                <div className="bg-white/10 p-4 rounded-2xl backdrop-blur-sm">
                    <span className="block text-blue-300 text-[10px] uppercase font-black mb-1">Mean Time to Fix</span>
                    <span className="text-2xl font-bold">4.2d</span>
                </div>
            </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
