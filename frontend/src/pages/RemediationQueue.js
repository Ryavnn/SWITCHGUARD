import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  ShieldCheck, 
  AlertTriangle, 
  RefreshCw,
  MessageSquare,
  CheckCircle,
  AlertCircle
} from 'lucide-react';

const RemediationQueue = () => {
  const [queue, setQueue] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [commentingOn, setCommentingOn] = useState(null);
  const [commentText, setCommentText] = useState("");

  const fetchQueue = async () => {
    try {
      setLoading(true);
      const res = await axios.get('/api/remediation/queue');
      setQueue(res.data);
      setError(null);
    } catch (err) {
      setError("Failed to load remediation queue. Ensure AI services are active.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueue();
  }, []);

  const handleResolve = async (id) => {
    try {
      await axios.post(`/api/remediation/${id}/resolve`);
      fetchQueue();
    } catch (err) {
      alert("Resolution failed.");
    }
  };

  const handleComment = async (id) => {
    if (!commentText.trim()) return;
    try {
      await axios.post(`/api/remediation/${id}/comment`, null, { 
        params: { comment: commentText } 
      });
      setCommentingOn(null);
      setCommentText("");
      fetchQueue();
    } catch (err) {
      alert("Comment failed.");
    }
  };

  if (loading) return (
    <div className="p-8 text-center bg-gray-50 flex flex-col items-center justify-center min-h-screen">
      <RefreshCw className="w-12 h-12 animate-spin mb-4 text-blue-500" />
      <p className="text-gray-500 font-medium">Securing Remediation Intelligence...</p>
    </div>
  );

  return (
    <div className="sg-page-container p-6 bg-gray-50 min-h-screen">
      <header className="mb-8 flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-extrabold text-blue-900 tracking-tight flex items-center">
            <ShieldCheck className="w-8 h-8 mr-3 text-emerald-500" />
            Remediation Queue
          </h1>
          <p className="text-gray-600 mt-2">AI-Prioritized vulnerabilities ordered by business impact and exploitability.</p>
        </div>
        <button 
          onClick={fetchQueue}
          className="bg-white border border-gray-300 px-4 py-2 rounded-lg flex items-center hover:bg-gray-50 transition shadow-sm"
        >
          <RefreshCw className="w-5 h-5 mr-2" /> Refresh
        </button>
      </header>

      {error && (
        <div className="bg-red-50 border-l-4 border-red-400 p-4 mb-6 rounded-r">
          <p className="text-red-700">{error}</p>
        </div>
      )}

      <div className="bg-white rounded-xl shadow-md overflow-hidden border border-gray-200">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Score</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Vulnerability</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Asset</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">AI Insight</th>
              <th className="px-6 py-3 text-right text-xs font-semibold text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {queue.map((item) => (
              <tr key={item.id} className="hover:bg-blue-50/30 transition-colors">
                <td className="px-6 py-4">
                  <div className={`inline-flex items-center justify-center w-12 h-12 rounded-full font-bold text-white shadow-sm
                    ${item.remediation_score > 8 ? 'bg-red-500' : item.remediation_score > 5 ? 'bg-orange-500' : 'bg-blue-500'}`}>
                    {item.remediation_score.toFixed(1)}
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm font-bold text-gray-900">{item.title}</div>
                  <div className="text-xs text-gray-500 mt-1 uppercase tracking-widest flex items-center">
                    <span className={`mr-2 h-2 w-2 rounded-full bg-${item.severity === 'Critical' ? 'red' : 'orange'}-500`}></span>
                    {item.severity}
                  </div>
                  {item.cve_id && <div className="mt-1"><span className="px-2 py-0.5 bg-blue-100 text-blue-800 rounded text-[10px] font-mono">{item.cve_id}</span></div>}
                </td>
                <td className="px-6 py-4 text-sm text-gray-700 font-mono italic">
                  {item.url || item.scan_job?.target}
                </td>
                <td className="px-6 py-4 max-w-md">
                  <p className="text-xs text-gray-600 line-clamp-2 italic">
                    {item.ai_summary || "Automated analysis pending..."}
                  </p>
                  {item.is_kev && (
                    <div className="mt-2 flex items-center text-red-600 font-bold text-[10px]">
                      <AlertTriangle className="w-4 h-4 mr-1 animate-pulse" />
                      CISA KEV ALERT
                    </div>
                  )}
                </td>
                <td className="px-6 py-4 text-right space-x-3">
                  <button 
                    onClick={() => setCommentingOn(item.id)}
                    className="text-gray-400 hover:text-blue-600 transition" 
                    title="Add Comment"
                  >
                    <MessageSquare className="w-6 h-6" />
                  </button>
                  <button 
                    onClick={() => handleResolve(item.id)}
                    className="text-gray-400 hover:text-emerald-600 transition" 
                    title="Resolve"
                  >
                    <CheckCircle className="w-6 h-6" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {queue.length === 0 && (
          <div className="p-20 text-center text-gray-400">
            <ShieldCheck className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p>No vulnerabilities in the queue. Zero risk detected.</p>
          </div>
        )}
      </div>

      {/* Comment Modal Placeholder */}
      {commentingOn && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md border border-gray-100">
            <h3 className="text-xl font-bold text-blue-900 mb-4">Add Remediation Note</h3>
            <textarea 
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              className="w-full border border-gray-200 rounded-xl p-3 h-32 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition"
              placeholder="What steps were taken to remediate this?"
            />
            <div className="mt-6 flex justify-end space-x-3">
              <button 
                onClick={() => setCommentingOn(null)}
                className="px-4 py-2 text-gray-500 hover:text-gray-700 font-semibold"
              >
                Cancel
              </button>
              <button 
                onClick={() => handleComment(commentingOn)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-xl font-bold transition shadow-lg shadow-blue-200"
              >
                Save Comment
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RemediationQueue;
