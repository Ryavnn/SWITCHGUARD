import React, { useState, useEffect, useCallback } from 'react';
import ReactFlow, { 
  useNodesState, 
  useEdgesState, 
  addEdge, 
  Background, 
  Controls, 
  MiniMap,
  MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';
import api from '../services/api';
import { useParams } from 'react-router-dom';
import { Share2, RefreshCw, AlertCircle } from 'lucide-react';

const initialNodes = [];
const initialEdges = [];

const ChainExplorer = () => {
  const { id } = useParams(); // job_id
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchGraph = useCallback(async () => {
    if (!id) return;
    try {
      setLoading(true);
      const res = await api.get(`/api/analysis/chains/${id}`);
      const data = res.data;

      // Transform NetworkX JSON to ReactFlow format
      const rfNodes = data.nodes.map((node, idx) => ({
        id: node.id,
        data: { label: (
            <div className="p-2 text-center">
                <div className="font-bold text-[10px] uppercase text-gray-400">{node.type}</div>
                <div className="font-medium text-xs">{node.label}</div>
                {node.blast_radius !== undefined && (
                  <div className="mt-1 text-[9px] text-blue-500 font-bold">BR: {node.blast_radius}</div>
                )}
            </div>
        ) },
        position: { x: (idx % 3) * 200, y: Math.floor(idx / 3) * 100 },
        style: { 
            background: node.type === 'vulnerability' ? '#fee2e2' : node.type === 'asset' ? '#dcfce7' : '#fef9c3',
            border: `2px solid ${node.type === 'vulnerability' ? '#ef4444' : node.type === 'asset' ? '#22c55e' : '#eab308'}`,
            borderRadius: '12px',
            width: 150
        }
      }));

      const rfEdges = data.links.map((link, idx) => ({
        id: `e${idx}`,
        source: link.source,
        target: link.target,
        label: link.relation,
        animated: true,
        style: { stroke: link.relation === 'exploits' ? '#ef4444' : '#3b82f6', strokeWidth: 2 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: link.relation === 'exploits' ? '#ef4444' : '#3b82f6',
        },
      }));

      setNodes(rfNodes);
      setEdges(rfEdges);
      setError(null);
    } catch (err) {
      console.error(err);
      setError("Analysis unavailable for this scan. Check if NetworkX is installed on the backend.");
    } finally {
      setLoading(false);
    }
  }, [id, setNodes, setEdges]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  if (loading) return <div className="p-10 text-center">Building Attack Graph...</div>;

  return (
    <div className="sg-page-container flex flex-col h-screen bg-gray-50">
      <header className="p-6 bg-white border-b border-gray-200 flex justify-between items-center shadow-sm">
        <div>
          <h1 className="text-2xl font-black text-blue-950 flex items-center">
            <Share2 className="w-7 h-7 mr-3 text-blue-600" />
            Attack Path Explorer
          </h1>
          <p className="text-xs text-gray-500 font-medium">Heuristic correlation of vulnerabilities across assets.</p>
        </div>
        <div className="flex space-x-3">
            <span className="bg-emerald-50 text-emerald-700 px-3 py-1 rounded-full text-[10px] font-bold border border-emerald-100 flex items-center">
                SCAN ID: {id}
            </span>
            <button 
                onClick={fetchGraph}
                className="p-2 hover:bg-gray-100 rounded-lg transition"
            >
                <RefreshCw className="w-5 h-5 text-gray-600" />
            </button>
        </div>
      </header>

      <div className="flex-grow relative">
        {error ? (
            <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center p-8 bg-white rounded-3xl shadow-xl max-w-sm border border-gray-100">
                    <AlertCircle className="w-16 h-16 text-amber-500 mx-auto mb-4" />
                    <h2 className="text-xl font-bold text-gray-900 mb-2">Graph Generation Failed</h2>
                    <p className="text-sm text-gray-500 mb-6">{error}</p>
                    <button 
                        onClick={fetchGraph}
                        className="bg-blue-600 text-white px-6 py-2 rounded-xl font-bold text-sm"
                    >
                        Try Again
                    </button>
                </div>
            </div>
        ) : (
            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                fitView
            >
                <Background color="#efeff1" gap={16} />
                <Controls />
                <MiniMap />
            </ReactFlow>
        )}
      </div>

      <footer className="p-4 bg-blue-900 text-white text-[10px] uppercase font-black tracking-widest flex justify-between items-center">
        <span>&copy; SwitchGuard AI Engine v2.5</span>
        <div className="flex space-x-4">
            <span className="flex items-center"><div className="w-2 h-2 bg-red-500 rounded mr-2"></div> Vulnerability</span>
            <span className="flex items-center"><div className="w-2 h-2 bg-emerald-500 rounded mr-2"></div> Asset</span>
        </div>
      </footer>
    </div>
  );
};

export default ChainExplorer;
