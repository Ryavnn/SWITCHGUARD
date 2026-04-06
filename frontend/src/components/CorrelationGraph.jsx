import React, { useCallback, useEffect, useState } from 'react';
import ReactFlow, { 
  addEdge, 
  Background, 
  Controls, 
  MiniMap,
  useNodesState,
  useEdgesState
} from 'reactflow';
import 'reactflow/dist/style.css';

const nodeTypes = {}; // We can add custom node types later (e.g. VulnNode with color)

const CorrelationGraph = ({ data }) => {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (data && data.nodes) {
      // Map raw nodes to ReactFlow nodes with better styling
      const formattedNodes = data.nodes.map(node => ({
        ...node,
        style: { 
          background: node.type === 'asset' ? '#1e6fff' : node.type === 'service' ? '#10b981' : '#f59e0b',
          color: '#fff',
          borderRadius: '8px',
          padding: '10px',
          width: 180,
          fontSize: '0.75rem',
          fontWeight: 'bold',
          border: 'none',
          boxShadow: '0 4px 12px rgba(0,0,0,0.2)'
        },
      }));
      setNodes(formattedNodes);
      setEdges(data.edges || []);
    }
  }, [data, setNodes, setEdges]);

  const onConnect = useCallback((params) => setEdges((eds) => addEdge(params, eds)), [setEdges]);

  return (
    <div style={{ height: '500px', width: '100%', background: '#0f172a', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.1)' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodeTypes={nodeTypes}
        fitView
      >
        <Background color="#1e293b" gap={20} />
        <Controls />
        <MiniMap nodeStrokeWidth={3} zoomable pannable />
      </ReactFlow>
    </div>
  );
};

export default CorrelationGraph;
