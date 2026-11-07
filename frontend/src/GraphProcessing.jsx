import React, { useEffect, useState } from 'react';
import { ReactFlow, Background, Controls } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import axios from 'axios';

export default function GraphProcessing({ isSimulated }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadGraph = async () => {
    setLoading(true);
    try {
      const url = `http://127.0.0.1:8000/api/v1/graph-data${isSimulated ? '?simulate=true' : ''}`;
      const response = await axios.get(url);
      setNodes(response.data.nodes);
      setEdges(response.data.edges);
    } catch (err) {
      console.error("Failed to fetch graph data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraph();
  }, [isSimulated]);

  return (
    <div style={{ height: '500px', backgroundColor: '#090d16', borderRadius: '0.5rem', border: '1px solid #334155', position: 'relative' }}>
      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#38bdf8' }}>
          Updating Process Chain Visualizer...
        </div>
      ) : (
        <ReactFlow nodes={nodes} edges={edges} fitView>
          <Background color="#334155" gap={16} />
          <Controls style={{ backgroundColor: '#1e293b', border: '1px solid #334155', fill: '#f8fafc' }} />
        </ReactFlow>
      )}
    </div>
  );
}