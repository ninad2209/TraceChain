import React, { useEffect, useState, useMemo } from 'react';
import { ReactFlow, Background, Controls, Handle, Position, Panel, MarkerType } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from '@dagrejs/dagre';

const NODE_W = 220;
const NODE_H = 142;

function fmtTime(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return d.toLocaleTimeString([], { hour12: false });
}

// Top-to-bottom tree layout so parent -> child chains read clearly
function layoutTree(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 80 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    return { ...n, position: { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 } };
  });
}

function ProcessNode({ data }) {
  const { label, pid, threat_level, risk_score, is_isolated, started, parentLabel } = data;

  const isHigh = threat_level === 'HIGH';
  const isMed = threat_level === 'MEDIUM';

  let borderColor = isHigh ? '#ff2a6d' : (isMed ? '#ffb703' : '#2b1650');
  let bgColor = isHigh ? '#3a0913' : (isMed ? '#331902' : '#140c28');
  let textColor = isHigh ? '#ff2a6d' : (isMed ? '#ffb703' : '#00f2fe');

  if (is_isolated) {
    borderColor = '#475569';
    bgColor = '#0f172a';
    textColor = '#64748b';
  }

  return (
    <div style={{
      padding: '12px 14px',
      borderRadius: '8px',
      border: `2px solid ${borderColor}`,
      backgroundColor: bgColor,
      color: textColor,
      width: `${NODE_W}px`,
      boxShadow: is_isolated ? 'none' : (isHigh ? '0 0 20px rgba(255, 42, 109, 0.4)' : (isMed ? '0 0 15px rgba(255, 183, 3, 0.2)' : 'none')),
      fontFamily: 'monospace, sans-serif',
      cursor: 'pointer',
      opacity: is_isolated ? 0.7 : 1
    }}>
      <Handle type="target" position={Position.Top} style={{ background: borderColor, width: 8, height: 8 }} />
      <div style={{ fontWeight: 'bold', fontSize: '0.85rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>{is_isolated ? '🛡️ ISOLATED' : (isHigh ? '🔴 THREAT' : isMed ? '⚠️ WARNING' : '🟢 OK')}</span>
        <span style={{ fontSize: '0.7rem', color: '#94a3b8' }}>PID: {pid}</span>
      </div>
      <div style={{ fontSize: '0.95rem', fontWeight: '800', marginTop: '6px', color: '#ffffff', wordBreak: 'break-all' }}>
        {label}
      </div>
      {started && (
        <div style={{ fontSize: '0.7rem', marginTop: '2px', color: '#94a3b8' }}>Started {started}</div>
      )}
      {parentLabel && (
        <div style={{ fontSize: '0.68rem', marginTop: '5px', color: '#c4b5fd', whiteSpace: 'nowrap' }}>
          {parentLabel}
        </div>
      )}
      <div style={{ fontSize: '0.75rem', marginTop: '6px', display: 'flex', justifyContent: 'space-between', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '4px' }}>
        <span style={{ color: '#94a3b8' }}>Risk Score:</span>
        <span style={{ fontWeight: 'bold', color: textColor }}>{risk_score}/100</span>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: borderColor, width: 8, height: 8 }} />
    </div>
  );
}

const panelBox = {
  backgroundColor: 'rgba(18, 9, 36, 0.92)',
  border: '1px solid #2b1650',
  borderRadius: 8,
  padding: '10px 12px',
  color: '#cbd5e1',
  fontSize: '0.75rem',
  maxWidth: 270,
  lineHeight: 1.5
};

export default function GraphProcessing({ isSimulated, refreshKey = 0, onNodeClick }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [chainOnly, setChainOnly] = useState(true);
  const [showHelp, setShowHelp] = useState(true);

  useEffect(() => {
    if (!showHelp) return undefined;
    const t = setTimeout(() => setShowHelp(false), 6000);
    return () => clearTimeout(t);
  }, [showHelp]);

  const nodeTypes = useMemo(() => ({ processNode: ProcessNode }), []);

  useEffect(() => {
    let cancelled = false;

    const fetchGraphData = async () => {
      try {
        const res = await fetch(
          `http://127.0.0.1:8000/api/v1/graph-data?simulate=${isSimulated}&chain_only=${chainOnly}`
        );
        const data = await res.json();

        const rawNodes = data.nodes || [];
        const rawEdges = data.edges || [];
        const childCounts = rawEdges.reduce((counts, edge) => {
          counts[edge.source] = (counts[edge.source] || 0) + 1;
          return counts;
        }, {});
        const incoming = Object.fromEntries(rawEdges.map((edge) => [edge.target, edge]));

        const formattedNodes = rawNodes.map((n) => {
          const raw = n.data || {};
          const details = raw.full_details || {};
          const parentEdge = incoming[n.id];
          const step = parentEdge?.data?.step;
          const parentName = details.parent_name;
          const parentLabel = parentEdge && parentName
            ? (chainOnly
              ? `Chain step ${step}: started by ${parentName}`
              : `Started by ${parentName} · child ${step} of ${childCounts[parentEdge.source]}`)
            : null;
          return {
            id: n.id,
            type: 'processNode',
            data: {
              label: raw.label || 'Process',
              pid: raw.pid || n.id,
              threat_level: raw.threat_level || 'LOW',
              risk_score: raw.risk_score || 0,
              is_isolated: raw.is_isolated || false,
              order: raw.order || 0,
              started: fmtTime(details.create_time),
              parentLabel,
              full_details: details
            },
            position: { x: 0, y: 0 }
          };
        });

        const formattedEdges = rawEdges.map((e) => {
          const hot = !!(e.data && e.data.in_chain);
          const edgeColor = hot ? '#ff2a6d' : '#6b46c1';

          return {
            id: e.id,
            source: e.source,
            target: e.target,
            type: 'smoothstep',
            animated: hot,
            style: { stroke: edgeColor, strokeWidth: hot ? 2.5 : 1.5 },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              width: 16,
              height: 16,
              color: edgeColor
            }
          };
        });

        if (!cancelled) {
          setNodes(layoutTree(formattedNodes, formattedEdges));
          setEdges(formattedEdges);
          setError(false);
        }
      } catch (err) {
        console.error('Failed to fetch graph data', err);
        if (!cancelled) setError(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchGraphData();
    return () => { cancelled = true; };
  }, [isSimulated, refreshKey, chainOnly]);

  const story = useMemo(() => {
    if (nodes.length < 2) return '';
    return [...nodes]
      .sort((a, b) => a.data.order - b.data.order)
      .map((n) => n.data.label)
      .join(' → ');
  }, [nodes]);

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#00f2fe' }}>
        ⚡ Building process tree...
      </div>
    );
  }

  if (error && nodes.length === 0) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#ffb703', padding: 16, textAlign: 'center' }}>
        Could not reach the backend at 127.0.0.1:8000. Start it with: python -m uvicorn backend.main:app --reload
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: '100%', backgroundColor: '#0b0718', position: 'relative' }}>
      <ReactFlow
        key={`${isSimulated ? 'simulated' : 'live'}-${chainOnly ? 'chain' : 'all'}`}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        nodesDraggable={false}
        onNodeClick={(_, node) => {
          if (node.data && node.data.full_details) {
            onNodeClick(node.data.full_details);
          }
        }}
        fitView
      >
        <Background color="#2b1650" gap={20} size={1} />
        <Controls className="custom-react-flow-controls" />

        <Panel position="top-left">
          <div style={panelBox}>
            <div style={{ display: 'flex', gap: 6, marginBottom: showHelp ? 8 : 0 }}>
              {[
                { id: true, label: 'Suspicious chain' },
                { id: false, label: 'All processes' }
              ].map((opt) => (
                <button
                  key={String(opt.id)}
                  onClick={() => setChainOnly(opt.id)}
                  className="btn-hover"
                  style={{
                    padding: '4px 10px', borderRadius: 4, fontSize: '0.7rem', fontWeight: 'bold',
                    backgroundColor: chainOnly === opt.id ? '#7c3aed' : '#180d30',
                    color: '#fff', border: '1px solid #2b1650'
                  }}
                >
                  {opt.label}
                </button>
              ))}
              <button
                onClick={() => setShowHelp((v) => !v)}
                className="btn-hover"
                title="Show or hide how to read this graph"
                style={{
                  padding: '4px 10px', borderRadius: 4, fontSize: '0.7rem', fontWeight: 'bold',
                  backgroundColor: showHelp ? '#7c3aed' : '#180d30', color: '#fff', border: '1px solid #2b1650'
                }}
              >
                ?
              </button>
            </div>
            {showHelp && (
              <div>
                <div><strong style={{ color: '#fff' }}>How to read this graph</strong></div>
                <div>Follow arrows from parent to child. Each child card names its parent and start order.</div>
                <div>{chainOnly ? 'Chain step numbers follow the suspicious chain.' : 'Child numbers restart for each parent; lower numbers started first.'}</div>
                <div>Red arrows and nodes are part of the suspicious chain.</div>
                {story && chainOnly && (
                  <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid #2b1650', color: '#fff', wordBreak: 'break-word' }}>
                    Order of events: {story}
                  </div>
                )}
              </div>
            )}
          </div>
        </Panel>
      </ReactFlow>

      {nodes.length === 0 && (
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none', color: '#94a3b8', textAlign: 'center', padding: 24, fontSize: '0.9rem'
        }}>
          No suspicious chain found. Press Simulate Attack to see one, or switch to All processes.
        </div>
      )}
    </div>
  );
}
