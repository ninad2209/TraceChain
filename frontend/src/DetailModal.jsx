import React from 'react';

export default function DetailModal({ process, onClose, onIsolate }) {
  if (!process) return null;

  const isHighRisk = process.threat_level === 'HIGH';
  const isMedRisk = process.threat_level === 'MEDIUM';
  const canIsolate = (isHighRisk || isMedRisk) && !process.is_isolated;
  const accent = isHighRisk ? '#ff2a6d' : isMedRisk ? '#ffb703' : '#00f2fe';

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(7, 3, 16, 0.85)', backdropFilter: 'blur(4px)',
      display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
    }}>
      <div style={{
        backgroundColor: '#120924', border: `2px solid ${accent}`,
        borderRadius: '16px', padding: '28px', width: '600px', maxWidth: '90%', maxHeight: '90vh', overflowY: 'auto',
        color: '#f8fafc', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #2b1650', paddingBottom: '16px' }}>
          <h2 style={{ margin: 0, fontSize: '1.3rem', display: 'flex', alignItems: 'center', gap: '10px', color: '#00f2fe' }}>
            {isHighRisk ? '🔴' : isMedRisk ? '⚠️' : '🟢'} {process.name}
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontFamily: 'monospace' }}>(PID: {process.pid})</span>
          </h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '1.4rem', cursor: 'pointer' }}>✕</button>
        </div>

        {/* Chain line */}
        <div style={{ marginTop: '12px', fontSize: '0.85rem', color: '#94a3b8', fontFamily: 'monospace' }}>
          {process.parent_name || 'unknown parent'} → <span style={{ color: '#fff' }}>{process.name}</span>
        </div>

        {/* Threat level and score */}
        <div style={{ marginTop: '16px', display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{
            padding: '6px 14px', borderRadius: '20px', fontSize: '0.75rem', fontWeight: 'bold',
            backgroundColor: isHighRisk ? 'rgba(255, 42, 109, 0.2)' : isMedRisk ? 'rgba(255, 183, 3, 0.2)' : 'rgba(0, 242, 254, 0.15)',
            color: accent, border: `1px solid ${accent}`
          }}>
            {process.threat_level} THREAT LEVEL
          </span>
          <span style={{ fontSize: '0.9rem', color: '#cbd5e1' }}>
            Risk Score: <strong style={{ color: accent }}>{process.risk_score} / 100</strong>
          </span>
          {process.is_isolated && (
            <span style={{ fontSize: '0.75rem', color: '#94a3b8', border: '1px solid #475569', borderRadius: 20, padding: '4px 10px' }}>
              🛡️ Isolated (simulated)
            </span>
          )}
        </div>

        {/* Plain-language finding */}
        <div style={{ marginTop: '20px', backgroundColor: '#180d30', padding: '16px', borderRadius: '10px', borderLeft: `4px solid ${accent}` }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '6px' }}>Why this was flagged</div>
          <div style={{ fontSize: '0.95rem', color: '#f1f5f9', lineHeight: '1.5' }}>{process.human_summary}</div>
        </div>

        {/* Score breakdown */}
        {process.breakdown && process.breakdown.length > 0 && (
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: 6 }}>How this score was built</div>
            {process.breakdown.map((f, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, fontSize: '0.8rem', padding: '4px 0', borderBottom: '1px solid rgba(43, 22, 80, 0.4)' }}>
                <span style={{ color: '#ff007f', fontWeight: 'bold', minWidth: 36 }}>+{f.points}</span>
                <span style={{ flex: 1 }}>{f.text}</span>
                {f.mitre && <code style={{ color: '#94a3b8' }}>{f.mitre}</code>}
              </div>
            ))}
          </div>
        )}

        {/* Technical details */}
        <div style={{ marginTop: '20px', fontSize: '0.85rem', display: 'grid', gap: '12px' }}>
          <div>
            <strong style={{ color: '#94a3b8' }}>Spawned by:</strong>{' '}
            {process.parent_name
              ? <><code style={{ color: '#00f2fe' }}>{process.parent_name}</code> <span style={{ color: '#94a3b8' }}>(PID {process.ppid})</span></>
              : <span style={{ color: '#94a3b8' }}>Unknown (system process or already exited)</span>}
          </div>
          <div><strong style={{ color: '#94a3b8' }}>Executable path:</strong> <code style={{ color: '#00f2fe', wordBreak: 'break-all' }}>{process.exe}</code></div>
          <div>
            <strong style={{ color: '#94a3b8' }}>Command line:</strong>
            <pre style={{ backgroundColor: '#0b0718', padding: '10px', borderRadius: '8px', overflowX: 'auto', color: '#a7f3d0', fontSize: '0.8rem', marginTop: '6px', border: '1px solid #2b1650', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {process.cmdline && process.cmdline.length ? process.cmdline.join(' ') : 'N/A'}
            </pre>
          </div>
          {process.connections && process.connections.length > 0 && (
            <div>
              <strong style={{ color: '#94a3b8' }}>Network connections:</strong>
              {process.connections.map((c, i) => (
                <div key={i} style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#cbd5e1', marginTop: 4 }}>
                  {c.laddr} → {c.raddr || 'listening'} ({c.status})
                </div>
              ))}
            </div>
          )}
          <div><strong style={{ color: '#94a3b8' }}>User:</strong> {process.username}</div>
          <div><strong style={{ color: '#94a3b8' }}>Recommended action:</strong> <span style={{ color: '#ffb703' }}>{process.recommendation}</span></div>
        </div>

        {/* Actions */}
        <div style={{ marginTop: '28px', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
          <button onClick={onClose} className="btn-hover" style={{ padding: '10px 20px', borderRadius: '8px', backgroundColor: '#261347', color: '#fff', border: '1px solid #2b1650' }}>
            Close
          </button>
          {canIsolate && (
            <button
              onClick={() => onIsolate(process)}
              className="btn-hover"
              style={{
                padding: '10px 20px', borderRadius: '8px',
                background: 'linear-gradient(135deg, #ff2a6d 0%, #990000 100%)',
                color: '#fff', fontWeight: 'bold', border: 'none',
                boxShadow: '0 4px 15px rgba(255, 42, 109, 0.4)'
              }}
            >
              🛡️ Isolate (simulated)
            </button>
          )}
        </div>
      </div>
    </div>
  );
}