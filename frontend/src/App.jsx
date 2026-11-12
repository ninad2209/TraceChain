import React, { useState, useEffect, useRef } from 'react';
import GraphProcessing from './GraphProcessing';
import DetailModal from './DetailModal';
import IncidentPanel from './IncidentPanel';

const API = 'http://127.0.0.1:8000/api/v1';

const NAV = [
  { label: 'Dashboard', icon: '📊' },
  { label: 'Threat Graph', icon: '🕸️' },
  { label: 'Process Analytics', icon: '🔎' },
  { label: 'Rule Engine', icon: '📜' },
  { label: 'Alert Logs', icon: '🚨' },
  { label: 'Settings', icon: '⚙️' }
];

const Pill = ({ level, children }) => (
  <span className={`pill pill-${String(level).toLowerCase()}`}>{children || level}</span>
);

export default function App() {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [scanData, setScanData] = useState(null);
  const [isSimulated, setIsSimulated] = useState(false);
  const [selectedProc, setSelectedProc] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState('ALL');
  const [rules, setRules] = useState([]);
  const [refreshKey, setRefreshKey] = useState(0);
  const [toast, setToast] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [backendDown, setBackendDown] = useState(false);
  const [lastScan, setLastScan] = useState('');
  const toastTimer = useRef(null);

  const showToast = (msg) => {
    setToast(msg);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(''), 3000);
  };

  const stamp = () => setLastScan(new Date().toLocaleTimeString([], { hour12: false }));

  // Load live (or simulated) results WITHOUT resetting isolation state
  const loadScan = async (simulate = false) => {
    try {
      const res = await fetch(`${API}/scan?simulate=${simulate}`);
      const data = await res.json();
      setScanData(data);
      setIsSimulated(simulate);
      setRefreshKey((k) => k + 1);
      setBackendDown(false);
      stamp();
    } catch (err) {
      console.error('Scan failed', err);
      setBackendDown(true);
    }
  };

  // Fresh simulated attack (clears earlier isolation of the mock PIDs)
  const startSimulation = async () => {
    try {
      const res = await fetch(`${API}/simulate-threat`, { method: 'POST' });
      const data = await res.json();
      setScanData(data);
      setIsSimulated(true);
      setRefreshKey((k) => k + 1);
      setBackendDown(false);
      setActiveTab('Dashboard');
      stamp();
      showToast('Simulated attack loaded');
    } catch (err) {
      console.error('Simulation failed', err);
      setBackendDown(true);
    }
  };

  useEffect(() => {
    loadScan(false);
    fetch(`${API}/rules`).then((r) => r.json()).then(setRules).catch(() => {});
  }, []);

  useEffect(() => {
    if (!autoRefresh || isSimulated) return undefined;
    const id = setInterval(() => loadScan(false), 3000);
    return () => clearInterval(id);
  }, [autoRefresh, isSimulated]);

  const isolateProc = async (proc) => {
    try {
      await fetch(`${API}/isolate-process/${proc.pid}?create_time=${encodeURIComponent(proc.create_time || '')}`, {
        method: 'POST'
      });
      showToast(`${proc.name} (PID ${proc.pid}) marked as isolated`);
      setSelectedProc(null);
      loadScan(isSimulated);
    } catch (err) {
      console.error('Isolation failed', err);
      showToast('Isolation failed. Is the backend running?');
    }
  };

  const results = scanData?.results || [];
  const sortedResults = [...results].sort((a, b) => b.risk_score - a.risk_score);

  const filteredResults = sortedResults.filter((proc) => {
    const q = searchQuery.toLowerCase();
    if (!(proc.name.toLowerCase().includes(q) || proc.pid.toString().includes(q))) return false;
    if (filter === 'HIGH') return proc.threat_level === 'HIGH';
    if (filter === 'NETWORK') return proc.tags?.includes('NETWORK_ACTIVE');
    return true;
  });

  const live = results.filter((r) => !r.is_isolated);
  const highCount = live.filter((r) => r.threat_level === 'HIGH').length;
  const medCount = live.filter((r) => r.threat_level === 'MEDIUM').length;
  const status = scanData?.system_status;

  const kpis = [
    { label: 'Processes analysed', value: scanData?.total_analyzed || 0, color: 'var(--accent)' },
    { label: 'High risk', value: highCount, color: highCount ? 'var(--high)' : 'var(--ok)' },
    { label: 'Medium risk', value: medCount, color: medCount ? 'var(--med)' : 'var(--ok)' },
    { label: 'Detection rules', value: rules.length, color: 'var(--violet)' }
  ];

  const alertList = sortedResults.filter((r) => r.threat_level !== 'LOW');

  return (
    <div className="layout">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div>
          <h2 className="brand">Trace<span>Chain</span></h2>
          <div className="brand-sub">Every attack leaves a chain</div>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {NAV.map((item) => (
            <div
              key={item.label}
              role="button"
              tabIndex={0}
              onClick={() => setActiveTab(item.label)}
              onKeyDown={(e) => e.key === 'Enter' && setActiveTab(item.label)}
              className={`sidebar-nav-item ${activeTab === item.label ? 'active' : ''}`}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </div>
          ))}
        </nav>

        <div style={{ marginTop: 'auto', paddingTop: 16, borderTop: '1px solid var(--line)' }}>
          <button onClick={startSimulation} className="btn-sim btn-hover">⚡ Simulate Attack</button>
          <div className="muted" style={{ fontSize: '0.7rem', marginTop: 8, textAlign: 'center' }}>
            Safe demo with fake data. Nothing is executed.
          </div>
        </div>
      </aside>

      {/* MAIN */}
      <main className="content">
        <header className="topbar">
          <div className="topbar-left">
            <span className="page-title">{activeTab}</span>
            <Pill level={status || 'low'}>{status || (backendDown ? 'OFFLINE' : 'LOADING')}</Pill>
          </div>
          <div className="topbar-right">
            <span className="mode">
              <span className={`live-dot ${isSimulated ? 'sim' : ''}`} />
              {isSimulated ? 'Simulation' : 'Live system'}
              {lastScan && <span className="mono"> · {lastScan}</span>}
            </span>
            <button onClick={() => loadScan(false)} className="btn">
              {isSimulated ? 'Back to live system' : 'Rescan'}
            </button>
          </div>
        </header>

        {backendDown && (
          <div className="banner">
            Cannot reach the backend at 127.0.0.1:8000. Start it with: python -m uvicorn backend.main:app --reload
          </div>
        )}

        {/* DASHBOARD */}
        {activeTab === 'Dashboard' && (
          <div className="page">
            <div className="kpis">
              {kpis.map((k) => (
                <div className="kpi" key={k.label} style={{ borderTop: `3px solid ${k.color}` }}>
                  <div className="kpi-label">{k.label}</div>
                  <div className="kpi-value" style={{ color: k.color }}>{k.value}</div>
                </div>
              ))}
            </div>

            <IncidentPanel
              results={results}
              status={status}
              isSimulated={isSimulated}
              onInspect={setSelectedProc}
              onViewGraph={() => setActiveTab('Threat Graph')}
            />

            <div className="split">
              <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                <div className="toolbar">
                  <input
                    className="input"
                    type="text"
                    placeholder="Search by PID or name"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                  <div className="chips">
                    {['ALL', 'HIGH', 'NETWORK'].map((chip) => (
                      <button key={chip} onClick={() => setFilter(chip)} className={`chip ${filter === chip ? 'on' : ''}`}>
                        {chip}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr><th>PID</th><th>Process</th><th>Risk</th><th></th></tr>
                    </thead>
                    <tbody>
                      {filteredResults.length === 0 && (
                        <tr><td colSpan={4} className="muted">No processes match. Clear the search or filter.</td></tr>
                      )}
                      {filteredResults.map((proc) => (
                        <tr key={`${proc.pid}-${proc.create_time}`} style={{ opacity: proc.is_isolated ? 0.5 : 1 }}>
                          <td className="mono muted">{proc.pid}</td>
                          <td style={{ color: '#fff', fontWeight: 600 }}>
                            {proc.name} {proc.is_isolated && <span className="muted" style={{ fontWeight: 400 }}>· isolated</span>}
                          </td>
                          <td><Pill level={proc.threat_level}>{proc.risk_score}</Pill></td>
                          <td><button className="btn btn-ghost" onClick={() => setSelectedProc(proc)}>Inspect</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="card" style={{ overflow: 'hidden' }}>
                <GraphProcessing isSimulated={isSimulated} refreshKey={refreshKey} onNodeClick={setSelectedProc} />
              </div>
            </div>
          </div>
        )}

        {/* THREAT GRAPH */}
        {activeTab === 'Threat Graph' && (
          <div style={{ flex: 1, padding: 16, minHeight: 0 }}>
            <div className="card" style={{ height: '100%', overflow: 'hidden' }}>
              <GraphProcessing isSimulated={isSimulated} refreshKey={refreshKey} onNodeClick={setSelectedProc} />
            </div>
          </div>
        )}

        {/* PROCESS ANALYTICS */}
        {activeTab === 'Process Analytics' && (
          <div className="page">
            <h3 className="card-title">Processes ranked by risk score</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
              {sortedResults.slice(0, 10).map((proc) => (
                <div
                  key={`${proc.pid}-${proc.create_time}`}
                  className="card card-pad"
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelectedProc(proc)}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                    <strong style={{ color: '#fff' }}>{proc.name} <span className="muted mono">PID {proc.pid}</span></strong>
                    <Pill level={proc.threat_level}>{proc.risk_score}</Pill>
                  </div>
                  <div className="muted mono" style={{ fontSize: '0.75rem', marginTop: 6, wordBreak: 'break-all' }}>{proc.exe}</div>
                  <div className="mono" style={{ fontSize: '0.75rem', marginTop: 4, color: 'var(--accent)', wordBreak: 'break-all' }}>
                    {proc.cmdline?.join(' ') || 'N/A'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* RULE ENGINE */}
        {activeTab === 'Rule Engine' && (
          <div className="page">
            <h3 className="card-title">Detection rules</h3>
            <div className="stack">
              {rules.length === 0 && <div className="muted">No rules loaded. Check that the backend is running.</div>}
              {rules.map((r) => (
                <div className="row" key={r.id}>
                  <div>
                    <div style={{ color: '#fff', fontWeight: 600 }}>
                      <span className="mono muted">{r.id}</span> {r.name}
                    </div>
                    <div className="muted" style={{ fontSize: '0.75rem' }}>MITRE ATT&CK {r.mitre}</div>
                  </div>
                  <span className="mono" style={{ color: 'var(--pink)', fontWeight: 700 }}>{r.points} pts</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ALERT LOGS */}
        {activeTab === 'Alert Logs' && (
          <div className="page">
            <h3 className="card-title">Security events</h3>
            <div className="stack">
              {alertList.length === 0 && (
                <div className="muted">No alerts. Press Simulate Attack to see how a chain is detected.</div>
              )}
              {alertList.map((proc) => (
                <div
                  key={`${proc.pid}-${proc.create_time}`}
                  className="row"
                  style={{ cursor: 'pointer', opacity: proc.is_isolated ? 0.5 : 1 }}
                  onClick={() => setSelectedProc(proc)}
                >
                  <div>
                    <div style={{ color: '#fff', fontWeight: 600 }}>
                      {proc.name} <span className="muted mono">PID {proc.pid}</span>
                    </div>
                    <div className="muted" style={{ fontSize: '0.78rem', marginTop: 2 }}>{proc.human_summary}</div>
                  </div>
                  <Pill level={proc.threat_level}>{proc.risk_score}</Pill>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SETTINGS */}
        {activeTab === 'Settings' && (
          <div className="page">
            <h3 className="card-title">Settings</h3>
            <div className="card card-pad" style={{ maxWidth: 440 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
                <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
                Auto-refresh the live scan every 3 seconds
              </label>
              <div className="muted" style={{ fontSize: '0.75rem', marginTop: 8 }}>
                Applies to the live system only. Simulation mode does not refresh on its own.
              </div>
            </div>
          </div>
        )}
      </main>

      <DetailModal process={selectedProc} onClose={() => setSelectedProc(null)} onIsolate={isolateProc} />

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
