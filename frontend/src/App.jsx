import React, { useState } from 'react';
import axios from 'axios';
import { Shield, AlertTriangle, Activity, Server, RefreshCw, Search, Network, Flame } from 'lucide-react';
import GraphProcessing from './GraphProcessing';

export default function App() {
  const [loading, setLoading] = useState(false);
  const [telemetryData, setTelemetryData] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('table'); // 'table' or 'graph'
  const [isSimulated, setIsSimulated] = useState(false);
  const [error, setError] = useState(null);

  const runLiveScan = async () => {
    setIsSimulated(false);
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/v1/scan');
      setTelemetryData(response.data);
    } catch (err) {
      setError("Failed to connect to TraceChain Engine at http://127.0.0.1:8000");
    } finally {
      setLoading(false);
    }
  };

  const runThreatSimulation = async () => {
    setIsSimulated(true);
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/v1/simulate-threat');
      setTelemetryData(response.data);
    } catch (err) {
      setError("Failed to execute threat simulation.");
    } finally {
      setLoading(false);
    }
  };

  const filteredProcesses = telemetryData?.results?.filter(proc => 
    proc.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    proc.pid.toString().includes(searchTerm)
  ) || [];

  return (
    <div style={{ backgroundColor: '#0f172a', color: '#f8fafc', minHeight: '100vh', fontFamily: 'system-ui, sans-serif' }}>
      {/* Header Bar */}
      <header style={{ borderBottom: '1px solid #1e293b', padding: '1rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Shield style={{ color: '#38bdf8', width: '28px', height: '28px' }} />
          <h1 style={{ fontSize: '1.25rem', fontWeight: 'bold', margin: 0 }}>TraceChain Security Telemetry</h1>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button 
            onClick={runThreatSimulation}
            disabled={loading}
            style={{ 
              backgroundColor: '#dc2626', color: '#ffffff', border: 'none', padding: '0.5rem 1rem', 
              borderRadius: '0.375rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: '600' 
            }}
          >
            <Flame style={{ width: '16px', height: '16px' }} />
            Simulate Threat
          </button>
          <button 
            onClick={runLiveScan} 
            disabled={loading}
            style={{ 
              backgroundColor: '#0284c7', color: '#ffffff', border: 'none', padding: '0.5rem 1rem', 
              borderRadius: '0.375rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: '600' 
            }}
          >
            <RefreshCw style={{ width: '16px', height: '16px', animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            {loading ? 'Scanning Endpoint...' : 'Run Live Diagnostics'}
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto' }}>
        {error && (
          <div style={{ backgroundColor: '#450a0a', border: '1px solid #991b1b', color: '#fca5a5', padding: '1rem', borderRadius: '0.5rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <AlertTriangle />
            <span>{error}</span>
          </div>
        )}

        {/* System Overview Metric Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
          <div style={{ backgroundColor: '#1e293b', padding: '1.25rem', borderRadius: '0.5rem', border: '1px solid #334155' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8' }}>
              <span>Total Processes</span>
              <Activity style={{ width: '20px', height: '20px' }} />
            </div>
            <p style={{ fontSize: '2rem', fontWeight: 'bold', margin: '0.5rem 0 0 0' }}>
              {telemetryData ? telemetryData.total_analyzed : '--'}
            </p>
          </div>

          <div style={{ backgroundColor: '#1e293b', padding: '1.25rem', borderRadius: '0.5rem', border: '1px solid #334155' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8' }}>
              <span>High Threats</span>
              <AlertTriangle style={{ width: '20px', height: '20px', color: telemetryData?.high_threat_count > 0 ? '#ef4444' : '#22c55e' }} />
            </div>
            <p style={{ fontSize: '2rem', fontWeight: 'bold', margin: '0.5rem 0 0 0', color: telemetryData?.high_threat_count > 0 ? '#ef4444' : '#f8fafc' }}>
              {telemetryData ? telemetryData.high_threat_count : '--'}
            </p>
          </div>

          <div style={{ backgroundColor: '#1e293b', padding: '1.25rem', borderRadius: '0.5rem', border: '1px solid #334155' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8' }}>
              <span>System Status</span>
              <Server style={{ width: '20px', height: '20px' }} />
            </div>
            <p style={{ fontSize: '1.5rem', fontWeight: 'bold', margin: '0.75rem 0 0 0', color: telemetryData?.system_status === 'NORMAL' ? '#22c55e' : (telemetryData ? '#ef4444' : '#f8fafc') }}>
              {telemetryData ? telemetryData.system_status : 'READY'}
            </p>
          </div>
        </div>

        {/* View Selection Tabs */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <button 
            onClick={() => setActiveTab('table')}
            style={{
              backgroundColor: activeTab === 'table' ? '#0284c7' : '#1e293b',
              color: '#ffffff', border: '1px solid #334155', padding: '0.5rem 1rem',
              borderRadius: '0.375rem', cursor: 'pointer', fontSize: '0.875rem', fontWeight: '600'
            }}>
            Process Table
          </button>
          <button 
            onClick={() => setActiveTab('graph')}
            style={{
              backgroundColor: activeTab === 'graph' ? '#0284c7' : '#1e293b',
              color: '#ffffff', border: '1px solid #334155', padding: '0.5rem 1rem',
              borderRadius: '0.375rem', cursor: 'pointer', fontSize: '0.875rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '0.4rem'
            }}>
            <Network style={{ width: '16px', height: '16px' }} /> Visual Chain Graph
          </button>
        </div>

        {/* Tab Content Display */}
        {activeTab === 'graph' ? (
          <GraphProcessing isSimulated={isSimulated} />
        ) : (
          <div style={{ backgroundColor: '#1e293b', borderRadius: '0.5rem', border: '1px solid #334155', padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h2 style={{ fontSize: '1.1rem', fontWeight: '600', margin: 0, color: '#cbd5e1' }}>Telemetry Process Analysis</h2>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', backgroundColor: '#0f172a', border: '1px solid #334155', padding: '0.4rem 0.75rem', borderRadius: '0.375rem' }}>
                <Search style={{ width: '16px', height: '16px', color: '#64748b' }} />
                <input 
                  type="text" 
                  placeholder="Search process name or PID..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{ background: 'transparent', border: 'none', color: '#f8fafc', outline: 'none', fontSize: '0.875rem', width: '200px' }}
                />
              </div>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                    <th style={{ padding: '0.75rem' }}>PID</th>
                    <th style={{ padding: '0.75rem' }}>Process Name</th>
                    <th style={{ padding: '0.75rem' }}>User</th>
                    <th style={{ padding: '0.75rem' }}>Threat Level</th>
                    <th style={{ padding: '0.75rem' }}>Risk Score</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProcesses.length > 0 ? (
                    filteredProcesses.slice(0, 15).map((proc) => (
                      <tr key={proc.pid} style={{ borderBottom: '1px solid #1e293b' }}>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>{proc.pid}</td>
                        <td style={{ padding: '0.75rem', fontWeight: '500' }}>{proc.name}</td>
                        <td style={{ padding: '0.75rem', color: '#94a3b8' }}>{proc.username || 'SYSTEM'}</td>
                        <td style={{ padding: '0.75rem' }}>
                          <span style={{ 
                            padding: '0.2rem 0.5rem', borderRadius: '0.25rem', fontSize: '0.75rem', fontWeight: 'bold',
                            backgroundColor: proc.threat_level === 'HIGH' ? '#450a0a' : (proc.threat_level === 'MEDIUM' ? '#451a03' : '#064e3b'),
                            color: proc.threat_level === 'HIGH' ? '#fca5a5' : (proc.threat_level === 'MEDIUM' ? '#fdba74' : '#6ee7b7')
                          }}>
                            {proc.threat_level}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem', fontWeight: 'bold' }}>{proc.risk_score} / 100</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="5" style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
                        {telemetryData ? 'No matching processes found.' : 'Click "Run Live Diagnostics" to fetch live system processes.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}