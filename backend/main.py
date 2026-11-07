from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from backend.check_susbehav import ThreatAnalyzer, ProcessModel
from agent.collector import TelemetryCollector

app = FastAPI(title="TraceChain Analysis Engine", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = ThreatAnalyzer()
collector = TelemetryCollector()

@app.get("/")
def health_check():
    return {"status": "active", "system": "TraceChain Analysis Engine"}

@app.get("/api/v1/scan")
def scan_live_system():
    """Captures live system processes and runs threat analysis directly."""
    raw_snapshot = collector.capture_system_snapshot()
    validated_processes = [ProcessModel(**p) for p in raw_snapshot]
    analysis_results = analyzer.analyze(validated_processes)
    high_threats = [p for p in analysis_results if p["risk_score"] >= 50]
    
    return {
        "total_analyzed": len(analysis_results),
        "high_threat_count": len(high_threats),
        "system_status": "CRITICAL" if high_threats else "NORMAL",
        "results": analysis_results
    }

@app.get("/api/v1/simulate-threat")
def simulate_threat():
    """Injects a fake suspicious reverse-shell process to verify threat detection."""
    mock_processes = [
        {
            "pid": 9999,
            "ppid": 1000,
            "name": "powershell.exe",
            "exe": "C:\\Users\\HP\\AppData\\Local\\Temp\\malicious_payload.exe",
            "cmdline": ["powershell.exe", "-nop", "-w", "hidden", "-c", "IEX"],
            "username": "DESKTOP-DCGTKQB\\HP",
            "create_time_iso": "2026-11-06T23:30:00",
            "connections": [
                {
                    "type": "tcp",
                    "laddr": "192.168.1.15:52134",
                    "raddr": "45.33.32.156:4444",
                    "status": "ESTABLISHED"
                }
            ]
        },
        {
            "pid": 1000,
            "ppid": 4,
            "name": "cmd.exe",
            "exe": "C:\\Windows\\System32\\cmd.exe",
            "cmdline": ["cmd.exe"],
            "username": "DESKTOP-DCGTKQB\\HP",
            "create_time_iso": "2026-11-06T23:29:00",
            "connections": []
        }
    ]
    
    validated = [ProcessModel(**p) for p in mock_processes]
    analysis = analyzer.analyze(validated)
    
    return {
        "total_analyzed": len(analysis),
        "high_threat_count": len([p for p in analysis if p["risk_score"] >= 50]),
        "system_status": "CRITICAL",
        "results": analysis
    }

@app.get("/api/v1/graph-data")
def get_graph_data(simulate: bool = False):
    """Converts live system snapshot or simulated threat into React Flow nodes and edges."""
    if simulate:
        raw_snapshot = [
            {
                "pid": 9999,
                "ppid": 1000,
                "name": "powershell.exe",
                "exe": "C:\\Users\\HP\\AppData\\Local\\Temp\\malicious_payload.exe",
                "cmdline": ["powershell.exe", "-nop", "-w", "hidden", "-c", "IEX"],
                "username": "DESKTOP-DCGTKQB\\HP",
                "create_time_iso": "2026-11-06T23:30:00",
                "connections": [
                    {
                        "type": "tcp",
                        "laddr": "192.168.1.15:52134",
                        "raddr": "45.33.32.156:4444",
                        "status": "ESTABLISHED"
                    }
                ]
            },
            {
                "pid": 1000,
                "ppid": 4,
                "name": "cmd.exe",
                "exe": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": ["cmd.exe"],
                "username": "DESKTOP-DCGTKQB\\HP",
                "create_time_iso": "2026-11-06T23:29:00",
                "connections": []
            }
        ]
    else:
        raw_snapshot = collector.capture_system_snapshot()

    validated = [ProcessModel(**p) for p in raw_snapshot]
    analysis = analyzer.analyze(validated)
    
    nodes = []
    edges = []
    
    for idx, proc in enumerate(analysis[:25]):
        is_threat = proc["threat_level"] in ["HIGH", "MEDIUM"]
        
        nodes.append({
            "id": str(proc["pid"]),
            "data": { 
                "label": f"{proc['name']}\nPID: {proc['pid']} | Risk: {proc['risk_score']}"
            },
            "position": { "x": (idx % 4) * 250, "y": (idx // 4) * 140 },
            "style": {
                "background": "#450a0a" if is_threat else "#1e293b",
                "color": "#fca5a5" if is_threat else "#f8fafc",
                "border": f"2px solid {'#ef4444' if is_threat else '#334155'}",
                "borderRadius": "8px",
                "padding": "12px",
                "fontSize": "12px",
                "fontWeight": "bold",
                "width": 200
            }
        })
        
        if proc["ppid"] and any(p["pid"] == proc["ppid"] for p in analysis[:25]):
            edges.append({
                "id": f"e-{proc['ppid']}-{proc['pid']}",
                "source": str(proc["ppid"]),
                "target": str(proc["pid"]),
                "animated": is_threat,
                "style": { "stroke": "#ef4444" if is_threat else "#38bdf8", "strokeWidth": 2 }
            })
            
    return {"nodes": nodes, "edges": edges}

@app.post("/api/v1/analyze")
def analyze_telemetry(processes: List[ProcessModel]):
    analysis_results = analyzer.analyze(processes)
    high_threats = [p for p in analysis_results if p["risk_score"] >= 50]
    
    return {
        "total_analyzed": len(analysis_results),
        "high_threat_count": len(high_threats),
        "system_status": "CRITICAL" if high_threats else "NORMAL",
        "results": analysis_results
    }