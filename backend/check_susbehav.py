from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class ConnectionModel(BaseModel):
    type: str
    laddr: Optional[str] = None
    raddr: Optional[str] = None
    status: Optional[str] = None

class ProcessModel(BaseModel):
    pid: int
    ppid: int
    name: str
    exe: Optional[str] = None
    cmdline: Optional[List[str]] = None
    username: Optional[str] = None
    create_time_iso: Optional[str] = None
    connections: List[ConnectionModel] = []

class ThreatAnalyzer:
    """Evaluates activity logs using deterministic rules mapped to attack patterns."""

    # Common test/reverse shell ports
    SUSPICIOUS_PORTS = {4444, 1337, 6667, 8888, 9001}

    def analyze(self, processes: List[ProcessModel]) -> List[Dict[str, Any]]:
        results = []

        for proc in processes:
            risk_score = 0
            rules_triggered = []

            # Rule 1: Execution from Temporary Directories
            if proc.exe and any(tmp in proc.exe.lower() for tmp in ["tmp", "temp", "appdata\\local\\temp"]):
                risk_score += 30
                rules_triggered.append({"rule": "TEMP_DIR_EXECUTION", "points": 30})

            # Rule 2: Suspicious Outbound Ports
            for conn in proc.connections:
                if conn.raddr:
                    try:
                        port = int(conn.raddr.split(":")[-1])
                        if port in self.SUSPICIOUS_PORTS:
                            risk_score += 25
                            rules_triggered.append({"rule": f"SUSPICIOUS_PORT_{port}", "points": 25})
                    except ValueError:
                        pass

            # Rule 3: Suspicious Shell Launch
            if proc.name.lower() in ["powershell.exe", "cmd.exe", "bash", "sh", "nc", "ncat"]:
                risk_score += 15
                rules_triggered.append({"rule": "SUSPICIOUS_SHELL_PROCESS", "points": 15})

            total_score = min(risk_score, 100)
            threat_level = "HIGH" if total_score >= 50 else ("MEDIUM" if total_score >= 20 else "LOW")

            results.append({
                "pid": proc.pid,
                "ppid": proc.ppid,
                "name": proc.name,
                "exe": proc.exe,
                "username": proc.username,
                "risk_score": total_score,
                "threat_level": threat_level,
                "rules_triggered": rules_triggered,
                "connections": [c.model_dump() for c in proc.connections]
            })

        return results