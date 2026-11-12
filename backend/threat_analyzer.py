"""TraceChain threat analyzer: rule-based, explainable and chain-aware.

Drop-in replacement for backend/threat_analyzer.py. All previous output keys are
kept; new keys are: breakdown, in_chain, parent_name, is_isolated is added by main.py.
"""
import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class ConnectionModel(BaseModel):
    type: str = "tcp"
    laddr: Optional[str] = ""
    raddr: Optional[str] = None
    status: Optional[str] = ""


class ProcessModel(BaseModel):
    pid: int
    ppid: Optional[int] = None
    name: str
    exe: Optional[str] = ""
    cmdline: Optional[List[str]] = Field(default_factory=list)
    username: Optional[str] = "SYSTEM"
    create_time_iso: Optional[str] = ""
    connections: Optional[List[ConnectionModel]] = Field(default_factory=list)


OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
               "onenote.exe", "acrord32.exe", "acrobat.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
          "cscript.exe", "mshta.exe"}
SYSTEM_BINARIES = {"cmd.exe", "powershell.exe", "svchost.exe", "explorer.exe",
                   "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe"}
SUSPICIOUS_DIRS = {"temp", "tmp", "downloads"}
C2_PORTS = {"4444", "1337", "8888", "6667", "31337"}

# (regex, label, points, MITRE). (?<!\S) = "start of a token", which works for
# flags like -w / -nop where \b fails (both '-' and ' ' are non-word characters).
CMD_PATTERNS = [
    (r"(?<!\S)-w(?:indowstyle)?\s+hidden\b", "Hidden window", 15, "T1564.003"),
    (r"(?<!\S)-nop(?:rofile)?\b", "No PowerShell profile", 10, "T1059.001"),
    (r"(?<!\S)-ep\s+bypass\b|executionpolicy\s+bypass", "Execution policy bypass", 15, "T1059.001"),
    (r"(?<!\S)-e(?:nc(?:odedcommand)?)?\s+[a-z0-9+/=]{20,}", "Encoded command", 25, "T1027"),
    (r"\biex\b|downloadstring|downloadfile|invoke-webrequest", "Download-and-execute", 25, "T1105"),
]

# Single source of truth for the Rule Engine tab (served by /api/v1/rules)
RULES = [
    {"id": "R001", "name": "Execution from Temp/Downloads folder", "mitre": "T1204", "points": "+35"},
    {"id": "R002", "name": "Suspicious command-line flags", "mitre": "T1059.001", "points": "+10 to +40"},
    {"id": "R003", "name": "External connection to high-risk port", "mitre": "T1571", "points": "+45"},
    {"id": "R005", "name": "System binary name outside Windows folder", "mitre": "T1036", "points": "+30"},
    {"id": "R010", "name": "Office/PDF app spawned a shell", "mitre": "T1059", "points": "+40"},
    {"id": "R011", "name": "Ancestor of a high-risk process", "mitre": "-", "points": "+25 / +10"},
]


def _split_addr(addr: str) -> Tuple[str, str]:
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), port


def _is_external(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified)


class ThreatAnalyzer:
    HIGH_AT = 60
    MEDIUM_AT = 25

    def __init__(self, allowlist: Optional[List[str]] = None):
        # Full exe paths (any case) that are trusted and never scored
        self.allowlist = {a.lower() for a in (allowlist or [])}
        # strongest indicators first, so the 40-point cap trims the weakest ones
        self._cmd = [(re.compile(p), label, pts, mitre)
                     for p, label, pts, mitre in sorted(CMD_PATTERNS, key=lambda x: -x[2])]

    def describe_rules(self) -> List[Dict]:
        return RULES

    # ------------------------------------------------------------------ public
    def analyze(self, processes: List[ProcessModel]) -> List[Dict]:
        by_pid = {p.pid: p for p in processes}
        states: Dict[int, Dict] = {}
        for proc in processes:
            st = {"proc": proc, "findings": [], "tags": [], "in_chain": False}
            states[proc.pid] = st
            if proc.exe and proc.exe.lower() in self.allowlist:
                st["tags"].append("ALLOWLISTED")
                continue
            self._apply_rules(st, by_pid.get(proc.ppid))
        self._propagate(states, by_pid)
        return [self._finalize(st, by_pid) for st in states.values()]

    # ------------------------------------------------------------------- rules
    @staticmethod
    def _add(st, rule_id, points, text, mitre, tag):
        st["findings"].append({"rule_id": rule_id, "points": points,
                               "text": text, "mitre": mitre})
        if tag and tag not in st["tags"]:
            st["tags"].append(tag)

    def _apply_rules(self, st, parent: Optional[ProcessModel]):
        proc = st["proc"]
        exe = proc.exe or ""
        name = proc.name.lower()

        # R001: directory segments, not substrings ("Template App" is fine)
        parts = re.split(r"[\\/]+", exe.lower())
        if any(p in SUSPICIOUS_DIRS for p in parts[:-1]):
            self._add(st, "R001", 35, f"Runs from a temporary/download folder: {exe}",
                      "T1204", "SUSPICIOUS_PATH")

        # R002: command-line flags, capped at 40 points in total
        cmd_str = " ".join(proc.cmdline or []).lower()
        budget = 40
        for rx, label, pts, mitre in self._cmd:
            if budget > 0 and rx.search(cmd_str):
                pts = min(pts, budget)
                budget -= pts
                self._add(st, "R002", pts, f"Suspicious command-line: {label}",
                          mitre, "OBFUSCATED_CMD")

        # R003: external IPs only, once per unique remote address, max 45 points
        seen, c2_budget = set(), 45
        for conn in proc.connections or []:
            if not conn.raddr:
                continue
            if "NETWORK_ACTIVE" not in st["tags"]:
                st["tags"].append("NETWORK_ACTIVE")
            host, port = _split_addr(conn.raddr)
            if conn.raddr in seen or c2_budget <= 0:
                continue
            seen.add(conn.raddr)
            if port in C2_PORTS and _is_external(host):
                pts = min(45, c2_budget)
                c2_budget -= pts
                self._add(st, "R003", pts,
                          f"Connected to external host on high-risk port: {conn.raddr}",
                          "T1571", "RISKY_PORT")

        # R005: well-known system binary name running outside C:\Windows
        low = exe.lower()
        if name in SYSTEM_BINARIES and "\\" in exe and not low.startswith("c:\\windows\\"):
            self._add(st, "R005", 30,
                      f"'{proc.name}' is a system binary name but runs from {exe}",
                      "T1036", "MASQUERADE")

        # R010: document app launching a shell
        if parent and parent.name.lower() in OFFICE_APPS and name in SHELLS:
            self._add(st, "R010", 40,
                      f"{parent.name} started {proc.name} (documents should not launch shells)",
                      "T1059", "OFFICE_SHELL")

    # --------------------------------------------------------------- chain logic
    @staticmethod
    def _pre_score(st) -> int:
        return min(sum(f["points"] for f in st["findings"]), 100)

    def _propagate(self, states, by_pid):
        """Give ancestors of HIGH processes a bonus so the whole chain lights up."""
        bonus: Dict[int, Tuple[int, str]] = {}
        for st in states.values():
            if self._pre_score(st) < self.HIGH_AT:
                continue
            st["in_chain"] = True
            child, seen = st["proc"], {st["proc"].pid}
            for depth in range(1, 7):
                parent = by_pid.get(child.ppid)
                if parent is None or parent.pid in seen:
                    break
                seen.add(parent.pid)
                states[parent.pid]["in_chain"] = True
                pts = {1: 25, 2: 10}.get(depth, 0)
                if pts > bonus.get(parent.pid, (0, ""))[0]:
                    bonus[parent.pid] = (pts, f"Ancestor of high-risk process "
                                              f"{st['proc'].name} (PID {st['proc'].pid})")
                child = parent
        for pid, (pts, text) in bonus.items():
            st = states[pid]
            current = self._pre_score(st)
            if current >= self.HIGH_AT:
                continue
            pts = min(pts, self.HIGH_AT - 1 - current)  # propagation never makes HIGH
            if pts > 0:
                self._add(st, "R011", pts, text, None, "CHAIN_MEMBER")

    # ------------------------------------------------------------------- output
    def _finalize(self, st, by_pid) -> Dict:
        proc = st["proc"]
        findings = st["findings"]
        score = self._pre_score(st)
        if score >= self.HIGH_AT:
            level, rec = "HIGH", ("Review this process and its parent chain, then isolate it "
                                  "if the activity is not expected.")
        elif score >= self.MEDIUM_AT:
            level, rec = "MEDIUM", "Inspect the parent process origin and verify the network destination."
        else:
            level, rec = "LOW", "Normal background process. No action required."

        reasons = [f["text"] for f in findings]
        parent = by_pid.get(proc.ppid)
        return {
            "pid": proc.pid,
            "ppid": proc.ppid,
            "parent_name": parent.name if parent else None,
            "name": proc.name,
            "exe": proc.exe or "N/A",
            "cmdline": proc.cmdline or [],
            "username": proc.username or "SYSTEM",
            "create_time": proc.create_time_iso,
            "connections": [c.model_dump() for c in (proc.connections or [])],
            "risk_score": score,
            "threat_level": level,
            "in_chain": st["in_chain"],
            "breakdown": findings,
            "reasons": reasons,
            "tags": st["tags"],
            "human_summary": " ⚡ ".join(reasons) if reasons
                             else "Standard system operation. No anomalous behavior detected.",
            "recommendation": rec,
        }