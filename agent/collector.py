import time
import psutil
from typing import List, Dict, Any

class TelemetryCollector:
    """Gathers live system activity logs (processes, network connections, execution metadata)."""

    def capture_system_snapshot(self) -> List[Dict[str, Any]]:
        """Takes a snapshot of all active programs and open network ports."""
        activity_logs = []

        for proc in psutil.process_iter([
            'pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time'
        ]):
            try:
                process_data = proc.info
                
                # Format creation time
                process_data['create_time_iso'] = time.strftime(
                    '%Y-%m-%dT%H:%M:%SZ', time.gmtime(process_data['create_time'])
                ) if process_data.get('create_time') else None

                # Collect network connection footprints
                active_connections = []
                try:
                    for conn in proc.net_connections(kind='inet'):
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
                        active_connections.append({
                            "type": str(conn.type),
                            "laddr": laddr,
                            "raddr": raddr,
                            "status": conn.status
                        })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                process_data['connections'] = active_connections
                activity_logs.append(process_data)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return activity_logs

if __name__ == "__main__":
    collector = TelemetryCollector()
    snapshot = collector.capture_system_snapshot()
    print(f"[+] {len(snapshot)} Logs of running programs captured successfully ")