
import requests
from agent.collector import TelemetryCollector

# 1. Capture system snapshot
collector = TelemetryCollector()
raw_snapshot = collector.capture_system_snapshot()
print(f"[+] Captured {len(raw_snapshot)} live processes.")

# 2. Send payload to FastAPI analysis engine
url = "http://127.0.0.1:8000/api/v1/analyze"
response = requests.post(url, json=raw_snapshot)

# 3. Print analysis report
if response.status_code == 200:
    data = response.json()
    print(f"\n[+] Server Response Status: {response.status_code} OK")
    print(f"[+] Total Analyzed: {data['total_analyzed']}")
    print(f"[+] High Threats Detected: {data['high_threat_count']}")
    print(f"[+] System Status: {data['system_status']}")
else:
    print(f"[-] Error: {response.status_code} - {response.text}")