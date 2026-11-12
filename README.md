# TraceChain

**Real-time security telemetry and process-chain visualization**

TraceChain is a hackathon prototype for exploring endpoint process activity. It collects process metadata, applies explainable rule-based threat scoring, and visualizes parent–child process relationships so an analyst can follow how a suspicious process started.

> **Prototype notice:** TraceChain is a demonstration project, not a production endpoint detection and response (EDR) product. Its detection rules are heuristic and may produce false positives or miss threats. The attack simulation uses mock data and does not execute malware or make network connections. The isolate action is simulated; it only marks a process in the UI and does not stop it.

## What it currently does

- Collects a local snapshot of running processes with process IDs, parent IDs, executable paths, command lines, usernames, start times, and available network connections.
- Scores process activity using explainable rules and displays the findings that contributed to each score.
- Groups detections with their process ancestors to help show the broader chain.
- Displays process data in a React dashboard with a process table, analytics, alert logs, a rule list, and an interactive process graph.
- Includes a safe, repeatable simulated attack chain for demonstrations.
- Supports manual rescans and optional three-second refreshes of live results.

## Detection rules

The prototype currently includes rules for:

| Rule | Behavior |
| --- | --- |
| R001 | Execution from a Temp, tmp, or Downloads folder |
| R002 | Suspicious command-line options and download-and-execute patterns |
| R003 | Connections to external IP addresses on selected high-risk ports |
| R005 | A known system-binary name running outside the Windows folder |
| R010 | An Office or PDF application starting a shell |
| R011 | Ancestors of a high-risk process, to highlight its process chain |

Scores are grouped into LOW, MEDIUM, and HIGH levels. These heuristics are intentionally small and should not be treated as a complete or authoritative security assessment.

## Requirements

- Python 3.10 or newer
- Node.js 18 or newer
- npm

## Run locally on Windows

Open two terminals from the project folder.

### 1. Start the backend

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn backend.main:app --reload
```

The API runs at `http://127.0.0.1:8000` by default. You can check that it is running at `http://127.0.0.1:8000/`.

### 2. Start the frontend

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, usually `http://localhost:5173`.

## Try the safe simulation

1. Open the dashboard in the browser.
2. Select **Simulate Attack**.
3. Review the incident summary and process graph.
4. Select a process to inspect its score breakdown and evidence.
5. Open **Rule Engine**, **Alert Logs**, and **Process Analytics** to explore the other views.

The simulated scenario contains four mock processes. In simulation mode, the dashboard shows that sample instead of combining it with the live process list. Selecting **Back to live system** or **Rescan** returns to the live snapshot.

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/` | Backend health check |
| `GET` | `/api/v1/scan` | Analyze a live process snapshot |
| `GET` | `/api/v1/scan?simulate=true` | Analyze the mock process chain |
| `POST` | `/api/v1/simulate-threat` | Start a fresh simulation and clear its demo isolation state |
| `GET` | `/api/v1/rules` | Return the rules shown in the dashboard |
| `GET` | `/api/v1/graph-data` | Return graph nodes and edges |
| `POST` | `/api/v1/isolate-process/{pid}` | Mark a process as isolated in demo state; does not terminate it |
| `POST` | `/api/v1/ingest` | Accept and analyze process telemetry for a host |

Interactive API documentation is available at `http://127.0.0.1:8000/docs` while the backend is running.

## Project structure

```text
tracechain/
├── agent/                 # Process and connection telemetry collector
├── backend/               # FastAPI app and threat analysis rules
├── frontend/              # React + Vite dashboard and graph
├── requirements.txt       # Python dependencies
├── test_pipeline.py       # Example collector-to-backend pipeline
└── README.md
```

## Current limitations and next steps

This is an early prototype. The rule set is limited, heuristic, and not validated against a broad dataset. More rules can be added and tuned over time, then evaluated against known benign and suspicious examples to improve accuracy and reduce false positives. Other future improvements may include stronger telemetry validation, configurable allowlists, and production-ready authentication and deployment controls.

## Security and privacy note

Process telemetry can contain usernames, executable paths, command lines, and network details. Review what is collected before sharing scan output. The backend is intended for local development and does not provide authentication; keep it on localhost and do not expose it to untrusted networks.
