#  TraceChain — Real-Time Security Telemetry & Threat Graph

TraceChain is a security telemetry engine that captures endpoint process execution trees, calculates heuristic threat scores, and renders real-time process dependency graphs for threat hunting.

---

## Initial Steps

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Backend Setup
\`\`\`bash
# Activate virtual environment
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch FastAPI Backend Engine
uvicorn backend.main:app --reload
\`\`\`

### 2. Frontend Setup
\`\`\`bash
cd frontend

# Install dependencies
npm install

# Launch React Dev Server
npm run dev
\`\`\`

---

## Repository Structure
\`\`\`text
tracechain/
├── agent/             # System telemetry collector (psutil)
├── backend/           # FastAPI engine & threat scoring rules
├── frontend/          # React + Vite + @xyflow/react dashboard
├── requirements.txt   # Python dependencies
└── README.md
\`\`\`


