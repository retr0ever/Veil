# Veil

A self-improving AI-powered firewall that continuously discovers new web attack techniques, red-teams itself, and auto-patches its own defences.

## Architecture

```
HTTP request → Veil WAF (Crusoe fast filter → Claude deep classifier)
  → Safe: forward to application
  → Malicious: block + log + update rules

Background agents:
  Peek (scout)    → discovers new web attack techniques (SQLi, XSS, RCE, etc.)
  Poke (red team) → tests Veil's own defences with attack payloads
  Patch (adapt)   → analyses bypasses and strengthens detection rules
```

## Stack

- **Backend:** Python / FastAPI / SQLite
- **Frontend:** React / TailwindCSS
- **AI:** Crusoe Inference API (fast filter) + Claude API (deep classifier + agents)

## Setup

### Backend

```bash
cd backend
cp .env.example .env  # add your API keys
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard at `http://localhost:5173`

## Tracks

- **Bluedot** (main) — Cybersecurity
- **Crusoe** — Inference API
- **Anthropic** — Claude
- **incident.io** — Adaptable Agent
- **SIG** — Best Use of Data
- **Patch** — Under 22

## Team

Hack Europe 2026 — Dublin
