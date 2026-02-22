<p align="center">
  <img src="veil.png" alt="Veil" width="400" />
</p>

<h3 align="center">AI-Powered Web Application Firewall</h3>

<p align="center">
  Protect your vibecoded apps with our self-improving reverse-proxy WAF that discovers new attack techniques, red-teams itself, and auto-patches highlighted vulnerabilities.
  <p align="center">
    <a href="https://veil.keanuc.net" target="_blank"><b>Live demo: veil.keanuc.net</b></a>
  </p>
  
---

## How it works

1. Point your domain's DNS (CNAME) to Veil.
2. All traffic flows through the Veil proxy, where every request is classified in real time:

```
Incoming request
  → Regex classifier (instant, blocks obvious attacks)
  → Proxy to your origin (< 100ms overhead)
  → Background LLM pipeline (Crusoe fast filter → Claude deep analysis)
  → Threat intelligence + IP reputation check
  → If malicious: block + log + update rules

Background agents (continuous loop):
  Peek (scout)  → discovers new web attack techniques
  Poke (red)    → tests Veil's own defences with generated payloads
  Patch (adapt) → analyses bypasses and strengthens detection rules
```

## Stack

- **Backend:** Go / Chi / PostgreSQL
- **Frontend:** React / Vite / TailwindCSS
- **AI:** Crusoe Inference API (fast filter) + Claude via AWS Bedrock (deep classifier + agents)
- **Infra:** Caddy (on-demand TLS) + Docker Compose

## Setup (local development)

### Backend

```bash
cd backend
cp .env.example .env   # add your API keys
go run ./cmd/server/main.go
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Docker (production)

```bash
cd backend
docker compose up -d
```

### Local development

```bash
./dev.sh   # starts Postgres, Go backend, and frontend
```

Dashboard at `http://localhost:5173`

## Features

- **DNS-based onboarding** — CNAME your domain, Veil handles the rest (auto-TLS via Caddy)
- **Async LLM classification** — regex runs inline (~0.1ms), full LLM pipeline runs in background so requests are never delayed
- **Self-improving agents** — Peek discovers attacks, Poke tests defences, Patch adapts rules
- **IP threat intelligence** — automatic blocking from threat feeds + decision engine (ban, captcha, throttle)
- **Real-time dashboard** — live request feed, threat analytics, agent activity via SSE
- **GitHub OAuth** — sign in with GitHub, optional repo connection for code-level findings
- **Site-scoped data** — each project gets its own isolated dashboard and analytics

## Tracks

- **Bluedot** (main) — Cybersecurity
- **Crusoe** — Inference API
- **Anthropic** — Claude
- **incident.io** — Adaptable Agent
- **SIG** — Best Use of Data
- **Patch** — Under 22

## Team

**Keanu Czirjak (@keanucz)** - worked on the Golang backend, the agentic pipeline and inference engine

**Justyna Przyborska (@justyna-przy)** - worked on designing the frontend and making it beautiful

**Selin Abdullazade (@retr0ever)** - worked on the initial Python backend and core concept & idea

**Cian McNamara (@Bocksa)** - worked on implementing analytics and compliance dashboard views
