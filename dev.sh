#!/usr/bin/env bash
# dev.sh — start Postgres, Go backend, and frontend for local development
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

PIDS=()

cleanup() {
  trap - EXIT INT TERM
  echo ""
  echo "Shutting down..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
  exit 0
}
trap cleanup EXIT INT TERM

# ── Postgres ────────────────────────────────────────────────────────
if docker ps --format '{{.Names}}' | grep -q '^veil-db$'; then
  echo "[db] Postgres already running"
elif docker ps -a --format '{{.Names}}' | grep -q '^veil-db$'; then
  echo "[db] Starting existing veil-db container"
  docker start veil-db
else
  echo "[db] Creating Postgres container"
  docker run -d --name veil-db \
    -e POSTGRES_DB=veil \
    -e POSTGRES_USER=veil \
    -e POSTGRES_PASSWORD=veil \
    -p 5432:5432 \
    postgres:16-alpine
fi

# Wait for Postgres to be ready
echo "[db] Waiting for Postgres..."
for i in $(seq 1 30); do
  if docker exec veil-db pg_isready -U veil -q 2>/dev/null; then
    echo "[db] Postgres ready"
    break
  fi
  sleep 1
done

# ── Go backend ──────────────────────────────────────────────────────
echo "[go] Starting Go backend on http://localhost:8080"
(
  cd "$ROOT/go-backend"
  export DATABASE_URL="postgres://veil:veil@localhost:5432/veil?sslmode=disable"
  # Load .env (check go-backend/ first, then project root)
  # Temporarily disable nounset — .env values may contain $ characters
  set +u
  for envfile in "$ROOT/go-backend/.env" "$ROOT/.env"; do
    if [ -f "$envfile" ]; then
      set -a
      source "$envfile"
      set +a
      break
    fi
  done
  set -u
  go run ./cmd/server/main.go
) &
PIDS+=($!)

# ── Frontend ────────────────────────────────────────────────────────
echo "[ui] Starting frontend on http://localhost:5173"
(
  cd "$ROOT/frontend"
  npm run dev
) &
PIDS+=($!)

# Wait a moment then show status
sleep 3
echo ""
echo "============================================"
echo "  Veil dev environment running"
echo "  Backend:  http://localhost:8080"
echo "  Frontend: http://localhost:5173"
echo "  Postgres: localhost:5432"
echo "  Health:   curl http://localhost:8080/ping"
echo "============================================"
echo ""

wait
