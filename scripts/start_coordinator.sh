#!/usr/bin/env bash
set -euo pipefail
# Uso: ./scripts/start_coordinator.sh <IP_P0> <IP_P1> [IP_P2 ...]
#
# Levanta en esta PC:
#   - bitcoind           : nodo Bitcoin Core regtest (accesible por todos)
#   - cln-coordinator    : nodo CLN coordinador (abre canales a participantes)
#   - coordinator script : orquesta bootstrap + N rondas via hold invoices
#
# Variables opcionales:
#   INTERACTIVE=1          → pausa entre rondas esperando Enter
#   CONTRIBUTION_SATS=N    → aportación por participante en sats  (default 10000)
#   ROUND=k                → correr solo la ronda k  (0-indexed)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

if [[ $# -lt 2 ]]; then
  echo "Uso: $0 <IP_P0> <IP_P1> [IP_P2 ...]"
  echo "  Ejemplo: $0 192.168.1.10 192.168.1.11 192.168.1.12"
  echo "  Con pausa: INTERACTIVE=1 $0 192.168.1.10 192.168.1.11 192.168.1.12"
  exit 1
fi

N=$#
IPS=("$@")
INTERACTIVE=${INTERACTIVE:-0}
CONTRIBUTION_SATS=${CONTRIBUTION_SATS:-10000}
ROUND=${ROUND:-}

echo "▶ Coordinador — $N participantes, $CONTRIBUTION_SATS sats/ronda"
for i in "${!IPS[@]}"; do
  echo "   P$i → ${IPS[$i]}:8080"
done
echo ""

# ── 1. Infraestructura en background ─────────────────────────────────────────
docker compose -f "$ROOT/deploy/coord.yml" up --build -d

# ── 2. Esperar cln-coordinator healthy ────────────────────────────────────────
echo "Esperando cln-coordinator..."
CONTAINER=$(docker compose -f "$ROOT/deploy/coord.yml" ps -q cln-coordinator)
for i in $(seq 1 60); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "starting")
  if [[ "$STATUS" == "healthy" ]]; then
    echo "  cln-coordinator listo"
    break
  fi
  echo "  [$i/60] $STATUS..."
  sleep 3
done

# ── 3. Exportar env vars para el script coordinator ───────────────────────────
export N_PARTICIPANTS=$N
export CONTRIBUTION_SATS
export INTERACTIVE
export ROUND
for i in "${!IPS[@]}"; do
  export "P${i}_URL=http://${IPS[$i]}:8080"
  export "P${i}_CLN_HOST=${IPS[$i]}"
  export "P${i}_CLN_P2P_PORT=9735"
done

# ── 4. Lanzar coordinator script ──────────────────────────────────────────────
if [[ "$INTERACTIVE" == "1" ]]; then
  docker compose \
    -f "$ROOT/deploy/coord.yml" \
    -f "$ROOT/deploy/run.yml" \
    run --rm -it coordinator
else
  docker compose \
    -f "$ROOT/deploy/coord.yml" \
    -f "$ROOT/deploy/run.yml" \
    up coordinator
fi
