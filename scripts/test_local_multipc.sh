#!/usr/bin/env bash
set -euo pipefail
# Prueba local de los scripts multi-PC: simula N participantes en una sola
# máquina usando COMPOSE_PROJECT_NAME distintos y puertos desplazados.
#
# Topología (N=3 por defecto):
#   tanda-btc       → coord:  bitcoind :18443  +  cln-coordinator :9735
#   tanda-p0        → P0:     cln :9736        +  api :8080
#   tanda-p1        → P1:     cln :9737        +  api :8081
#   tanda-p2        → P2:     cln :9738        +  api :8082
#
# Variables opcionales:
#   N=3                → número de participantes  (default 3)
#   CONTRIBUTION_SATS  → sats por participante     (default 10000)
#   INTERACTIVE=1      → pausa entre rondas esperando Enter
#   ROUND=k            → ejecutar solo la ronda k  (0-indexed)
#   KEEP=1             → no borrar containers al salir (útil para debug)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

N=${N:-3}
CONTRIBUTION_SATS=${CONTRIBUTION_SATS:-10000}
INTERACTIVE=${INTERACTIVE:-0}
ROUND=${ROUND:-}
KEEP=${KEEP:-0}

# Puerto base para participantes (coord ocupa 9735)
BASE_P2P=9736
BASE_API=8080

# ── Helpers ───────────────────────────────────────────────────────────────────

cleanup() {
  local rc=$?
  [[ "$KEEP" == "1" ]] && { echo "KEEP=1 — dejando containers activos"; exit $rc; }
  echo ""
  echo "▶ Limpiando stacks..."
  for i in $(seq 0 $((N - 1))); do
    COMPOSE_PROJECT_NAME="tanda-p${i}" \
      docker compose -f "$ROOT/deploy/participant.yml" down --volumes 2>/dev/null || true
  done
  docker compose \
    -f "$ROOT/deploy/coord.yml" \
    -f "$ROOT/deploy/coord.local.yml" \
    -f "$ROOT/deploy/run.yml" \
    -f "$ROOT/deploy/run.local.yml" \
    down --volumes 2>/dev/null || true
  exit $rc
}
trap cleanup EXIT INT TERM

wait_healthy() {
  local container="$1"
  local label="$2"
  echo "  Esperando $label..."
  for i in $(seq 1 60); do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "missing")
    [[ "$STATUS" == "healthy" ]] && { echo "    ✓ $label listo"; return 0; }
    echo "    [$i/60] $STATUS..."
    sleep 3
  done
  echo "ERROR: $label no llegó a healthy en 180s" >&2
  return 1
}

# ── Banner ────────────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════╗"
echo "║  test_local_multipc — $N participantes en una sola PC  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  coord  → bitcoind :18443  +  cln-coordinator :9735"
for i in $(seq 0 $((N - 1))); do
  P2P=$((BASE_P2P + i))
  API=$((BASE_API + i))
  echo "  P$i     → cln :${P2P}         +  api :${API}"
done
echo ""

# ── 1. Coordinador (bitcoind + cln-coordinator) ────────────────────────────────

echo "▶ Levantando coordinador (bitcoind + cln-coordinator)..."
docker compose \
  -f "$ROOT/deploy/coord.yml" \
  -f "$ROOT/deploy/coord.local.yml" \
  up --build -d --remove-orphans

COORD_CONTAINER=$(docker compose -f "$ROOT/deploy/coord.yml" ps -q cln-coordinator)
wait_healthy "$COORD_CONTAINER" "cln-coordinator"
echo ""

# ── 2. Participantes (en paralelo) ────────────────────────────────────────────

echo "▶ Levantando participantes..."
for i in $(seq 0 $((N - 1))); do
  P2P=$((BASE_P2P + i))
  API=$((BASE_API + i))
  echo "  Iniciando tanda-p${i} (CLN :${P2P}  API :${API})..."
  COMPOSE_PROJECT_NAME="tanda-p${i}" \
  BITCOIND_HOST=host.docker.internal \
  CLN_P2P_PORT="$P2P" \
  API_PORT="$API" \
    docker compose -f "$ROOT/deploy/participant.yml" up --build -d
done
echo ""

echo "▶ Esperando que todos los participant-api estén healthy..."
for i in $(seq 0 $((N - 1))); do
  CONTAINER=$(COMPOSE_PROJECT_NAME="tanda-p${i}" \
    docker compose -f "$ROOT/deploy/participant.yml" ps -q participant-api)
  wait_healthy "$CONTAINER" "tanda-p${i}/participant-api"
done
echo ""

# ── 3. Exportar env vars ───────────────────────────────────────────────────────

export N_PARTICIPANTS=$N
export CONTRIBUTION_SATS
export INTERACTIVE
export ROUND

for i in $(seq 0 $((N - 1))); do
  API=$((BASE_API + i))
  P2P=$((BASE_P2P + i))
  export "P${i}_URL=http://host.docker.internal:${API}"
  export "P${i}_CLN_HOST=host.docker.internal"
  export "P${i}_CLN_P2P_PORT=${P2P}"
done

# ── 4. Lanzar coordinator script ───────────────────────────────────────────────

echo "▶ Lanzando coordinator script ($N participantes, $CONTRIBUTION_SATS sats/ronda)..."
for i in $(seq 0 $((N - 1))); do
  API=$((BASE_API + i))
  echo "   P${i} → http://host.docker.internal:${API}"
done
echo ""

if [[ "$INTERACTIVE" == "1" ]]; then
  docker compose \
    -f "$ROOT/deploy/coord.yml" \
    -f "$ROOT/deploy/run.yml" \
    -f "$ROOT/deploy/run.local.yml" \
    run --rm -it coordinator
else
  docker compose \
    -f "$ROOT/deploy/coord.yml" \
    -f "$ROOT/deploy/run.yml" \
    -f "$ROOT/deploy/run.local.yml" \
    up coordinator
fi
