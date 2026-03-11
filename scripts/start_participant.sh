#!/usr/bin/env bash
set -euo pipefail
# Uso: ./scripts/start_participant.sh [IP_COORDINADOR]
#
# Levanta en esta PC:
#   - cln-participant  : nodo CLN propio (regtest), conectado al bitcoind del coordinador
#   - participant-api  : FastAPI en :8080 que recibe órdenes del coordinador
#
# IP_COORDINADOR: IP del PC-Coord donde corre bitcoind  (default: 192.168.1.10)
#
# Variables opcionales:
#   BITCOIND_HOST   — igual que el argumento posicional
#   CLN_P2P_PORT    — puerto P2P del nodo CLN  (default: 9735)
#   API_PORT        — puerto HTTP de la API    (default: 8080)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

BITCOIND_HOST=${1:-${BITCOIND_HOST:-192.168.1.10}}

echo "▶ Participante iniciando (bitcoind en $BITCOIND_HOST:18443)"
echo "  API disponible en http://$(hostname -I | awk '{print $1}'):${API_PORT:-8080}"
echo ""

BITCOIND_HOST="$BITCOIND_HOST" \
  docker compose -f "$ROOT/deploy/participant.yml" up --build
