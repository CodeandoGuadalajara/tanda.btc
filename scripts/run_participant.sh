#!/usr/bin/env bash
# Arranca el servidor participante.
# Lee variables desde .env.local si existe; las variables de entorno ya
# definidas tienen precedencia (no se sobreescriben).
#
# Variables requeridas:
#   SK_IDX            — índice del participante (0, 1 o 2)
#   SK_SEED           — semilla de la clave privada (string secreto)
#   BITCOIND_RPC_URL  — http://user:password@<host>:18443
#
# Opcional:
#   PORT              — puerto de escucha (default 8080)

set -euo pipefail

if [ -f .env.local ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' .env.local | grep -v '^$' | xargs)
fi

: "${SK_IDX:?Variable SK_IDX no definida}"
: "${SK_SEED:?Variable SK_SEED no definida}"
: "${BITCOIND_RPC_URL:?Variable BITCOIND_RPC_URL no definida}"

PORT="${PORT:-8080}"

# Asegura que el paquete tanda sea importable desde el directorio del repo
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}${SCRIPT_DIR}/.."

exec uvicorn tanda.api_participant:app --host 0.0.0.0 --port "$PORT"
