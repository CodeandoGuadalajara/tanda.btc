#!/usr/bin/env bash
# Regtest Bitcoin node setup for tanda-btc development.
# Works with Bitcoin Core compiled WITHOUT wallet support.
# Run once before tests; safe to re-run (idempotent).

set -euo pipefail

BITCOIN_CLI="bitcoin-cli -regtest"
RPC_USER="user"
RPC_PASS="password"
RPC_PORT=18443
DATA_DIR="${HOME}/.bitcoin"

# ── bitcoin.conf ──────────────────────────────────────────────────────────────
CONF="${DATA_DIR}/bitcoin.conf"
mkdir -p "${DATA_DIR}"

if [[ ! -f "${CONF}" ]]; then
  cat > "${CONF}" <<EOF
regtest=1
server=1
rpcuser=${RPC_USER}
rpcpassword=${RPC_PASS}
rpcport=${RPC_PORT}
fallbackfee=0.0001
txindex=1
EOF
  echo "[+] Created ${CONF}"
fi

# ── Start bitcoind if not running ─────────────────────────────────────────────
if ! ${BITCOIN_CLI} getblockchaininfo &>/dev/null; then
  echo "[+] Starting bitcoind in regtest mode..."
  bitcoind -daemon -regtest 2>/dev/null || true
  sleep 2
fi

# Wait for RPC to be ready
for i in $(seq 1 20); do
  if ${BITCOIN_CLI} getblockchaininfo &>/dev/null; then
    echo "[+] bitcoind is ready"
    break
  fi
  echo "    Waiting for bitcoind... (${i}/20)"
  sleep 1
done

# ── Mine initial blocks using Python (wallet-less) ────────────────────────────
# Bitcoin Core is compiled without wallet support; use the Python BitcoinRPC
# wrapper which falls back to getblocktemplate + bitcoin-util grind + submitblock.

HEIGHT=$(${BITCOIN_CLI} getblockcount)
echo "[+] Current height: ${HEIGHT}"

if [[ "${HEIGHT}" -lt 101 ]]; then
  NEEDED=$((101 - HEIGHT))
  echo "[+] Mining ${NEEDED} blocks to reach coinbase maturity..."
  python3 - <<PYEOF
from tanda.rpc import BitcoinRPC
rpc = BitcoinRPC(rpc_user="${RPC_USER}", rpc_password="${RPC_PASS}", rpc_port=${RPC_PORT})
rpc.mine(${NEEDED})
print(f"[+] Mined ${NEEDED} blocks")
PYEOF
fi

echo ""
echo "=== Regtest ready ==="
echo "  Blocks : $(${BITCOIN_CLI} getblockcount)"
echo ""
echo "  Note: participant wallets are not needed — the e2e tests fund"
echo "  participants directly via raw transactions using deterministic keys."
echo "  Run:  python -m pytest tests/test_e2e_regtest.py -v -s"
