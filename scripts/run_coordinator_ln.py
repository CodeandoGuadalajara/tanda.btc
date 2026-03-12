#!/usr/bin/env python3
"""
Docker LN demo coordinator: runs tanda rounds via Lightning Network hold invoices.

Protocol per round:
  1. Coordinator generates N preimages P_i, payment_hashes H_i = sha256(P_i).
  2. Coordinator creates N hold invoices (one per participant) via its CLN node.
  3. Each participant pays their hold invoice → HTLC locked in coordinator node.
  4. Coordinator verifies all N HTLCs are in state "accepted".
  5. Coordinator pays the round winner N × contribution_sats via regular invoice.
  6. Coordinator settles all hold invoices with each P_i → recovers N × contribution_sats.

Fallback: if a participant doesn't pay, coordinator cancels all hold invoices.

Environment variables:
  N_PARTICIPANTS       — number of participants (default 3)
  BITCOIND_RPC_URL     — http://user:pass@host:18443
  CLN_COORDINATOR_RPC  — unix socket path for the coordinator CLN node
  CLN_P{i}_RPC         — optional unix socket path for participant i CLN node
                         (only used in bootstrap for local setups; if omitted,
                          the coordinator polls participant HTTP APIs instead)
  P{i}_URL             — FastAPI participant API URL (http://host:port)
  P{i}_CLN_P2P_PORT    — participant i's CLN P2P port (default 9736+i)
  P{i}_CLN_HOST        — participant i's hostname/IP (default 127.0.0.1)
  CONTRIBUTION_SATS    — per-participant contribution in satoshis (default 10000)
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
from bitcoinrpc.authproxy import AuthServiceProxy
from embit.ec import PrivateKey as _PK
from embit.networks import NETWORKS as _NETS

from tanda.rpc import BitcoinRPC
from tanda.lnrpc import CLNRpc


# ── Configuration ──────────────────────────────────────────────────────────────

N = int(os.environ.get("N_PARTICIPANTS", "3"))
N_CYCLES = int(os.environ.get("N_CYCLES", "1"))
CONTRIBUTION_SATS = int(os.environ.get("CONTRIBUTION_SATS", "10000"))
BITCOIND_URL = os.environ.get("BITCOIND_RPC_URL", "http://user:password@127.0.0.1:18443")

CLN_COORD_RPC = os.environ.get("CLN_COORDINATOR_RPC", "/cln/coordinator/regtest/lightning-rpc")

# Participant CLN sockets — optional; if empty, bootstrap uses HTTP /node_info
CLN_P_RPCS = [os.environ.get(f"CLN_P{i}_RPC", "") for i in range(N)]

# Participant FastAPI URLs
P_URLS = [
    os.environ.get(f"P{i}_URL", f"http://127.0.0.1:{8080 + i}")
    for i in range(N)
]

# Participant CLN P2P connection info (for coordinator to open channels)
P_CLN_HOSTS = [os.environ.get(f"P{i}_CLN_HOST", "127.0.0.1") for i in range(N)]
P_CLN_P2P_PORTS = [
    int(os.environ.get(f"P{i}_CLN_P2P_PORT", str(9736 + i)))
    for i in range(N)
]

# Channel parameters
CHANNEL_CAPACITY_SAT = 200_000
PUSH_MSAT = 150_000_000   # 150k sats → participant outbound capacity

# Execution mode
# INTERACTIVE=1  → pause between rounds, wait for Enter
# ROUND=k        → run only round k (0-indexed); skips bootstrap if channels exist
INTERACTIVE = os.environ.get("INTERACTIVE", "0") == "1"
SINGLE_ROUND = os.environ.get("ROUND", "")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_rpc(url: str) -> BitcoinRPC:
    p = urllib.parse.urlparse(url)
    return BitcoinRPC(
        rpc_user=p.username,
        rpc_password=p.password,
        rpc_host=p.hostname,
        rpc_port=p.port or 18443,
    )


def wait_bitcoind(rpc: BitcoinRPC, retries: int = 60) -> None:
    print("Waiting for bitcoind...", flush=True)
    for i in range(retries):
        try:
            AuthServiceProxy(rpc._base_url, timeout=5).getblockcount()
            print("  bitcoind ready", flush=True)
            return
        except Exception as e:
            print(f"  [{i+1}/{retries}] {type(e).__name__}: {e}", flush=True)
            time.sleep(1)
    raise RuntimeError("bitcoind not available after 60 s")


def wait_cln(cln: CLNRpc, name: str, retries: int = 120) -> dict:
    print(f"Waiting for CLN node {name}...", flush=True)
    for i in range(retries):
        try:
            info = cln.get_info()
            print(f"  {name} ready  id={info['id'][:16]}...", flush=True)
            return info
        except Exception as e:
            print(f"  [{i+1}/{retries}] {type(e).__name__}: {e}", flush=True)
            time.sleep(1)
    raise RuntimeError(f"CLN node {name} not available after {retries} s")


def wait_participant_api(url: str, retries: int = 60) -> dict:
    print(f"Waiting for participant API {url}...", flush=True)
    for i in range(retries):
        try:
            r = httpx.get(f"{url}/health", timeout=5)
            if r.status_code == 200:
                data = r.json()
                print(f"  {url} ready  pubkey={data['pubkey_hex'][:16]}...", flush=True)
                return data
        except Exception as e:
            print(f"  [{i+1}/{retries}] {type(e).__name__}: {e}", flush=True)
        time.sleep(1)
    raise RuntimeError(f"Participant API {url} not available after 60 s")


def get_participant_node_id(url: str, cln_rpc_path: str) -> str:
    """
    Get participant's CLN node_id.
    Prefers direct socket (local) → falls back to HTTP /node_info (remote).
    """
    if cln_rpc_path:
        try:
            info = CLNRpc(cln_rpc_path).get_info()
            return info["id"]
        except Exception:
            pass
    # Fallback: HTTP API
    r = httpx.get(f"{url}/node_info", timeout=10)
    r.raise_for_status()
    return r.json()["id"]


def wait_cln_synced(cln: CLNRpc, rpc: BitcoinRPC, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    cln_height = 0
    while time.time() < deadline:
        target = rpc.get_block_height()
        info = cln.get_info()
        cln_height = info.get("blockheight", 0)
        syncing = info.get("warning_bitcoind_sync") or info.get("warning_lightningd_sync")
        if cln_height >= target and not syncing:
            return
        time.sleep(1)
    raise RuntimeError(f"CLN not synced after {timeout}s (cln={cln_height}, target={target})")


def wait_cln_funds(cln: CLNRpc, min_sats: int, label: str = "CLN", timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        funds = cln.list_funds()
        confirmed_sats = sum(
            (o.get("amount_msat", 0) // 1000 if "amount_msat" in o else o.get("value", 0))
            for o in funds.get("outputs", [])
            if o.get("status") == "confirmed"
        )
        if confirmed_sats >= min_sats:
            print(f"  {label} wallet ready: {confirmed_sats} confirmed sats", flush=True)
            return
        time.sleep(1)
    raise RuntimeError(f"{label} wallet has < {min_sats} confirmed sats after {timeout}s")


def wait_channels_normal(cln: CLNRpc, n_expected: int, retries: int = 120) -> None:
    print(f"Waiting for {n_expected} channels to reach CHANNELD_NORMAL...", flush=True)
    for i in range(retries):
        channels = cln.list_peer_channels()
        normal_peers = {c.get("peer_id") for c in channels if c.get("state") == "CHANNELD_NORMAL"}
        if len(normal_peers) >= n_expected:
            print(f"  {n_expected} channels CHANNELD_NORMAL", flush=True)
            return
        print(f"  [{i+1}/{retries}] {len(normal_peers)}/{n_expected} channels normal", flush=True)
        time.sleep(2)
    raise RuntimeError(f"Channels did not reach CHANNELD_NORMAL after {retries * 2} s")


def wait_all_accepted(cln_coord: CLNRpc, payment_hashes: list[str], timeout: int = 120) -> None:
    n = len(payment_hashes)
    ph_set = set(payment_hashes)
    print(f"  Waiting for {n} HTLCs to be accepted...", flush=True)
    deadline = time.time() + timeout
    count = 0
    while time.time() < deadline:
        held = cln_coord.get_incoming_htlc_hashes()
        count = len(held & ph_set)
        print(f"    {count}/{n} HTLCs accepted", flush=True)
        if count >= n:
            return
        time.sleep(1)
    raise TimeoutError(f"Only {count}/{n} HTLCs accepted after {timeout} s")


# ── Bootstrap ──────────────────────────────────────────────────────────────────

def bootstrap(rpc: BitcoinRPC, cln_coord: CLNRpc) -> None:
    print("\n--- Bootstrap ---", flush=True)

    # Mine 101 blocks if needed
    current_height = rpc.get_block_height()
    coord_addr = rpc._default_mine_addr()
    if current_height < 101:
        print("Mining 101 blocks to coordinator address...", flush=True)
        rpc.mine(101, address=coord_addr)

    _mine_wif = _PK(hashlib.sha256(b"regtest_mine_key").digest()).wif(network=_NETS["regtest"])

    # Fund coordinator CLN on-chain
    cln_coord_addr = cln_coord.new_address()
    print(f"CLN coordinator on-chain address: {cln_coord_addr}", flush=True)

    all_utxos = rpc.scan_utxos(coord_addr)
    current_height = rpc.get_block_height()
    mature = [u for u in all_utxos if int(u.get("height", 0)) <= current_height - 100]
    if not mature:
        raise RuntimeError("No mature coinbases — mine more blocks first")

    fund_btc = round(N * CHANNEL_CAPACITY_SAT / 1e8 + 0.001, 8)
    fee_btc = 0.0001
    selected, total_in = [], 0.0
    for u in mature:
        selected.append(u)
        total_in += float(u["amount"])
        if total_in >= fund_btc + fee_btc:
            break
    if total_in < fund_btc + fee_btc:
        raise RuntimeError(
            f"Insufficient mature coinbases: have {total_in:.8f} BTC, "
            f"need {fund_btc + fee_btc:.8f} BTC"
        )

    change_btc = round(total_in - fund_btc - fee_btc, 8)
    outputs = {cln_coord_addr: fund_btc}
    if change_btc > 0.00000546:
        outputs[coord_addr] = change_btc

    base = AuthServiceProxy(rpc._base_url)
    inputs  = [{"txid": u["txid"], "vout": u["vout"]} for u in selected]
    prevtxs = [{
        "txid": u["txid"], "vout": u["vout"],
        "scriptPubKey": (
            u["scriptPubKey"] if isinstance(u["scriptPubKey"], str)
            else u["scriptPubKey"]["hex"]
        ),
        "amount": float(u["amount"]),
    } for u in selected]

    raw_tx = base.createrawtransaction(inputs, outputs)
    signed = base.signrawtransactionwithkey(raw_tx, [_mine_wif], prevtxs)
    if not signed.get("complete"):
        raise RuntimeError(f"Funding tx signing incomplete: {signed}")
    base.sendrawtransaction(signed["hex"])
    print(f"  Funded CLN coordinator with {fund_btc} BTC", flush=True)
    rpc.mine(3)

    wait_cln_synced(cln_coord, rpc)
    wait_cln_funds(cln_coord, min_sats=int(fund_btc * 1e8) - 10_000, label="CLN coordinator")

    # Wait for participant APIs then get their node info
    print("\nWaiting for participant APIs...", flush=True)
    for url in P_URLS:
        wait_participant_api(url)

    # Connect coordinator → each participant CLN node and open channels.
    # Participant node_id is fetched via HTTP /node_info (works local and remote).
    for i in range(N):
        p_node_id = get_participant_node_id(P_URLS[i], CLN_P_RPCS[i])
        host = P_CLN_HOSTS[i]
        port = P_CLN_P2P_PORTS[i]
        print(f"  Connecting to P{i} ({p_node_id[:16]}...) at {host}:{port}", flush=True)
        try:
            cln_coord.connect(p_node_id, host, port)
        except Exception as e:
            print(f"    connect warning: {e}", flush=True)

        print(
            f"  Opening channel to P{i}: "
            f"capacity={CHANNEL_CAPACITY_SAT} sat, push={PUSH_MSAT // 1000} sat...",
            flush=True,
        )
        cln_coord.fund_channel(p_node_id, CHANNEL_CAPACITY_SAT, push_msat=PUSH_MSAT)
        # Mine 1 block so the change UTXO from this fundchannel TX is confirmed
        # before the next fundchannel call.  CLN only spends confirmed UTXOs.
        if i < N - 1:
            rpc.mine(1)
            wait_cln_synced(cln_coord, rpc)

    print("Mining 6 blocks to confirm channels...", flush=True)
    rpc.mine(6)
    wait_cln_synced(cln_coord, rpc)
    wait_channels_normal(cln_coord, N)


# ── Round execution ────────────────────────────────────────────────────────────

def run_round_ln(
    round_idx: int,
    winner_idx: int,
    cln_coord: CLNRpc,
    p_urls: list[str],
    contribution_sats: int,
) -> None:
    n = len(p_urls)

    # One preimage per invoice — CLN rejects duplicate payment_hashes
    preimages = [os.urandom(32) for _ in range(n)]
    payment_hashes = [hashlib.sha256(p).hexdigest() for p in preimages]

    print(f"  payment_hashes[0]={payment_hashes[0][:16]}...", flush=True)

    # Create N hold invoices (BoltzExchange/hold: takes payment_hash + amount)
    print(f"  Creating {n} hold invoices...", flush=True)
    invoices = []
    for i in range(n):
        try:
            inv = cln_coord.holdinvoice(
                payment_hash_hex=payment_hashes[i],
                amount_msat=contribution_sats * 1000,
            )
        except Exception as exc:
            raise RuntimeError(f"holdinvoice creation failed for P{i}: {exc}")
        invoices.append(inv)
        print(f"    P{i} bolt11={inv.get('bolt11', '')[:40]}...", flush=True)

    # Dispatch payments concurrently (CLN pay blocks until settle/cancel)
    print(f"  Dispatching payments from {n} participants (concurrent)...", flush=True)

    def _pay(url: str, bolt11: str) -> None:
        r = httpx.post(f"{url}/pay_invoice", json={"bolt11": bolt11}, timeout=120)
        r.raise_for_status()

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=n)
    futs = {
        executor.submit(_pay, url, inv["bolt11"]): i
        for i, (url, inv) in enumerate(zip(p_urls, invoices))
    }

    wait_all_accepted(cln_coord, payment_hashes)

    # Pay the winner
    pot_msat = contribution_sats * n * 1000
    winner_url = p_urls[winner_idx]
    print(f"  Paying P{winner_idx} pot ({contribution_sats * n} sats)...", flush=True)
    r = httpx.post(
        f"{winner_url}/create_invoice",
        json={"amount_msat": pot_msat, "label": f"pot-round-{round_idx}"},
        timeout=30,
    )
    r.raise_for_status()
    cln_coord.pay(r.json()["bolt11"])
    print(f"  P{winner_idx} received pot ({contribution_sats * n} sats)", flush=True)

    # Settle — BoltzExchange/hold: settleholdinvoice takes preimage
    print("  Settling hold invoices...", flush=True)
    for p in preimages:
        cln_coord.settle_holdinvoice(p.hex())

    errors = []
    for fut, i in futs.items():
        try:
            fut.result(timeout=30)
            print(f"    P{i} payment confirmed", flush=True)
        except Exception as exc:
            errors.append(f"P{i}: {exc}")
    executor.shutdown(wait=False)
    if errors:
        raise RuntimeError(f"Round {round_idx} payment errors: {errors}")

    print(
        f"  ✓ Round {round_idx} complete. "
        f"P{winner_idx} won {contribution_sats * n} sats.",
        flush=True,
    )


# ── Renewal ────────────────────────────────────────────────────────────────────

def collect_renewals(
    cycle: int,
    p_urls: list[str],
    contribution_sats: int,
    cln_coord: CLNRpc,
) -> bool:
    """
    Propose a new cycle to all participants and verify each acceptance
    cryptographically via CLN signmessage/checkmessage.

    Canonical message: tanda-renew:cycle={N}:sats={S}:coordinator={node_id}
    Both sides construct this message independently from the request fields.
    Returns True only if every participant accepts and their signature verifies.
    Winner order is fixed (participant k always wins round k).
    """
    coordinator_id = cln_coord.get_info()["id"]
    message = f"tanda-renew:cycle={cycle}:sats={contribution_sats}:coordinator={coordinator_id}"
    print(f"\n--- Renewal: proposing cycle {cycle} ---", flush=True)
    print(f"  message: {message}", flush=True)

    for i, url in enumerate(p_urls):
        # Get participant node_id for signature verification
        p_node_id = get_participant_node_id(url, CLN_P_RPCS[i])

        r = httpx.post(
            f"{url}/renew",
            json={
                "cycle": cycle,
                "contribution_sats": contribution_sats,
                "coordinator_id": coordinator_id,
            },
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()

        if not data.get("accept", False):
            print(f"  P{i} declined cycle {cycle}", flush=True)
            return False

        zbase = data.get("zbase", "")
        if not cln_coord.check_message(message, zbase, p_node_id):
            print(f"  P{i} signature verification FAILED", flush=True)
            return False

        print(f"  P{i} accepted and signed cycle {cycle} (zbase={zbase[:16]}...)", flush=True)

    return True


# ── Main ───────────────────────────────────────────────────────────────────────

def print_balances(p_urls: list[str]) -> None:
    print("\n--- Balances ---", flush=True)
    for i, url in enumerate(p_urls):
        try:
            r = httpx.get(f"{url}/health", timeout=10)
            for ch in r.json().get("channels", []):
                local_msat = ch.get("to_us_msat", ch.get("msatoshi_to_us", "?"))
                print(f"  P{i} local balance: {local_msat} msat", flush=True)
        except Exception as e:
            print(f"  P{i} balance check failed: {e}", flush=True)


def _wait_for_enter(msg: str) -> None:
    """Block until the user presses Enter. Works in both TTY and pipe (skips if not a TTY)."""
    if sys.stdin.isatty():
        input(msg)
    else:
        print(f"{msg} [non-interactive: continuing automatically]", flush=True)


def main() -> None:
    rpc = _make_rpc(BITCOIND_URL)
    cln_coord = CLNRpc(CLN_COORD_RPC)

    wait_bitcoind(rpc)
    wait_cln(cln_coord, "cln-coordinator")

    # ── Single-round mode: ROUND=k ──────────────────────────────────────────────
    if SINGLE_ROUND != "":
        k = int(SINGLE_ROUND)
        if k < 0 or k >= N:
            raise ValueError(f"ROUND={k} out of range [0, {N - 1}]")
        bootstrap(rpc, cln_coord)
        print(f"\n=== Round {k}: P{k} wins ===", flush=True)
        run_round_ln(k, k, cln_coord, P_URLS, CONTRIBUTION_SATS)
        print_balances(P_URLS)
        return

    # ── Full run (automatic or interactive) ─────────────────────────────────────
    bootstrap(rpc, cln_coord)

    if INTERACTIVE:
        print_balances(P_URLS)
        _wait_for_enter("\n▶ Bootstrap completo. Presiona Enter para iniciar la Ronda 0… ")

    for cycle in range(N_CYCLES):
        if cycle > 0:
            if not collect_renewals(cycle, P_URLS, CONTRIBUTION_SATS, cln_coord):
                print(f"\n✗ Cycle {cycle} rejected by one or more participants. Stopping.", flush=True)
                break
            if INTERACTIVE:
                _wait_for_enter(f"\n▶ Ciclo {cycle} confirmado. Presiona Enter para iniciar… ")

        print(f"\n{'=' * 10} Cycle {cycle} {'=' * 10}", flush=True)
        for k in range(N):
            winner_idx = k
            round_label = f"cycle={cycle} round={k}"
            print(f"\n=== {round_label}: P{winner_idx} wins ===", flush=True)
            run_round_ln(cycle * N + k, winner_idx, cln_coord, P_URLS, CONTRIBUTION_SATS)
            print_balances(P_URLS)

            if INTERACTIVE and k < N - 1:
                _wait_for_enter(f"\n▶ Ronda {k} completa. Presiona Enter para la Ronda {k + 1}… ")

        print(f"\n✓ Cycle {cycle} complete ({N} rounds).", flush=True)

    print(f"\n✓ All {N_CYCLES} cycle(s) complete.", flush=True)


if __name__ == "__main__":
    main()
