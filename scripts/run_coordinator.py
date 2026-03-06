#!/usr/bin/env python3
"""
Docker demo coordinator: runs all 3 tanda rounds via HTTP to isolated containers.

Rounds:
  0 — cooperative  (MuSig2 keypath)  : all 3 sign → P0 claims pot
  1 — HTLC fallback (leaf1)           : P0 "refuses" → P1 claims after T_CLAIM blocks
  2 — refund fallback (leaf2)         : P2 "disappears" → P0+P1 refund after T_REFUND blocks

Environment variables (set by docker-compose):
  BITCOIND_RPC_URL — http://user:pass@bitcoind:18443
  AMOUNT_BTC       — per-participant contribution (default 0.1)
  T_CLAIM          — block timelock for HTLC path (default 5)
  T_REFUND         — block timelock for refund path (default 10)
"""

from __future__ import annotations

import os
import sys

# Allow running as `python scripts/run_coordinator.py` from the repo root
# without needing PYTHONPATH to be set externally.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import time
import urllib.parse
from io import BytesIO

import hashlib
import coincurve
import httpx
from bitcoinrpc.authproxy import AuthServiceProxy
from embit.ec import PublicKey
from embit.script import Script

from tanda.rpc import BitcoinRPC
from tanda.coordinator import Coordinator, TandaParams
from tanda.musig2 import (
    AggNonce,
    PubNonce,
    SessionContext,
    key_agg,
    nonce_agg,
    partial_sig_agg,
    apply_tweak,
)
from tanda.protocol import (
    UTXO,
    taproot_tweak,
    compute_taproot_sighash,
    build_claim_tx,
    build_htlc_claim_tx,
    build_refund_tx,
    make_keypath_witness,
    make_refund_witness,
    build_control_block,
    btc_to_sats,
    REGTEST,
)


# ── Configuration ──────────────────────────────────────────────────────────────

AMOUNT_BTC = float(os.environ.get("AMOUNT_BTC", "0.1"))
T_CLAIM = int(os.environ.get("T_CLAIM", "5"))
T_REFUND = int(os.environ.get("T_REFUND", "10"))
K_MIN = 2

BITCOIND_URL = os.environ.get("BITCOIND_RPC_URL", "http://user:password@bitcoind:18443")

P_URLS = [
    os.environ.get("P0_URL", "http://192.168.100.85:8080"),
    os.environ.get("P1_URL", "http://192.168.100.61:8080"),
    os.environ.get("P2_URL", "http://192.168.100.97:8082"),
]


# ── RPC helpers ────────────────────────────────────────────────────────────────

def _make_rpc(url: str, wallet: str | None = None) -> BitcoinRPC:
    p = urllib.parse.urlparse(url)
    return BitcoinRPC(
        rpc_user=p.username,
        rpc_password=p.password,
        rpc_host=p.hostname,
        rpc_port=p.port or 18443,
        wallet=wallet,
    )


# ── Wait helpers ───────────────────────────────────────────────────────────────

def wait_bitcoind(rpc: BitcoinRPC, retries: int = 60) -> None:
    print("Waiting for bitcoind...", flush=True)
    for i in range(retries):
        try:
            # Use a short timeout so a hang doesn't stall for 30 s per retry
            AuthServiceProxy(rpc._base_url, timeout=5).getblockcount()
            print("  bitcoind ready", flush=True)
            return
        except Exception as e:
            print(f"  [{i+1}/{retries}] {type(e).__name__}: {e}", flush=True)
            time.sleep(1)
    raise RuntimeError("bitcoind not available after 60 s")


def wait_participant(url: str, retries: int = 60) -> dict:
    print(f"Waiting for {url}...", flush=True)
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
    raise RuntimeError(f"Participant {url} not available after 60 s")


# ── UTXO helpers ───────────────────────────────────────────────────────────────

def scan_utxos(
    rpc: BitcoinRPC,
    address: str,
    expected_n: int,
    amount_sats: int,
    script_pubkey: bytes,
    max_retries: int = 30,
) -> list[UTXO]:
    """Poll scantxoutset until expected_n UTXOs appear, mining if needed."""
    for attempt in range(max_retries):
        raw = rpc.scan_utxos(address)
        utxos = [
            UTXO(
                txid=u["txid"],
                vout=u["vout"],
                amount_sats=round(float(u["amount"]) * 100_000_000),
                script_pubkey=(
                    bytes.fromhex(u["scriptPubKey"])
                    if isinstance(u.get("scriptPubKey"), str)
                    else bytes.fromhex(u["scriptPubKey"]["hex"])
                ),
            )
            for u in raw
            if round(float(u["amount"]) * 100_000_000) >= amount_sats * 0.99
        ]
        if len(utxos) >= expected_n:
            return utxos[:expected_n]
        if attempt < max_retries - 1:
            rpc.mine(1)
            time.sleep(0.3)
    raise TimeoutError(f"Expected {expected_n} UTXOs at {address}, found {len(utxos)}")


def tx_to_hex(tx) -> str:
    buf = BytesIO()
    tx.write_to(buf)
    return buf.getvalue().hex()


def utxos_to_json(utxos: list[UTXO]) -> list[dict]:
    return [
        {
            "txid": u.txid,
            "vout": u.vout,
            "amount_sats": u.amount_sats,
            "script_pubkey_hex": u.script_pubkey.hex(),
        }
        for u in utxos
    ]


def p2tr_addr(pk_bytes: bytes) -> str:
    xonly = PublicKey.parse(pk_bytes).xonly()
    spk = Script(bytes([0x51, 0x20]) + xonly)
    return spk.address(network=REGTEST)


def agg_nonce_from_hex(hex_str: str) -> AggNonce:
    b = bytes.fromhex(hex_str)
    return AggNonce(R1=coincurve.PublicKey(b[:33]), R2=coincurve.PublicKey(b[33:]))


def pub_nonce_from_hex(hex_str: str) -> PubNonce:
    b = bytes.fromhex(hex_str)
    return PubNonce(R1=coincurve.PublicKey(b[:33]), R2=coincurve.PublicKey(b[33:]))


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    rpc = _make_rpc(BITCOIND_URL)

    # ── 1. Wait for all services ───────────────────────────────────────────────
    wait_bitcoind(rpc)
    health = [wait_participant(url) for url in P_URLS]
    pubkeys = [bytes.fromhex(h["pubkey_hex"]) for h in health]

    print("\nParticipants:", flush=True)
    for i, h in enumerate(health):
        print(f"  P{i}: {h['pubkey_hex'][:24]}...", flush=True)

    # ── 2. Bootstrap: mine 101 blocks, fund participants (wallet-less) ─────────
    print("\n--- Bootstrap ---", flush=True)

    coord_addr = rpc._default_mine_addr()
    print("Mining 101 blocks to coordinator address...", flush=True)
    rpc.mine(101, address=coord_addr)

    # Derive WIF for the deterministic mining key (same seed as _default_mine_addr)
    from embit.ec import PrivateKey as _PK
    from embit.networks import NETWORKS as _NETS
    _mine_wif = _PK(hashlib.sha256(b"regtest_mine_key").digest()).wif(network=_NETS["regtest"])

    # Only use mature coinbases (depth >= 100)
    current_height = rpc.get_block_height()
    all_utxos = rpc.scan_utxos(coord_addr)
    mature = [u for u in all_utxos
              if int(u.get("height", 0)) <= current_height - 100]
    if not mature:
        raise RuntimeError("No mature coinbases — mine more blocks first")

    # Collect all wallet addresses first
    wallet_addrs = []
    for i, url in enumerate(P_URLS):
        r = httpx.get(f"{url}/wallet_address", timeout=10)
        if not r.content:
            raise RuntimeError(f"P{i} ({url}) vacío en /wallet_address — revisa logs del participante")
        wallet_addrs.append(r.json()["address"])

    # Each participant needs enough for all N rounds plus the per-tx fee (0.0001)
    # per-round actual fee is 5000 sats (0.00005) but the UTXO selector checks >= amount+0.0001
    n_rounds = len(P_URLS)
    fund_per_participant = round(n_rounds * AMOUNT_BTC + n_rounds * 0.0001, 8)
    print(f"Funding participants ({fund_per_participant} BTC each = {n_rounds} rounds)...", flush=True)

    # Fund all participants in one transaction to avoid coinbase maturity issues
    u = mature[0]
    spk = u["scriptPubKey"] if isinstance(u["scriptPubKey"], str) else u["scriptPubKey"]["hex"]
    fee_btc = 0.0001
    change_btc = round(float(u["amount"]) - fund_per_participant * len(P_URLS) - fee_btc, 8)
    outputs = {addr: fund_per_participant for addr in wallet_addrs}
    if change_btc > 0.00000546:
        outputs[coord_addr] = change_btc

    base = AuthServiceProxy(rpc._base_url)
    raw_tx = base.createrawtransaction([{"txid": u["txid"], "vout": u["vout"]}], outputs)
    prevtxs = [{"txid": u["txid"], "vout": u["vout"], "scriptPubKey": spk,
                "amount": float(u["amount"])}]
    signed = base.signrawtransactionwithkey(raw_tx, [_mine_wif], prevtxs)
    if not signed.get("complete"):
        raise RuntimeError(f"Funding tx signing incomplete: {signed}")
    base.sendrawtransaction(signed["hex"])
    for i, addr in enumerate(wallet_addrs):
        print(f"  Sent {fund_per_participant} BTC → P{i} ({addr[:24]}...)", flush=True)
    rpc.mine(1)  # confirm funding tx

    # ── 3. Tanda setup ────────────────────────────────────────────────────────
    print("\n--- Tanda Setup ---", flush=True)
    params = TandaParams(
        n_participants=3,
        amount_btc=AMOUNT_BTC,
        t_contribution=3,
        t_claim=T_CLAIM,
        t_refund=T_REFUND,
        k_min=K_MIN,
        winner_order=[0, 1, 2],
    )
    coord = Coordinator(rpc, params, pubkeys)
    setup = coord.setup()

    # Distribute per-round parameters to participants.
    # The round winner additionally receives their HTLC preimage.
    for k in range(3):
        rs = setup.rounds[k]
        winner_idx = params.winner_order[k]
        base_payload = {
            "round_idx": k,
            "pubkeys": [pk.hex() for pk in pubkeys],
            "htlc_hash_hex": rs.htlc_hash.hex(),
            "internal_key_xonly_hex": rs.scripts.internal_key_xonly.hex(),
            "merkle_root_hex": rs.scripts.merkle_root.hex(),
        }
        for i, url in enumerate(P_URLS):
            payload = dict(base_payload)
            if i == winner_idx:
                payload["preimage_hex"] = rs.htlc_preimage.hex()
            httpx.post(f"{url}/setup", json=payload, timeout=10)
    print("Setup distributed to all participants.", flush=True)

    # ── Round 0 ────────────────────────────────────────────────────────────────
    print("\n=== Round 0: Cooperative MuSig2 (P0 wins) ===", flush=True)
    run_round0_cooperative(rpc, setup, params, pubkeys)

    # ── Round 1 ────────────────────────────────────────────────────────────────
    print("\n=== Round 1: HTLC fallback (P1 wins, P0 refuses) ===", flush=True)
    run_round1_htlc(rpc, setup, params, pubkeys)

    # ── Round 2 ────────────────────────────────────────────────────────────────
    print("\n=== Round 2: Collective refund (P2 disappears) ===", flush=True)
    run_round2_refund(rpc, setup, params, pubkeys)

    print("\n✓ All 3 rounds complete.", flush=True)


# ── Round 0: cooperative keypath spend ────────────────────────────────────────

def run_round0_cooperative(rpc, setup, params, pubkeys):
    rs = setup.rounds[0]
    address = rs.scripts.address
    spk = rs.scripts.script_pubkey.data   # raw 34-byte P2TR scriptPubKey

    # Contributions from all 3 participants
    print("  Requesting contributions...", flush=True)
    for i, url in enumerate(P_URLS):
        r = httpx.post(f"{url}/contribute",
                       json={"address": address, "amount_btc": AMOUNT_BTC},
                       timeout=30)
        r.raise_for_status()
        print(f"    P{i} txid={r.json()['txid'][:16]}...", flush=True)
    rpc.mine(1)

    utxos = scan_utxos(rpc, address, 3, btc_to_sats(AMOUNT_BTC), spk)
    for i, u in enumerate(utxos):
        rs.contributions[i] = u

    winner_addr = p2tr_addr(pubkeys[0])
    tx = build_claim_tx(utxos, winner_addr)
    kac = rs.key_agg_ctx   # already has Taproot tweak applied by coordinator.setup()
    agg_pk_hex = kac.agg_pk.hex()

    # Sign each input separately (each has a distinct BIP-341 sighash)
    print("  MuSig2 signing...", flush=True)
    for inp_idx in range(len(tx.vin)):
        sighash = compute_taproot_sighash(tx, inp_idx, utxos)

        # Collect fresh public nonces from all participants
        pub_nonces: list[PubNonce] = []
        for url in P_URLS:
            r = httpx.post(f"{url}/nonce",
                           json={"round_idx": 0, "inp_idx": inp_idx,
                                 "agg_pk_hex": agg_pk_hex},
                           timeout=10)
            r.raise_for_status()
            pub_nonces.append(pub_nonce_from_hex(r.json()["pub_nonce_hex"]))

        agg_nonce = nonce_agg(pub_nonces)
        agg_nonce_hex = agg_nonce.serialize().hex()

        # Collect partial signatures from all participants
        psigs: list[int] = []
        for url in P_URLS:
            r = httpx.post(f"{url}/sign_claim",
                           json={"round_idx": 0, "inp_idx": inp_idx,
                                 "agg_nonce_hex": agg_nonce_hex,
                                 "sighash_hex": sighash.hex()},
                           timeout=10)
            r.raise_for_status()
            psigs.append(r.json()["psig"])

        session = SessionContext(agg_nonce=agg_nonce, key_agg_ctx=kac, msg=sighash)
        final_sig = partial_sig_agg(psigs, session)
        tx.vin[inp_idx].witness = make_keypath_witness(final_sig)
        print(f"    input {inp_idx} signed", flush=True)

    tx_hex = tx_to_hex(tx)
    result = rpc.test_mempool_accept(tx_hex)
    if not result[0]["allowed"]:
        raise RuntimeError(f"Round 0 claim tx rejected: {result[0].get('reject-reason')}")

    txid = rpc.send_raw_transaction(tx_hex)
    rpc.mine(1)
    print(f"  ✓ P0 claimed pot. txid={txid}", flush=True)


# ── Round 1: HTLC fallback ─────────────────────────────────────────────────────

def run_round1_htlc(rpc, setup, params, pubkeys):
    rs = setup.rounds[1]
    address = rs.scripts.address
    spk = rs.scripts.script_pubkey.data

    # Contributions
    print("  Requesting contributions...", flush=True)
    for i, url in enumerate(P_URLS):
        r = httpx.post(f"{url}/contribute",
                       json={"address": address, "amount_btc": AMOUNT_BTC},
                       timeout=30)
        r.raise_for_status()
        print(f"    P{i} txid={r.json()['txid'][:16]}...", flush=True)
    rpc.mine(1)

    utxos = scan_utxos(rpc, address, 3, btc_to_sats(AMOUNT_BTC), spk)
    for i, u in enumerate(utxos):
        rs.contributions[i] = u

    # Cooperative path fails: P0 refuses to respond (simulated by skipping nonce requests)
    print(f"  P0 refuses to sign. Mining T_CLAIM={T_CLAIM} blocks...", flush=True)
    rpc.mine(T_CLAIM)

    # P1 (round winner) claims via HTLC scriptpath (leaf1)
    winner_addr = p2tr_addr(pubkeys[1])
    tx = build_htlc_claim_tx(utxos, winner_addr)
    htlc_script = rs.scripts.tap_tree.leaf1.script
    sibling_hash = rs.scripts.tap_tree.leaf2.leaf_hash
    control_block = build_control_block(
        internal_key_xonly=rs.scripts.internal_key_xonly,
        output_key_parity=rs.scripts.output_key_parity,
        sibling_hash=sibling_hash,
    )

    print("  P1 claiming via HTLC...", flush=True)
    r = httpx.post(
        f"{P_URLS[1]}/claim_htlc",
        json={
            "round_idx": 1,
            "tx_hex": tx_to_hex(tx),
            "utxos": utxos_to_json(utxos),
            "htlc_script_hex": htlc_script.hex(),
            "control_block_hex": control_block.hex(),
            "preimage_hex": rs.htlc_preimage.hex(),
        },
        timeout=30,
    )
    r.raise_for_status()
    txid = r.json()["txid"]
    rpc.mine(1)
    print(f"  ✓ P1 claimed via HTLC. txid={txid}", flush=True)


# ── Round 2: collective refund ─────────────────────────────────────────────────

def run_round2_refund(rpc, setup, params, pubkeys):
    rs = setup.rounds[2]
    address = rs.scripts.address
    spk = rs.scripts.script_pubkey.data

    # Contributions
    print("  Requesting contributions...", flush=True)
    for i, url in enumerate(P_URLS):
        r = httpx.post(f"{url}/contribute",
                       json={"address": address, "amount_btc": AMOUNT_BTC},
                       timeout=30)
        r.raise_for_status()
        print(f"    P{i} txid={r.json()['txid'][:16]}...", flush=True)
    rpc.mine(1)

    utxos = scan_utxos(rpc, address, 3, btc_to_sats(AMOUNT_BTC), spk)
    for i, u in enumerate(utxos):
        rs.contributions[i] = u

    # P2 (round winner) disappears: skip all interaction with P2
    print(f"  P2 disappears. Mining T_REFUND={T_REFUND} blocks...", flush=True)
    rpc.mine(T_REFUND)

    # Build refund tx: each participant gets their pro-rata share
    refund_addrs = [p2tr_addr(pk) for pk in pubkeys]
    tx = build_refund_tx(utxos, refund_addrs, T_REFUND)
    refund_script = rs.scripts.tap_tree.leaf2.script
    sibling_hash = rs.scripts.tap_tree.leaf1.leaf_hash
    control_block = build_control_block(
        internal_key_xonly=rs.scripts.internal_key_xonly,
        output_key_parity=rs.scripts.output_key_parity,
        sibling_hash=sibling_hash,
    )

    tx_hex_unsigned = tx_to_hex(tx)
    utxos_json = utxos_to_json(utxos)
    refund_script_hex = refund_script.hex()
    sorted_pks = sorted(pubkeys)   # sigs must follow sorted-pubkey order (BIP-342 multisig)

    # Sign each input: P0 and P1 sign; P2 abstains (b"" placeholder)
    print("  P0 and P1 signing refund inputs...", flush=True)
    for inp_idx in range(len(tx.vin)):
        sigs_by_pk: dict[bytes, bytes] = {}
        for i, url in enumerate(P_URLS[:2]):   # only P0 and P1
            r = httpx.post(
                f"{url}/sign_refund",
                json={
                    "round_idx": 2,
                    "inp_idx": inp_idx,
                    "tx_hex": tx_hex_unsigned,
                    "utxos": utxos_json,
                    "refund_script_hex": refund_script_hex,
                },
                timeout=10,
            )
            r.raise_for_status()
            sigs_by_pk[pubkeys[i]] = bytes.fromhex(r.json()["sig_hex"])

        # Ordered by sorted pubkeys; b"" for non-signers (P2)
        sigs = [sigs_by_pk.get(pk, b"") for pk in sorted_pks]
        tx.vin[inp_idx].witness = make_refund_witness(sigs, refund_script, control_block)
        print(f"    input {inp_idx} signed", flush=True)

    final_tx_hex = tx_to_hex(tx)
    result = rpc.test_mempool_accept(final_tx_hex)
    if not result[0]["allowed"]:
        raise RuntimeError(f"Refund tx rejected: {result[0].get('reject-reason')}")

    txid = rpc.send_raw_transaction(final_tx_hex)
    rpc.mine(1)
    print(f"  ✓ Refund broadcast. txid={txid}", flush=True)


if __name__ == "__main__":
    main()
