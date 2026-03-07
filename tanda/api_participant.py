"""
FastAPI server for a single tanda participant.

Each container runs one instance of this server, holding its own private key.
The coordinator communicates with participants exclusively via HTTP.

Environment variables:
  SK_IDX           — 0-based participant index (e.g. 0, 1, 2)
  SK_SEED          — seed string; private key = sha256(SK_SEED.encode())
  BITCOIND_RPC_URL — http://user:pass@host:port  (no wallet path)
"""

from __future__ import annotations

import hashlib
import os
import urllib.parse
from io import BytesIO
from typing import Optional

import coincurve
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .musig2 import (
    AggNonce,
    SecNonce,
    PubNonce,
    SessionContext,
    key_agg,
    nonce_gen,
    partial_sign,
    apply_tweak,
)
from .protocol import (
    UTXO,
    taproot_tweak,
    sign_tapscript,
    make_htlc_claim_witness,
    REGTEST,
)
from .rpc import BitcoinRPC
from embit.ec import PrivateKey
from embit.script import Script
from embit.transaction import Transaction


# ── Wallet-less helpers ────────────────────────────────────────────────────────

def _p2wpkh_addr(sk_bytes: bytes) -> str:
    """P2WPKH address derived from tanda key — no RPC needed."""
    pubkey = coincurve.PrivateKey(sk_bytes).public_key.format(compressed=True)
    pk_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    spk = bytes([0x00, 0x14]) + pk_hash
    return Script(spk).address(network=REGTEST)


def _wif(sk_bytes: bytes) -> str:
    """WIF (regtest) for the tanda key."""
    from embit.networks import NETWORKS
    return PrivateKey(sk_bytes).wif(network=NETWORKS["regtest"])


app = FastAPI(title="Tanda Participant")


# ── Startup ────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    idx = int(os.environ["SK_IDX"])
    seed = os.environ["SK_SEED"].encode()
    sk_bytes = hashlib.sha256(seed).digest()

    rpc_url = os.environ.get("BITCOIND_RPC_URL", "http://user:password@bitcoind:18443")
    parsed = urllib.parse.urlparse(rpc_url)

    # Wallet-less: use only chain-level RPC (no wallet creation)
    rpc = BitcoinRPC(
        rpc_user=parsed.username,
        rpc_password=parsed.password,
        rpc_host=parsed.hostname,
        rpc_port=parsed.port or 18443,
    )

    pubkey = coincurve.PrivateKey(sk_bytes).public_key.format(compressed=True)

    app.state.idx = idx
    app.state.sk_bytes = sk_bytes
    app.state.pubkey = pubkey
    app.state.rpc = rpc
    app.state.setup_rounds = {}   # round_idx → dict with round parameters
    app.state.sec_nonces = {}     # (round_idx, inp_idx) → SecNonce


# ── Request / response models ──────────────────────────────────────────────────

class SetupRequest(BaseModel):
    round_idx: int
    pubkeys: list[str]           # hex-encoded 33-byte compressed pubkeys
    htlc_hash_hex: str
    internal_key_xonly_hex: str
    merkle_root_hex: str
    preimage_hex: Optional[str] = None   # only sent to the round winner


class ContributeRequest(BaseModel):
    address: str
    amount_btc: float


class NonceRequest(BaseModel):
    round_idx: int
    inp_idx: int
    agg_pk_hex: str


class SignClaimRequest(BaseModel):
    round_idx: int
    inp_idx: int
    agg_nonce_hex: str   # 66-byte hex (R1 || R2, each 33 bytes compressed)
    sighash_hex: str     # 32-byte hex


class UTXOInfo(BaseModel):
    txid: str
    vout: int
    amount_sats: int
    script_pubkey_hex: str   # 34-byte raw P2TR scriptPubKey (no compact_size prefix)


class SignRefundRequest(BaseModel):
    round_idx: int
    inp_idx: int
    tx_hex: str
    utxos: list[UTXOInfo]
    refund_script_hex: str


class ClaimHTLCRequest(BaseModel):
    round_idx: int
    tx_hex: str
    utxos: list[UTXOInfo]
    htlc_script_hex: str
    control_block_hex: str
    preimage_hex: str


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utxo_list(infos: list[UTXOInfo]) -> list[UTXO]:
    return [
        UTXO(
            txid=u.txid,
            vout=u.vout,
            amount_sats=u.amount_sats,
            script_pubkey=bytes.fromhex(u.script_pubkey_hex),
        )
        for u in infos
    ]


def _parse_tx(tx_hex: str) -> Transaction:
    return Transaction.parse(bytes.fromhex(tx_hex))


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "idx": app.state.idx,
        "pubkey_hex": app.state.pubkey.hex(),
    }


@app.get("/wallet_address")
def wallet_address():
    return {"address": _p2wpkh_addr(app.state.sk_bytes)}


@app.post("/setup")
def setup(req: SetupRequest):
    app.state.setup_rounds[req.round_idx] = {
        "pubkeys": req.pubkeys,
        "htlc_hash_hex": req.htlc_hash_hex,
        "internal_key_xonly_hex": req.internal_key_xonly_hex,
        "merkle_root_hex": req.merkle_root_hex,
        "preimage_hex": req.preimage_hex,
    }
    return {"status": "ok", "round_idx": req.round_idx}


@app.post("/contribute")
def contribute(req: ContributeRequest):
    my_addr = _p2wpkh_addr(app.state.sk_bytes)
    utxos = app.state.rpc.scan_utxos(my_addr)
    if not utxos:
        raise HTTPException(400, detail=f"No funds at {my_addr}")

    fee = 0.0001
    u = next((u for u in utxos if float(u["amount"]) >= req.amount_btc + fee), None)
    if u is None:
        raise HTTPException(400, detail="Insufficient funds")

    spk_hex = (
        u["scriptPubKey"]
        if isinstance(u["scriptPubKey"], str)
        else u["scriptPubKey"]["hex"]
    )
    try:
        txid = app.state.rpc._fund_address_raw(req.address, req.amount_btc, [{
            "txid": u["txid"],
            "vout": u["vout"],
            "amount": float(u["amount"]),
            "scriptPubKey": spk_hex,
            "privkey": _wif(app.state.sk_bytes),
            "change_address": my_addr,
        }])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"fund_address_raw failed: {exc}")
    return {"txid": txid}


@app.post("/nonce")
def nonce(req: NonceRequest):
    """Generate a fresh nonce pair; return public half, store secret half."""
    sk = app.state.sk_bytes
    pk = app.state.pubkey
    agg_pk = bytes.fromhex(req.agg_pk_hex)

    sec, pub = nonce_gen(sk=sk, pk=pk, agg_pk=agg_pk)
    app.state.sec_nonces[(req.round_idx, req.inp_idx)] = sec
    return {"pub_nonce_hex": pub.serialize().hex()}


@app.post("/sign_claim")
def sign_claim(req: SignClaimRequest):
    """
    Produce a MuSig2 partial signature for keypath spend.

    Reconstructs KeyAggContext with Taproot tweak locally (never transmitted).
    Consumes the stored SecNonce for (round_idx, inp_idx) — use-once.
    """
    key = (req.round_idx, req.inp_idx)
    sec_nonce = app.state.sec_nonces.pop(key, None)
    if sec_nonce is None:
        raise HTTPException(
            status_code=400,
            detail=f"No nonce stored for round={req.round_idx} inp={req.inp_idx}",
        )

    round_info = app.state.setup_rounds.get(req.round_idx)
    if round_info is None:
        raise HTTPException(
            status_code=400,
            detail=f"Round {req.round_idx} not set up — call /setup first",
        )

    # Rebuild KeyAggContext with Taproot tweak applied
    pubkeys = [bytes.fromhex(pk) for pk in round_info["pubkeys"]]
    kac = key_agg(pubkeys)
    kac = apply_tweak(
        kac,
        taproot_tweak(
            bytes.fromhex(round_info["internal_key_xonly_hex"]),
            bytes.fromhex(round_info["merkle_root_hex"]),
        ),
        is_xonly=True,
    )

    # Deserialize aggregate nonce (66 bytes: R1 || R2, each 33 bytes compressed)
    agg_nonce_bytes = bytes.fromhex(req.agg_nonce_hex)
    agg_nonce = AggNonce(
        R1=coincurve.PublicKey(agg_nonce_bytes[:33]),
        R2=coincurve.PublicKey(agg_nonce_bytes[33:]),
    )

    sighash = bytes.fromhex(req.sighash_hex)
    session_ctx = SessionContext(agg_nonce=agg_nonce, key_agg_ctx=kac, msg=sighash)

    psig = partial_sign(sec_nonce, app.state.sk_bytes, session_ctx)
    return {"psig": psig}   # int — native JSON, no precision loss for secp256k1 scalars


@app.post("/sign_refund")
def sign_refund(req: SignRefundRequest):
    """
    Sign one input of the collective refund tx (leaf2 scriptpath).
    Returns a 64-byte Schnorr signature for the given inp_idx.
    """
    tx = _parse_tx(req.tx_hex)
    utxos = _utxo_list(req.utxos)
    refund_script = bytes.fromhex(req.refund_script_hex)
    privkey = PrivateKey(app.state.sk_bytes)

    sig = sign_tapscript(tx, req.inp_idx, utxos, privkey, refund_script)
    return {"sig_hex": sig.hex()}


@app.post("/claim_htlc")
def claim_htlc(req: ClaimHTLCRequest):
    """
    Sign all inputs of the HTLC claim tx (leaf1 scriptpath) and broadcast.
    Called only by the round winner after cooperative signing has failed.
    """
    tx = _parse_tx(req.tx_hex)
    utxos = _utxo_list(req.utxos)
    htlc_script = bytes.fromhex(req.htlc_script_hex)
    control_block = bytes.fromhex(req.control_block_hex)
    preimage = bytes.fromhex(req.preimage_hex)
    privkey = PrivateKey(app.state.sk_bytes)

    for i in range(len(tx.vin)):
        sig = sign_tapscript(tx, i, utxos, privkey, htlc_script)
        tx.vin[i].witness = make_htlc_claim_witness(
            winner_sig=sig,
            preimage=preimage,
            htlc_script=htlc_script,
            control_block=control_block,
        )

    buf = BytesIO()
    tx.write_to(buf)
    txid = app.state.rpc.send_raw_transaction(buf.getvalue().hex())
    return {"txid": txid}
