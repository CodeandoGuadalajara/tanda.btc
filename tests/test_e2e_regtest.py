"""
End-to-end regtest test: 3-participant tanda, 3 rounds, all spending paths.

Requires a running Bitcoin Core regtest node (wallet support optional).
Run `scripts/regtest_setup.sh` before executing these tests (or just start
bitcoind in regtest mode).

Scenarios:
  Round 0 — cooperative: all sign via MuSig2 → P₀ receives 3×amount
  Round 1 — HTLC fallback: P₂ does not sign → P₁ claims via leaf1 after T_claim
  Round 2 — refund fallback: P₂ (winner) disappears → P₀+P₁ refund via leaf2

Usage:
  pytest tests/test_e2e_regtest.py -v -m e2e --timeout=120
"""

from __future__ import annotations

import hashlib
import struct
import time
from io import BytesIO

import coincurve
import pytest

from embit.ec import PrivateKey, PublicKey
from embit.script import Script

from tanda.rpc import BitcoinRPC
from tanda.coordinator import Coordinator, TandaParams, TandaSetup
from tanda.participant import Participant
from tanda.musig2 import (
    key_agg,
    nonce_gen,
    nonce_agg,
    partial_sign,
    partial_sig_agg,
    partial_sig_verify,
    SessionContext,
    schnorr_verify,
)
from tanda.protocol import (
    UTXO,
    btc_to_sats,
    sats_to_btc,
    compute_taproot_sighash,
    make_keypath_witness,
    make_htlc_claim_witness,
    make_refund_witness,
    build_claim_tx,
    build_htlc_claim_tx,
    build_refund_tx,
    build_control_block,
    sign_tapscript,
    REGTEST,
)
from tanda.htlc import verify_preimage


# ── Configuration ─────────────────────────────────────────────────────────────

RPC_USER = "user"
RPC_PASS = "password"
RPC_PORT = 18443
AMOUNT_BTC = 0.1        # per participant per round (larger to avoid dust)
AMOUNT_SATS = btc_to_sats(AMOUNT_BTC)
T_CLAIM = 5             # short for regtest (normally 288)
T_REFUND = 10           # short for regtest (normally 576)
T_CONTRIBUTION = 3      # short for regtest

# Deterministic keys for the e2e test (DO NOT use on mainnet)
MINE_SEED = b"regtest_mine_key"
P0_SEED = b"participant_0_key"
P1_SEED = b"participant_1_key"
P2_SEED = b"participant_2_key"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _privkey(seed: bytes) -> bytes:
    return _sha256(seed)


def _pubkey(seed: bytes) -> bytes:
    return coincurve.PrivateKey(_privkey(seed)).public_key.format(compressed=True)


def _p2tr_addr(pk_bytes: bytes) -> str:
    xonly = PublicKey.parse(pk_bytes).xonly()
    spk = Script(bytes([0x51, 0x20]) + xonly)
    return spk.address(network=REGTEST)


def _p2tr_spk(pk_bytes: bytes) -> bytes:
    xonly = PublicKey.parse(pk_bytes).xonly()
    return bytes([0x51, 0x20]) + xonly


def _wif(sk_bytes: bytes) -> str:
    """Encode a private key in WIF (compressed, regtest)."""
    import base64
    # prefix 0xEF for testnet/regtest, 0x01 suffix for compressed
    payload = bytes([0xEF]) + sk_bytes + bytes([0x01])
    checksum = _sha256(_sha256(payload))[:4]
    from embit.base58 import encode_check
    return encode_check(bytes([0xEF]) + sk_bytes + bytes([0x01]))


def rpc() -> BitcoinRPC:
    return BitcoinRPC(RPC_USER, RPC_PASS, "127.0.0.1", RPC_PORT)


def mine(n: int = 1) -> None:
    """Mine n blocks."""
    rpc().mine(n)


def wait_for_utxos(
    address: str,
    expected_n: int,
    amount_sats: int,
    script_pubkey: bytes,
    max_retries: int = 30,
) -> list[UTXO]:
    """Poll scantxoutset until at least *expected_n* UTXOs appear."""
    r = rpc()
    for _ in range(max_retries):
        raw = r.scan_utxos(address)
        utxos = [
            UTXO(
                txid=u["txid"],
                vout=u["vout"],
                amount_sats=round(float(u["amount"]) * 100_000_000),
                # scantxoutset returns scriptPubKey as a hex string; use it directly
                # as raw bytes (no length prefix). Fall back to the parameter.
                script_pubkey=(
                    bytes.fromhex(u["scriptPubKey"])
                    if isinstance(u.get("scriptPubKey"), str)
                    else bytes.fromhex(u["scriptPubKey"]["hex"])
                    if isinstance(u.get("scriptPubKey"), dict)
                    else script_pubkey
                ),
            )
            for u in raw
            if round(float(u["amount"]) * 100_000_000) >= amount_sats * 0.99
        ]
        if len(utxos) >= expected_n:
            return utxos[:expected_n]
        mine(1)
        time.sleep(0.1)
    raise TimeoutError(f"Did not find {expected_n} UTXOs at {address}")


def fund_participants(
    participant_seeds: list[bytes],
    btc_each: float = 5.0,
) -> dict[bytes, list[UTXO]]:
    """
    Fund each participant address from the coinbase mine key.
    Returns a dict seed → list[UTXO].
    """
    r = rpc()
    mine_rpc = BitcoinRPC()
    mine_addr = mine_rpc._default_mine_addr()

    # Find a mature coinbase UTXO (at least 100 confs)
    utxos = r.scan_utxos(mine_addr)
    # Filter: need UTXOs with enough confirmations (height + 100 <= current height)
    height = r.get_block_height()
    mature = [
        u for u in utxos
        if u.get("coinbase", False) and (height - u.get("height", 0)) >= 100
    ]
    if not mature:
        raise RuntimeError("No mature coinbase UTXOs found; mine more blocks first")

    funded: dict[bytes, list[UTXO]] = {}

    for seed in participant_seeds:
        pk = _pubkey(seed)
        addr = _p2tr_addr(pk)
        spk = _p2tr_spk(pk)

        if not mature:
            raise RuntimeError("Ran out of coinbase UTXOs")
        coin = mature.pop(0)

        coin_spk_hex = coin["scriptPubKey"] if isinstance(coin["scriptPubKey"], str) else coin["scriptPubKey"]["hex"]

        fund_hex = _build_fund_tx(
            coin_txid=coin["txid"],
            coin_vout=coin["vout"],
            coin_amount_sats=round(float(coin["amount"]) * 100_000_000),
            coin_spk_hex=coin_spk_hex,
            recipient_addr=addr,
            amount_sats=btc_to_sats(btc_each),
        )
        result = r.test_mempool_accept(fund_hex)
        if not result[0]["allowed"]:
            raise RuntimeError(f"Fund tx rejected: {result[0].get('reject-reason')}")

        txid = r.send_raw_transaction(fund_hex)

        funded[seed] = [UTXO(
            txid=txid,
            vout=0,
            amount_sats=btc_to_sats(btc_each),
            script_pubkey=spk,
        )]

    mine(1)  # Confirm all funding transactions
    return funded


def _mine_sk_wif() -> str:
    """Return the mine key in WIF format (testnet/regtest prefix 0xEF)."""
    sk_bytes = _privkey(MINE_SEED)
    # WIF: 0xEF + 32-byte key + 0x01 (compressed) → base58check
    from embit.base58 import encode_check
    return encode_check(bytes([0xEF]) + sk_bytes + bytes([0x01]))


def _build_fund_tx(
    coin_txid: str,
    coin_vout: int,
    coin_amount_sats: int,
    coin_spk_hex: str,
    recipient_addr: str,
    amount_sats: int,
) -> str:
    """
    Build, sign (via signrawtransactionwithkey), and return a hex funding tx.

    The coinbase output is P2WPKH (mine addr), so signrawtransactionwithkey
    handles the BIP-143 segwit signing automatically.
    """
    from embit.transaction import Transaction as Tx, TransactionInput as TxIn, TransactionOutput as TxOut
    from embit.script import Script as _Script
    from io import BytesIO as _BIO

    r = rpc()
    fee = 3000  # sats
    change_sats = coin_amount_sats - amount_sats - fee

    # Build unsigned tx
    txid_bytes = bytes.fromhex(coin_txid)   # embit reverses on write
    vin = [TxIn(txid_bytes, coin_vout, sequence=0xFFFFFFFD)]
    vout = [TxOut(amount_sats, _Script.from_address(recipient_addr))]

    mine_addr = rpc().find_method_result("_default_mine_addr") if False else BitcoinRPC()._default_mine_addr()
    if change_sats > 546:
        vout.append(TxOut(change_sats, _Script.from_address(mine_addr)))

    tx = Tx(version=2, vin=vin, vout=vout)
    buf = _BIO()
    tx.write_to(buf)
    raw_hex = buf.getvalue().hex()

    # Sign using RPC (handles P2WPKH segwit automatically)
    wif = _mine_sk_wif()
    prevtxs = [{
        "txid": coin_txid,
        "vout": coin_vout,
        "scriptPubKey": coin_spk_hex,
        "amount": coin_amount_sats / 100_000_000,
    }]
    result = r.call("signrawtransactionwithkey", raw_hex, [wif], prevtxs)
    if not result.get("complete", False):
        raise RuntimeError(f"signrawtransactionwithkey incomplete: {result}")
    return result["hex"]


def contribute_raw(
    participant_sk: bytes,
    source_utxos: list[UTXO],
    target_address: str,
    target_spk: bytes,
    amount_sats: int,
) -> tuple[str, UTXO]:
    """
    Build + sign + broadcast a contribution transaction.
    Returns (txid, UTXO) of the contribution output.
    """
    from embit.transaction import Transaction as Tx, TransactionInput as TxIn, TransactionOutput as TxOut, Witness as TxW
    from embit.script import Script as _Script

    r = rpc()
    total_in = sum(u.amount_sats for u in source_utxos)
    fee = 2000
    change_sats = total_in - amount_sats - fee

    # embit reverses txid on write, so pass display order (no reversal needed)
    txid_bytes_list = [bytes.fromhex(u.txid) for u in source_utxos]
    vin = [TxIn(tb, u.vout, sequence=0xFFFFFFFD) for tb, u in zip(txid_bytes_list, source_utxos)]

    target_script = _Script.from_address(target_address)
    vout = [TxOut(amount_sats, target_script)]

    pk_bytes = coincurve.PrivateKey(participant_sk).public_key.format(compressed=True)
    participant_addr = _p2tr_addr(pk_bytes)

    if change_sats > 546:
        change_spk = _Script.from_address(participant_addr)
        vout.append(TxOut(change_sats, change_spk))

    tx = Tx(version=2, vin=vin, vout=vout)

    # Sign each input
    privkey = PrivateKey(participant_sk)
    for i, utxo in enumerate(source_utxos):
        sighash = compute_taproot_sighash(tx, i, source_utxos)
        sig_obj = privkey.schnorr_sign(sighash)
        sig_bytes = sig_obj.serialize()
        tx.vin[i].witness = TxW([sig_bytes])

    buf = BytesIO()
    tx.write_to(buf)
    tx_hex = buf.getvalue().hex()

    result = r.test_mempool_accept(tx_hex)
    if not result[0]["allowed"]:
        raise RuntimeError(f"Contribution tx rejected: {result[0].get('reject-reason')}")

    txid = r.send_raw_transaction(tx_hex)
    contribution_utxo = UTXO(
        txid=txid,
        vout=0,
        amount_sats=amount_sats,
        script_pubkey=target_spk,
    )
    return txid, contribution_utxo


# ── Pytest fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def regtest_env():
    """Set up the complete regtest environment for all e2e tests."""
    r = rpc()
    try:
        height = r.get_block_height()
    except Exception as e:
        pytest.skip(f"Regtest node not available: {e}")

    # Mine enough blocks for mature coinbase
    if height < 110:
        print(f"\nMining {110 - height} blocks to get mature coinbase...")
        r.mine(110 - height)
        height = r.get_block_height()

    # Participant keys
    seeds = [P0_SEED, P1_SEED, P2_SEED]
    privkeys = [_privkey(s) for s in seeds]
    pubkeys = [_pubkey(s) for s in seeds]

    # Fund participants from coinbase
    try:
        funded = fund_participants(seeds, btc_each=5.0)
    except Exception as e:
        pytest.skip(f"Could not fund participants: {e}")

    params = TandaParams(
        n_participants=3,
        amount_btc=AMOUNT_BTC,
        t_contribution=T_CONTRIBUTION,
        t_claim=T_CLAIM,
        t_refund=T_REFUND,
        k_min=2,
        winner_order=[0, 1, 2],
    )

    coord_rpc = rpc()
    coord = Coordinator(coord_rpc, params, pubkeys)
    setup = coord.setup()

    return {
        "privkeys": privkeys,
        "pubkeys": pubkeys,
        "seeds": seeds,
        "funded": funded,
        "params": params,
        "coord": coord,
        "setup": setup,
    }


# ── Round 0: Cooperative (MuSig2 keypath) ────────────────────────────────────

@pytest.mark.e2e
class TestRound0Cooperative:
    """All 3 participants sign cooperatively; P₀ claims the pot."""

    def test_round0_cooperative(self, regtest_env):
        env = regtest_env
        coord = env["coord"]
        setup = env["setup"]
        params = env["params"]
        privkeys = env["privkeys"]
        pubkeys = env["pubkeys"]
        funded = env["funded"]
        seeds = env["seeds"]

        rs = setup.rounds[0]
        address = rs.scripts.address
        # Use .data for raw bytes (no compact_size prefix) — required for UTXO.script_pubkey
        spk = rs.scripts.script_pubkey.data

        r = rpc()

        # 1. Each participant sends contribution from their funded UTXOs
        contribution_utxos = []
        for i, (seed, sk) in enumerate(zip(seeds, privkeys)):
            src_utxos = funded[seed]
            _, contrib_utxo = contribute_raw(
                participant_sk=sk,
                source_utxos=src_utxos,
                target_address=address,
                target_spk=spk,
                amount_sats=AMOUNT_SATS,
            )
            contribution_utxos.append(contrib_utxo)

        # Confirm contributions
        mine(1)

        # 2. Wait for all UTXOs to be visible
        utxos = wait_for_utxos(address, 3, AMOUNT_SATS, spk)
        for i, u in enumerate(utxos):
            rs.contributions[i] = u

        # 3. Build claim tx
        winner_pk = pubkeys[0]
        winner_addr = _p2tr_addr(winner_pk)
        tx = build_claim_tx(utxos, winner_addr)
        rs.claim_tx = tx

        # kac already has the taptweak applied (set up by coordinator.setup())
        # so kac.agg_pk == rs.scripts.output_key_xonly
        kac = rs.key_agg_ctx
        assert kac.agg_pk == rs.scripts.output_key_xonly, \
            "kac.agg_pk must equal tweaked output key for keypath signing"

        # 4–7. MuSig2 signing per input (each input has a distinct sighash)
        for inp_idx in range(len(tx.vin)):
            sighash = compute_taproot_sighash(tx, inp_idx, utxos)

            # Fresh nonces per input
            sec_nonces, pub_nonces = [], []
            for sk, pk in zip(privkeys, pubkeys):
                s, p = nonce_gen(sk=sk, pk=pk, agg_pk=kac.agg_pk)
                sec_nonces.append(s)
                pub_nonces.append(p)

            agg = nonce_agg(pub_nonces)
            session = SessionContext(agg_nonce=agg, key_agg_ctx=kac, msg=sighash)

            psigs = []
            for i, (s, sk) in enumerate(zip(sec_nonces, privkeys)):
                pk_i = coincurve.PrivateKey(sk).public_key.format(compressed=True)
                psig = partial_sign(s, sk, session)
                assert partial_sig_verify(psig, pub_nonces[i], pk_i, session), \
                    f"Partial sig {i} failed for input {inp_idx}"
                psigs.append(psig)

            final_sig = partial_sig_agg(psigs, session)
            assert len(final_sig) == 64
            assert schnorr_verify(final_sig, sighash, kac.agg_pk)
            tx.vin[inp_idx].witness = make_keypath_witness(final_sig)

        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()

        result = r.test_mempool_accept(tx_hex)
        assert result[0]["allowed"], f"Claim tx rejected: {result[0].get('reject-reason')}"

        txid = r.send_raw_transaction(tx_hex)
        mine(1)
        assert txid, "claim_tx not broadcast"

        # 9. Verify winner has the UTXO
        winner_utxos = r.scan_utxos(winner_addr)
        total_received = sum(float(u["amount"]) for u in winner_utxos)
        assert total_received >= AMOUNT_BTC * 3 - 0.001, \
            f"Winner got {total_received} BTC, expected ~{AMOUNT_BTC * 3}"


# ── Round 1: HTLC fallback (leaf1) ───────────────────────────────────────────

@pytest.mark.e2e
class TestRound1HTLCFallback:
    """P₂ doesn't sign coop claim. P₁ uses HTLC path (leaf1) after T_claim."""

    def test_round1_htlc_fallback(self, regtest_env):
        env = regtest_env
        coord = env["coord"]
        setup = env["setup"]
        params = env["params"]
        privkeys = env["privkeys"]
        pubkeys = env["pubkeys"]
        funded = env["funded"]
        seeds = env["seeds"]

        rs = setup.rounds[1]
        address = rs.scripts.address
        spk = rs.scripts.script_pubkey.data

        r = rpc()

        # 1. All 3 contribute
        for seed, sk in zip(seeds, privkeys):
            src_utxos = r.scan_utxos(_p2tr_addr(_pubkey(seed)))
            # Re-scan to find any remaining balance after round 0
            src_utxos_obj = [
                UTXO(
                    txid=u["txid"],
                    vout=u["vout"],
                    amount_sats=round(float(u["amount"]) * 100_000_000),
                    script_pubkey=_p2tr_spk(_pubkey(seed)),
                )
                for u in src_utxos
                if round(float(u["amount"]) * 100_000_000) > AMOUNT_SATS + 5000
            ]
            if not src_utxos_obj:
                pytest.skip(f"Insufficient funds for round 1 (seed={seed})")
            contribute_raw(sk, src_utxos_obj[:1], address, spk, AMOUNT_SATS)

        mine(1)
        utxos = wait_for_utxos(address, 3, AMOUNT_SATS, spk)
        for i, u in enumerate(utxos):
            rs.contributions[i] = u

        # 2. Mine T_claim blocks (cooperative signing fails; winner uses HTLC)
        mine(T_CLAIM)

        # 3. P₁ (winner of round 1) claims via HTLC (leaf1)
        winner_addr = _p2tr_addr(pubkeys[1])
        tx = build_htlc_claim_tx(utxos, winner_addr)
        htlc_script = rs.scripts.tap_tree.leaf1.script
        sibling_hash = rs.scripts.tap_tree.leaf2.leaf_hash
        control_block = build_control_block(
            internal_key_xonly=rs.scripts.internal_key_xonly,
            output_key_parity=rs.scripts.output_key_parity,
            sibling_hash=sibling_hash,
        )
        preimage = rs.htlc_preimage
        assert verify_preimage(preimage, rs.htlc_hash)

        winner_privkey = PrivateKey(privkeys[1])
        for i in range(len(tx.vin)):
            sig = sign_tapscript(tx, i, utxos, winner_privkey, htlc_script)
            tx.vin[i].witness = make_htlc_claim_witness(
                winner_sig=sig,
                preimage=preimage,
                htlc_script=htlc_script,
                control_block=control_block,
            )

        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()

        result = r.test_mempool_accept(tx_hex)
        assert result[0]["allowed"], f"HTLC tx rejected: {result[0].get('reject-reason')}"

        txid = r.send_raw_transaction(tx_hex)
        mine(1)
        assert txid

        winner_utxos = r.scan_utxos(winner_addr)
        total = sum(float(u["amount"]) for u in winner_utxos)
        assert total >= AMOUNT_BTC * 3 - 0.001


# ── Round 2: Refund fallback (leaf2) ─────────────────────────────────────────

@pytest.mark.e2e
class TestRound2RefundFallback:
    """P₂ wins but disappears. P₀+P₁ refund via leaf2 after T_refund."""

    def test_round2_refund_fallback(self, regtest_env):
        env = regtest_env
        coord = env["coord"]
        setup = env["setup"]
        params = env["params"]
        privkeys = env["privkeys"]
        pubkeys = env["pubkeys"]
        funded = env["funded"]
        seeds = env["seeds"]

        rs = setup.rounds[2]
        address = rs.scripts.address
        spk = rs.scripts.script_pubkey.data

        r = rpc()

        # 1. All 3 contribute
        for seed, sk in zip(seeds, privkeys):
            src_utxos = r.scan_utxos(_p2tr_addr(_pubkey(seed)))
            src_utxos_obj = [
                UTXO(
                    txid=u["txid"],
                    vout=u["vout"],
                    amount_sats=round(float(u["amount"]) * 100_000_000),
                    script_pubkey=_p2tr_spk(_pubkey(seed)),
                )
                for u in src_utxos
                if round(float(u["amount"]) * 100_000_000) > AMOUNT_SATS + 5000
            ]
            if not src_utxos_obj:
                pytest.skip(f"Insufficient funds for round 2 (seed={seed})")
            contribute_raw(sk, src_utxos_obj[:1], address, spk, AMOUNT_SATS)

        mine(1)
        utxos = wait_for_utxos(address, 3, AMOUNT_SATS, spk)
        for i, u in enumerate(utxos):
            rs.contributions[i] = u

        # 2. Mine T_refund blocks (P₂/winner disappears)
        mine(T_REFUND)

        # 3. P₀ and P₁ claim refund (leaf2: thresh(2, pk0, pk1, pk2))
        refund_addrs = [_p2tr_addr(pk) for pk in pubkeys]
        tx = build_refund_tx(utxos, refund_addrs, T_REFUND)
        refund_script = rs.scripts.tap_tree.leaf2.script
        sibling_hash = rs.scripts.tap_tree.leaf1.leaf_hash
        control_block = build_control_block(
            internal_key_xonly=rs.scripts.internal_key_xonly,
            output_key_parity=rs.scripts.output_key_parity,
            sibling_hash=sibling_hash,
        )

        # Build sigs in sorted pubkey order (empty bytes for non-signers).
        # Each input has its own sighash (different input_index), so sign per-input.
        sorted_pks = sorted(pubkeys)

        for inp_idx in range(len(tx.vin)):
            sigs_by_pk: dict[bytes, bytes] = {}
            for i in [0, 1]:  # P₀ and P₁ sign (P₂ abstains)
                pk_i = pubkeys[i]
                privkey_i = PrivateKey(privkeys[i])
                sig = sign_tapscript(tx, inp_idx, utxos, privkey_i, refund_script)
                sigs_by_pk[pk_i] = sig
            sigs = [sigs_by_pk.get(pk, b"") for pk in sorted_pks]
            tx.vin[inp_idx].witness = make_refund_witness(sigs, refund_script, control_block)

        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()

        result = r.test_mempool_accept(tx_hex)
        assert result[0]["allowed"], f"Refund tx rejected: {result[0].get('reject-reason')}"

        txid = r.send_raw_transaction(tx_hex)
        mine(1)
        assert txid

        # 4. Verify P₀ and P₁ got refunds
        for i in [0, 1]:
            refund_utxos = r.scan_utxos(refund_addrs[i])
            assert len(refund_utxos) >= 1, f"P{i} got no refund"


# ── Smoke test ────────────────────────────────────────────────────────────────

@pytest.mark.e2e
def test_regtest_node_accessible():
    """Smoke test: can we reach the regtest node and mine a block?"""
    try:
        r = rpc()
        h0 = r.get_block_height()
        r.mine(1)
        h1 = r.get_block_height()
        assert h1 == h0 + 1
    except Exception as e:
        pytest.skip(f"Regtest not available: {e}")
