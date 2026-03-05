"""
Unit tests for tanda/protocol.py and tanda/musig2.py.
These tests do NOT require a live Bitcoin node.
"""

import hashlib
import pytest

from tanda.htlc import generate_htlc_secret, verify_preimage
from tanda.musig2 import (
    key_agg,
    nonce_gen,
    nonce_agg,
    partial_sign,
    partial_sig_verify,
    partial_sig_agg,
    schnorr_verify,
    _tagged_hash,
    _int_to_bytes32,
    _bytes_to_int,
    _has_even_y,
    _point_from_compressed,
    _point_mul,
    _xonly,
    N,
    G_COMPRESSED,
)
from tanda.protocol import (
    build_taproot_output,
    build_claim_tx,
    build_refund_tx,
    _build_htlc_winner_script,
    _build_refund_script,
    _tap_leaf_hash,
    _tap_branch_hash,
    UTXO,
    btc_to_sats,
    sats_to_btc,
    REGTEST,
    TAPSCRIPT_LEAF_VERSION,
)

import coincurve
from embit.ec import PrivateKey, PublicKey


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_privkeys(n: int) -> list[bytes]:
    return [hashlib.sha256(f"test_key_{i}".encode()).digest() for i in range(n)]


def make_pubkeys(privkeys: list[bytes]) -> list[bytes]:
    return [coincurve.PrivateKey(sk).public_key.format(compressed=True) for sk in privkeys]


# ── HTLC tests ────────────────────────────────────────────────────────────────

class TestHTLC:
    def test_generate_htlc_secret(self):
        preimage, htlc_hash = generate_htlc_secret()
        assert len(preimage) == 32
        assert len(htlc_hash) == 32
        assert htlc_hash == hashlib.sha256(preimage).digest()

    def test_verify_preimage_valid(self):
        preimage, htlc_hash = generate_htlc_secret()
        assert verify_preimage(preimage, htlc_hash) is True

    def test_verify_preimage_invalid(self):
        preimage, htlc_hash = generate_htlc_secret()
        assert verify_preimage(b"\x00" * 32, htlc_hash) is False

    def test_different_preimages_different_hashes(self):
        p1, h1 = generate_htlc_secret()
        p2, h2 = generate_htlc_secret()
        assert p1 != p2
        assert h1 != h2


# ── MuSig2 tests ──────────────────────────────────────────────────────────────

class TestMuSig2:
    def test_key_agg_single(self):
        sk = make_privkeys(1)[0]
        pk = make_pubkeys([sk])[0]
        ctx = key_agg([pk])
        assert len(ctx.agg_pk) == 32  # x-only 32 bytes

    def test_key_agg_three(self):
        privkeys = make_privkeys(3)
        pubkeys = make_pubkeys(privkeys)
        ctx = key_agg(pubkeys)
        assert len(ctx.agg_pk) == 32
        assert len(ctx.coeffs) == 3
        assert len(ctx.pubkeys) == 3

    def test_key_agg_is_deterministic(self):
        privkeys = make_privkeys(3)
        pubkeys = make_pubkeys(privkeys)
        ctx1 = key_agg(pubkeys)
        ctx2 = key_agg(pubkeys)
        assert ctx1.agg_pk == ctx2.agg_pk

    def test_key_agg_order_independent(self):
        privkeys = make_privkeys(3)
        pubkeys = make_pubkeys(privkeys)
        ctx1 = key_agg(pubkeys)
        ctx2 = key_agg(list(reversed(pubkeys)))
        # Sorted internally, so result must be the same
        assert ctx1.agg_pk == ctx2.agg_pk

    def test_key_agg_second_unique_gets_coeff_1(self):
        """The second unique pubkey (when sorted) must get coefficient 1."""
        privkeys = make_privkeys(3)
        pubkeys = make_pubkeys(privkeys)
        sorted_pks = sorted(pubkeys)
        ctx = key_agg(pubkeys)
        # Find index of second unique key
        second = None
        for pk in sorted_pks:
            if pk != sorted_pks[0]:
                second = pk
                break
        if second is not None:
            idx = ctx.pubkeys.index(second)
            assert ctx.coeffs[idx] == 1

    def test_nonce_gen(self):
        sk = make_privkeys(1)[0]
        pk = make_pubkeys([sk])[0]
        ctx = key_agg([pk])
        sec, pub = nonce_gen(sk=sk, pk=pk, agg_pk=ctx.agg_pk)
        assert sec.k1 != 0
        assert sec.k2 != 0
        assert sec.k1 != sec.k2
        assert len(pub.serialize()) == 66

    def test_nonce_agg(self):
        privkeys = make_privkeys(3)
        pubkeys = make_pubkeys(privkeys)
        ctx = key_agg(pubkeys)

        nonces = []
        for sk, pk in zip(privkeys, pubkeys):
            _, pn = nonce_gen(sk=sk, pk=pk, agg_pk=ctx.agg_pk)
            nonces.append(pn)

        agg = nonce_agg(nonces)
        assert len(agg.serialize()) == 66

    def test_musig2_full_round_trip(self):
        """Full MuSig2 3-of-3 signing round trip."""
        privkeys = make_privkeys(3)
        pubkeys = make_pubkeys(privkeys)
        ctx = key_agg(pubkeys)

        msg = hashlib.sha256(b"test sighash").digest()

        # Nonce generation
        sec_nonces = []
        pub_nonces = []
        for sk, pk in zip(privkeys, pubkeys):
            sec, pub = nonce_gen(sk=sk, pk=pk, agg_pk=ctx.agg_pk)
            sec_nonces.append(sec)
            pub_nonces.append(pub)

        # Nonce aggregation
        from tanda.musig2 import SessionContext
        agg = nonce_agg(pub_nonces)

        # Session context
        session = SessionContext(agg_nonce=agg, key_agg_ctx=ctx, msg=msg)

        # Partial signing
        psigs = []
        for sk, sec_n, pub_n, pk in zip(privkeys, sec_nonces, pub_nonces, pubkeys):
            psig = partial_sign(sec_n, sk, session)
            psigs.append(psig)
            # Each partial sig should verify
            assert partial_sig_verify(psig, pub_n, pk, session)

        # Aggregate
        final_sig = partial_sig_agg(psigs, session)
        assert len(final_sig) == 64

        # Verify final Schnorr signature against aggregate key
        assert schnorr_verify(final_sig, msg, ctx.agg_pk)

    def test_musig2_2of2(self):
        """MuSig2 2-of-2 signing."""
        privkeys = make_privkeys(2)
        pubkeys = make_pubkeys(privkeys)
        ctx = key_agg(pubkeys)

        msg = b"\xAB" * 32

        from tanda.musig2 import SessionContext
        sec_nonces, pub_nonces = [], []
        for sk, pk in zip(privkeys, pubkeys):
            s, p = nonce_gen(sk=sk, pk=pk, agg_pk=ctx.agg_pk)
            sec_nonces.append(s)
            pub_nonces.append(p)

        agg = nonce_agg(pub_nonces)
        session = SessionContext(agg_nonce=agg, key_agg_ctx=ctx, msg=msg)

        psigs = [partial_sign(s, sk, session) for s, sk in zip(sec_nonces, privkeys)]
        final_sig = partial_sig_agg(psigs, session)
        assert schnorr_verify(final_sig, msg, ctx.agg_pk)


# ── Protocol / Script tests ───────────────────────────────────────────────────

class TestScripts:
    def setup_method(self):
        self.privkeys = make_privkeys(3)
        self.pubkeys = make_pubkeys(self.privkeys)
        self.preimage, self.htlc_hash = generate_htlc_secret()
        self.winner_pk = self.pubkeys[0]
        self.T_REFUND = 576
        self.K_MIN = 2

    def test_htlc_winner_script_structure(self):
        winner_xonly = PublicKey.parse(self.winner_pk).xonly()
        script = _build_htlc_winner_script(winner_xonly, self.htlc_hash)
        # Should contain: push(32) <winner_xonly> OP_CHECKSIGVERIFY OP_SHA256 push(32) <H> OP_EQUAL
        assert winner_xonly in script
        assert self.htlc_hash in script
        assert b"\xAD" in script  # OP_CHECKSIGVERIFY
        assert b"\xA8" in script  # OP_SHA256
        assert b"\x87" in script  # OP_EQUAL

    def test_refund_script_structure(self):
        participants_xonly = [PublicKey.parse(pk).xonly() for pk in sorted(self.pubkeys)]
        script = _build_refund_script(participants_xonly, self.K_MIN, self.T_REFUND)
        assert b"\xB2" in script  # OP_CSV
        assert b"\x75" in script  # OP_DROP
        assert b"\xAC" in script  # OP_CHECKSIG (first key)
        assert b"\xBA" in script  # OP_CHECKSIGADD
        assert b"\x9C" in script  # OP_NUMEQUAL

    def test_tap_leaf_hash_length(self):
        script = b"\x51" * 10
        h = _tap_leaf_hash(script)
        assert len(h) == 32

    def test_tap_branch_hash_commutative(self):
        h1 = b"\x01" * 32
        h2 = b"\x02" * 32
        assert _tap_branch_hash(h1, h2) == _tap_branch_hash(h2, h1)

    def test_build_taproot_output_returns_address(self):
        rs = build_taproot_output(
            winner_pubkey=self.winner_pk,
            all_pubkeys=self.pubkeys,
            htlc_hash=self.htlc_hash,
            t_refund=self.T_REFUND,
            k_min=self.K_MIN,
        )
        assert rs.address.startswith("bcrt1p")  # bech32m regtest
        assert len(rs.output_key_xonly) == 32
        assert len(rs.internal_key_xonly) == 32
        assert len(rs.merkle_root) == 32

    def test_build_taproot_output_deterministic(self):
        rs1 = build_taproot_output(
            winner_pubkey=self.winner_pk,
            all_pubkeys=self.pubkeys,
            htlc_hash=self.htlc_hash,
            t_refund=self.T_REFUND,
            k_min=self.K_MIN,
        )
        rs2 = build_taproot_output(
            winner_pubkey=self.winner_pk,
            all_pubkeys=self.pubkeys,
            htlc_hash=self.htlc_hash,
            t_refund=self.T_REFUND,
            k_min=self.K_MIN,
        )
        assert rs1.address == rs2.address
        assert rs1.output_key_xonly == rs2.output_key_xonly

    def _make_addr(self, pk_bytes: bytes) -> str:
        """Derive a p2tr address from a compressed pubkey for testing."""
        xonly = PublicKey.parse(pk_bytes).xonly()
        from embit.script import Script as _Script
        spk = _Script(bytes([0x51, 0x20]) + xonly)
        return spk.address(network=REGTEST)

    def test_build_claim_tx_structure(self):
        rs = build_taproot_output(
            winner_pubkey=self.winner_pk,
            all_pubkeys=self.pubkeys,
            htlc_hash=self.htlc_hash,
            t_refund=self.T_REFUND,
            k_min=self.K_MIN,
        )
        utxos = [
            UTXO(
                txid="a" * 64,
                vout=0,
                amount_sats=btc_to_sats(0.01),
                script_pubkey=rs.script_pubkey.serialize(),
            )
            for _ in range(3)
        ]
        winner_addr = self._make_addr(self.winner_pk)
        tx = build_claim_tx(utxos, winner_addr)
        assert tx.version == 2
        assert len(tx.vin) == 3
        assert len(tx.vout) == 1

    def test_build_refund_tx_structure(self):
        rs = build_taproot_output(
            winner_pubkey=self.winner_pk,
            all_pubkeys=self.pubkeys,
            htlc_hash=self.htlc_hash,
            t_refund=self.T_REFUND,
            k_min=self.K_MIN,
        )
        utxos = [
            UTXO(
                txid="b" * 64,
                vout=0,
                amount_sats=btc_to_sats(0.01),
                script_pubkey=rs.script_pubkey.serialize(),
            )
        ]
        addrs = [self._make_addr(pk) for pk in self.pubkeys]
        tx = build_refund_tx(utxos, addrs, t_refund=576)
        assert tx.version == 2
        assert len(tx.vout) == 3
        # Each input sequence encodes the CSV lock
        assert tx.vin[0].sequence == 576


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_btc_sats_roundtrip(self):
        for btc in [0.001, 0.01, 0.1, 1.0, 10.0]:
            sats = btc_to_sats(btc)
            assert abs(sats_to_btc(sats) - btc) < 1e-9
