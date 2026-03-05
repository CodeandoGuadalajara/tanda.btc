"""
Unit tests for coordinator + participant logic (no live node required).
Uses mock RPC.
"""

import hashlib
from unittest.mock import MagicMock, patch
import pytest

import coincurve
from embit.ec import PublicKey as EmbitPublicKey
from embit.script import Script as EmbitScript

from tanda.htlc import generate_htlc_secret
from tanda.coordinator import Coordinator, TandaParams
from tanda.participant import Participant
from tanda.musig2 import (
    key_agg,
    nonce_gen,
    nonce_agg,
    partial_sign,
    partial_sig_agg,
    SessionContext,
    schnorr_verify,
)
from tanda.protocol import (
    UTXO,
    btc_to_sats,
    compute_taproot_sighash,
    REGTEST,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_privkeys(n: int) -> list[bytes]:
    return [hashlib.sha256(f"coord_key_{i}".encode()).digest() for i in range(n)]


def make_pubkeys(privkeys: list[bytes]) -> list[bytes]:
    return [coincurve.PrivateKey(sk).public_key.format(compressed=True) for sk in privkeys]


def _p2tr_addr(pk_bytes: bytes) -> str:
    """Derive a valid bech32m regtest address from a compressed pubkey."""
    xonly = EmbitPublicKey.parse(pk_bytes).xonly()
    spk = EmbitScript(bytes([0x51, 0x20]) + xonly)
    return spk.address(network=REGTEST)


def make_mock_rpc(wallet_name: str = "test") -> MagicMock:
    # Use a deterministic valid bech32m regtest addr as default
    _mock_sk = hashlib.sha256(b"mock_rpc_key").digest()
    _mock_pk = coincurve.PrivateKey(_mock_sk).public_key.format(compressed=True)
    _default_addr = _p2tr_addr(_mock_pk)
    rpc = MagicMock()
    rpc.get_new_address.return_value = _default_addr
    rpc.get_balance.return_value = 10.0
    rpc.fund_address.return_value = "a" * 64
    rpc.scan_utxos.return_value = []
    rpc.send_raw_transaction.return_value = "b" * 64
    rpc.mine.return_value = ["hash1"]
    return rpc


def make_params(n: int = 3) -> TandaParams:
    return TandaParams(
        n_participants=n,
        amount_btc=0.01,
        t_contribution=144,
        t_claim=288,
        t_refund=576,
        k_min=n - 1,
        winner_order=list(range(n)),
    )


# ── Setup tests ───────────────────────────────────────────────────────────────

class TestCoordinatorSetup:
    def setup_method(self):
        self.n = 3
        self.privkeys = make_privkeys(self.n)
        self.pubkeys = make_pubkeys(self.privkeys)
        self.rpc = make_mock_rpc()
        self.params = make_params(self.n)
        self.coord = Coordinator(self.rpc, self.params, self.pubkeys)

    def test_setup_creates_correct_number_of_rounds(self):
        setup = self.coord.setup()
        assert len(setup.rounds) == self.n

    def test_setup_rounds_have_unique_addresses(self):
        setup = self.coord.setup()
        addresses = [r.scripts.address for r in setup.rounds]
        assert len(set(addresses)) == self.n  # all different (different htlc_hash per round)

    def test_setup_rounds_have_htlc_secrets(self):
        setup = self.coord.setup()
        for rs in setup.rounds:
            assert len(rs.htlc_preimage) == 32
            assert len(rs.htlc_hash) == 32
            assert hashlib.sha256(rs.htlc_preimage).digest() == rs.htlc_hash

    def test_setup_winner_order(self):
        setup = self.coord.setup()
        for k, rs in enumerate(setup.rounds):
            assert rs.winner_index == k
            assert rs.winner_pubkey == self.pubkeys[k]

    def test_wrong_pubkey_count_raises(self):
        with pytest.raises(ValueError, match="pubkeys count"):
            Coordinator(self.rpc, self.params, self.pubkeys[:2])


# ── MuSig2 Cooperative claim tests ───────────────────────────────────────────

class TestCooperativeClaim:
    """Test the full MuSig2 signing flow (without broadcasting)."""

    def setup_method(self):
        self.n = 3
        self.privkeys = make_privkeys(self.n)
        self.pubkeys = make_pubkeys(self.privkeys)
        self.rpc = make_mock_rpc()
        self.params = make_params(self.n)
        self.coord = Coordinator(self.rpc, self.params, self.pubkeys)

    def _inject_utxos(self, rs, amount_btc: float = 0.01):
        """Inject mock UTXOs into round state."""
        for i in range(self.n):
            rs.contributions[i] = UTXO(
                txid=f"{'a' * 63}{i}",
                vout=0,
                amount_sats=btc_to_sats(amount_btc),
                script_pubkey=rs.scripts.script_pubkey.serialize(),
            )

    def test_musig2_claim_flow(self):
        setup = self.coord.setup()
        rs = setup.rounds[0]
        self._inject_utxos(rs)

        winner_addr = _p2tr_addr(make_pubkeys([hashlib.sha256(b"winner").digest()])[0])

        # Build claim tx
        from tanda.protocol import build_claim_tx
        utxos = list(rs.contributions.values())
        tx = build_claim_tx(utxos, winner_addr)
        rs.claim_tx = tx

        kac = rs.key_agg_ctx

        # Each participant generates nonce
        sec_nonces, pub_nonces = [], []
        for sk, pk in zip(self.privkeys, self.pubkeys):
            s, p = nonce_gen(sk=sk, pk=pk, agg_pk=kac.agg_pk)
            sec_nonces.append(s)
            pub_nonces.append(p)

        # Aggregate nonces
        from tanda.musig2 import nonce_agg, AggNonce
        agg = nonce_agg(pub_nonces)

        # Build session context
        sighash = compute_taproot_sighash(tx, 0, utxos)
        session = SessionContext(agg_nonce=agg, key_agg_ctx=kac, msg=sighash)

        # Each participant signs
        psigs = [
            partial_sign(s, sk, session)
            for s, sk in zip(sec_nonces, self.privkeys)
        ]

        # Aggregate
        final_sig = partial_sig_agg(psigs, session)
        assert len(final_sig) == 64

        # Verify against aggregate key
        assert schnorr_verify(final_sig, sighash, kac.agg_pk)

    def test_partial_sig_verify(self):
        """Each partial sig should independently verify."""
        from tanda.musig2 import partial_sig_verify

        setup = self.coord.setup()
        rs = setup.rounds[0]
        self._inject_utxos(rs)

        winner_addr = _p2tr_addr(make_pubkeys([hashlib.sha256(b"winner").digest()])[0])
        from tanda.protocol import build_claim_tx
        utxos = list(rs.contributions.values())
        tx = build_claim_tx(utxos, winner_addr)

        kac = rs.key_agg_ctx
        sighash = compute_taproot_sighash(tx, 0, utxos)

        sec_nonces, pub_nonces = [], []
        for sk, pk in zip(self.privkeys, self.pubkeys):
            s, p = nonce_gen(sk=sk, pk=pk, agg_pk=kac.agg_pk)
            sec_nonces.append(s)
            pub_nonces.append(p)

        from tanda.musig2 import nonce_agg
        agg = nonce_agg(pub_nonces)
        session = SessionContext(agg_nonce=agg, key_agg_ctx=kac, msg=sighash)

        for i, (s, sk, pn) in enumerate(
            zip(sec_nonces, self.privkeys, pub_nonces)
        ):
            pk_i = coincurve.PrivateKey(sk).public_key.format(compressed=True)
            psig = partial_sign(s, sk, session)
            assert partial_sig_verify(psig, pn, pk_i, session), f"Partial sig {i} failed"


# ── Refund info tests ─────────────────────────────────────────────────────────

class TestRefundInfo:
    def setup_method(self):
        self.n = 3
        self.privkeys = make_privkeys(self.n)
        self.pubkeys = make_pubkeys(self.privkeys)
        self.rpc = make_mock_rpc()
        self.params = make_params(self.n)
        self.coord = Coordinator(self.rpc, self.params, self.pubkeys)

    def test_build_refund_info_returns_correct_fields(self):
        setup = self.coord.setup()
        rs = setup.rounds[2]

        # Inject UTXOs
        for i in range(self.n):
            rs.contributions[i] = UTXO(
                txid=f"{'c' * 63}{i}",
                vout=0,
                amount_sats=btc_to_sats(0.01),
                script_pubkey=rs.scripts.script_pubkey.serialize(),
            )

        addrs = [_p2tr_addr(make_pubkeys([hashlib.sha256(f"refund_{i}".encode()).digest()])[0])
                 for i in range(self.n)]
        info = self.coord.build_refund_info(rs, addrs)

        assert "tx" in info
        assert "refund_script" in info
        assert "control_block" in info
        assert "utxos" in info
        assert len(info["control_block"]) == 65  # 1 + 32 + 32

    def test_htlc_claim_info_returns_correct_fields(self):
        setup = self.coord.setup()
        rs = setup.rounds[1]

        for i in range(self.n):
            rs.contributions[i] = UTXO(
                txid=f"{'d' * 63}{i}",
                vout=0,
                amount_sats=btc_to_sats(0.01),
                script_pubkey=rs.scripts.script_pubkey.serialize(),
            )

        winner_addr = _p2tr_addr(make_pubkeys([hashlib.sha256(b"winner").digest()])[0])
        info = self.coord.build_htlc_claim_info(rs, winner_addr)

        assert "tx" in info
        assert "htlc_script" in info
        assert "control_block" in info
        assert "preimage" in info
        assert verify_preimage(info["preimage"], rs.htlc_hash)

    def test_control_block_length(self):
        """Control block = 1 byte version+parity + 32 internal key + 32 sibling hash."""
        setup = self.coord.setup()
        rs = setup.rounds[0]
        scripts = rs.scripts
        sibling = scripts.tap_tree.leaf2.leaf_hash
        from tanda.protocol import build_control_block
        cb = build_control_block(
            internal_key_xonly=scripts.internal_key_xonly,
            output_key_parity=scripts.output_key_parity,
            sibling_hash=sibling,
        )
        assert len(cb) == 65


# ── Participant tests ─────────────────────────────────────────────────────────

class TestParticipant:
    def setup_method(self):
        self.n = 3
        self.privkeys = make_privkeys(self.n)
        self.pubkeys = make_pubkeys(self.privkeys)

    def test_participant_pubkey(self):
        p = Participant(0, self.privkeys[0], make_mock_rpc())
        assert p.pubkey == self.pubkeys[0]

    def test_participant_contribute(self):
        rpc = make_mock_rpc()
        p = Participant(0, self.privkeys[0], rpc)
        txid = p.contribute("bcrt1test", 0.01)
        rpc.fund_address.assert_called_once_with("bcrt1test", 0.01)
        assert txid == "a" * 64

    def test_participant_nonce_generation(self):
        p = Participant(0, self.privkeys[0], make_mock_rpc())
        kac = key_agg(self.pubkeys)
        pub_nonce = p.generate_nonce(kac.agg_pk)
        assert len(pub_nonce.serialize()) == 66

    def test_participant_sign_claim(self):
        """Participant can sign a session context."""
        kac = key_agg(self.pubkeys)
        msg = hashlib.sha256(b"test").digest()

        participants = [
            Participant(i, self.privkeys[i], make_mock_rpc())
            for i in range(self.n)
        ]

        # Generate nonces
        pub_nonces = [p.generate_nonce(kac.agg_pk, msg) for p in participants]

        # Aggregate nonce
        from tanda.musig2 import nonce_agg
        agg = nonce_agg(pub_nonces)
        session = SessionContext(agg_nonce=agg, key_agg_ctx=kac, msg=msg)

        # Sign
        psigs = [p.sign_claim(session) for p in participants]
        assert all(isinstance(s, int) for s in psigs)

        # Aggregate and verify
        final_sig = partial_sig_agg(psigs, session)
        assert schnorr_verify(final_sig, msg, kac.agg_pk)


def verify_preimage(preimage: bytes, htlc_hash: bytes) -> bool:
    return hashlib.sha256(preimage).digest() == htlc_hash
