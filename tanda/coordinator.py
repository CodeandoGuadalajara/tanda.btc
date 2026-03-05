"""
Coordinator logic for the tanda protocol.

The coordinator is a trustless role: any participant can fill it.
The coordinator:
  1. Publishes round parameters (winner order, amounts, timelocks)
  2. Generates HTLC secrets (shares only with the round winner)
  3. Monitors contributions on-chain
  4. Builds and circulates claim PSBTs for co-signing (MuSig2)
  5. Aggregates partial signatures and broadcasts claim_tx
  6. Falls back to HTLC / refund paths if cooperation fails
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from .htlc import generate_htlc_secret, verify_preimage
from .protocol import (
    UTXO,
    RoundScripts,
    build_taproot_output,
    build_claim_tx,
    build_htlc_claim_tx,
    build_refund_tx,
    compute_taproot_sighash,
    make_keypath_witness,
    make_htlc_claim_witness,
    make_refund_witness,
    build_control_block,
    taproot_tweak,
    btc_to_sats,
    sats_to_btc,
    REGTEST,
)
from .musig2 import (
    KeyAggContext,
    SecNonce,
    PubNonce,
    AggNonce,
    SessionContext,
    key_agg,
    nonce_gen,
    nonce_agg,
    partial_sign,
    partial_sig_agg,
    schnorr_verify,
    apply_tweak,
)
from .rpc import BitcoinRPC


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class TandaParams:
    """Immutable parameters agreed upon at setup time."""
    n_participants: int
    amount_btc: float           # contribution per participant per round
    t_contribution: int         # blocks to wait for all contributions
    t_claim: int                # blocks after which winner can use HTLC path
    t_refund: int               # blocks after which collective refund is possible
    k_min: int                  # minimum sigs needed for refund (usually n-1)
    winner_order: list[int]     # winner_order[k] = index of winner in round k

    @property
    def amount_sats(self) -> int:
        return btc_to_sats(self.amount_btc)


@dataclass
class RoundState:
    """Mutable state for a single tanda round."""
    round_index: int            # 0-based
    winner_index: int           # index into participants list
    winner_pubkey: bytes        # 33-byte compressed pubkey of winner
    htlc_preimage: bytes        # secret; shared only with winner
    htlc_hash: bytes            # public; shared with all
    scripts: RoundScripts       # taproot scripts + address
    key_agg_ctx: KeyAggContext  # MuSig2 key aggregation context

    # Filled in as the round progresses
    contributions: dict[int, UTXO] = field(default_factory=dict)  # participant_idx → UTXO
    partial_sigs: dict[int, int] = field(default_factory=dict)    # participant_idx → psig
    pub_nonces: dict[int, PubNonce] = field(default_factory=dict) # participant_idx → pubnonce
    coordinator_sec_nonce: Optional[SecNonce] = None
    coordinator_pub_nonce: Optional[PubNonce] = None
    agg_nonce: Optional[AggNonce] = None
    claim_tx: Optional[object] = None
    claim_txid: Optional[str] = None
    session_ctx: Optional[SessionContext] = None


@dataclass
class TandaSetup:
    """Full setup state: params + per-participant keys + per-round scripts."""
    params: TandaParams
    pubkeys: list[bytes]        # 33-byte compressed pubkeys, index = participant index
    rounds: list[RoundState]    # one per participant


# ── Coordinator class ─────────────────────────────────────────────────────────

class Coordinator:
    """
    Trustless tanda coordinator.

    Usage:
        coord = Coordinator(rpc, params, pubkeys)
        setup = coord.setup()
        # ... participants send contributions ...
        coord.run_round(setup, round_idx=0, winner_addr="bcrt1...")
    """

    def __init__(
        self,
        rpc: BitcoinRPC,
        params: TandaParams,
        pubkeys: list[bytes],
        network: dict = REGTEST,
    ):
        if len(pubkeys) != params.n_participants:
            raise ValueError("pubkeys count must match n_participants")
        self.rpc = rpc
        self.params = params
        self.pubkeys = pubkeys
        self.network = network

    # ── Setup ─────────────────────────────────────────────────────────────────

    def setup(self) -> TandaSetup:
        """
        Build per-round HTLC secrets and taproot addresses.
        Returns TandaSetup to be shared with all participants.
        """
        params = self.params
        rounds: list[RoundState] = []

        for k in range(params.n_participants):
            winner_idx = params.winner_order[k]
            winner_pk = self.pubkeys[winner_idx]

            preimage, htlc_hash = generate_htlc_secret()

            scripts = build_taproot_output(
                winner_pubkey=winner_pk,
                all_pubkeys=self.pubkeys,
                htlc_hash=htlc_hash,
                t_refund=params.t_refund,
                k_min=params.k_min,
                network=self.network,
            )

            # Build the KeyAggContext with the Taproot tweak applied so that
            # kac.agg_pk == scripts.output_key_xonly (required for keypath signing).
            kac = key_agg(self.pubkeys)
            tweak_bytes = taproot_tweak(scripts.internal_key_xonly, scripts.merkle_root)
            kac = apply_tweak(kac, tweak_bytes, is_xonly=True)

            rs = RoundState(
                round_index=k,
                winner_index=winner_idx,
                winner_pubkey=winner_pk,
                htlc_preimage=preimage,
                htlc_hash=htlc_hash,
                scripts=scripts,
                key_agg_ctx=kac,
            )
            rounds.append(rs)

        return TandaSetup(params=params, pubkeys=self.pubkeys, rounds=rounds)

    # ── Contribution monitoring ────────────────────────────────────────────────

    def collect_contributions(
        self,
        rs: RoundState,
        min_confirmations: int = 1,
    ) -> bool:
        """
        Scan the blockchain for contributions to rs.scripts.address.
        Returns True if all N participants have contributed.
        """
        address = rs.scripts.address
        utxos = self.rpc.scan_utxos(address)

        n = self.params.n_participants
        expected_sats = self.params.amount_sats

        # Each contribution is a separate UTXO to the round address.
        # We match by amount.
        found = []
        for u in utxos:
            if round(u.get("amount", 0) * 100_000_000) >= expected_sats * 0.99:
                utxo = UTXO(
                    txid=u["txid"],
                    vout=u["vout"],
                    amount_sats=round(u["amount"] * 100_000_000),
                    script_pubkey=bytes.fromhex(u.get("scriptPubKey", {}).get("hex", "") or
                                                 rs.scripts.script_pubkey.serialize().hex()),
                )
                found.append(utxo)

        # Store found UTXOs (we can't assign per-participant without extra info;
        # just store all found UTXOs keyed by index)
        for i, utxo in enumerate(found):
            rs.contributions[i] = utxo

        return len(found) >= n

    # ── MuSig2 signing flow ────────────────────────────────────────────────────

    def prepare_claim_session(
        self,
        rs: RoundState,
        winner_address: str,
        coordinator_sk: Optional[bytes] = None,
    ) -> dict:
        """
        Build the claim transaction, generate coordinator nonce (if coordinator
        is also a participant), and return the session info to distribute.

        Returns dict with: claim_tx_hex, utxos, htlc_hash, round_index
        """
        utxos = list(rs.contributions.values())
        if not utxos:
            raise ValueError("No contributions found")

        tx = build_claim_tx(utxos, winner_address, network=self.network)
        rs.claim_tx = tx

        # If coordinator is also a participant, generate their nonce
        if coordinator_sk is not None:
            sec, pub = nonce_gen(sk=coordinator_sk, pk=rs.key_agg_ctx.agg_pk)
            rs.coordinator_sec_nonce = sec
            rs.coordinator_pub_nonce = pub

        from embit.transaction import Transaction
        from io import BytesIO
        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()

        return {
            "round_index": rs.round_index,
            "claim_tx_hex": tx_hex,
            "htlc_hash": rs.htlc_hash.hex(),
            "utxos": [
                {"txid": u.txid, "vout": u.vout, "amount_sats": u.amount_sats}
                for u in utxos
            ],
        }

    def collect_pub_nonce(self, rs: RoundState, participant_idx: int, pub_nonce: PubNonce):
        """Register a participant's public nonce."""
        rs.pub_nonces[participant_idx] = pub_nonce

    def finalize_nonce_aggregation(self, rs: RoundState) -> AggNonce:
        """Once all public nonces are collected, compute the aggregate nonce."""
        nonces = list(rs.pub_nonces.values())
        if rs.coordinator_pub_nonce is not None:
            nonces.append(rs.coordinator_pub_nonce)
        agg = nonce_agg(nonces)
        rs.agg_nonce = agg
        return agg

    def build_session_context(self, rs: RoundState, winner_address: str) -> SessionContext:
        """Build the MuSig2 session context from the claim tx sighash."""
        utxos = list(rs.contributions.values())
        tx = rs.claim_tx

        sighash = compute_taproot_sighash(tx, 0, utxos)
        session_ctx = SessionContext(
            agg_nonce=rs.agg_nonce,
            key_agg_ctx=rs.key_agg_ctx,
            msg=sighash,
        )
        rs.session_ctx = session_ctx
        return session_ctx

    def collect_partial_sig(self, rs: RoundState, participant_idx: int, psig: int):
        """Register a participant's partial signature."""
        rs.partial_sigs[participant_idx] = psig

    def aggregate_and_broadcast(self, rs: RoundState) -> str:
        """
        Aggregate partial signatures, attach witness to claim_tx, broadcast.
        Returns txid.
        """
        psigs = list(rs.partial_sigs.values())
        final_sig = partial_sig_agg(psigs, rs.session_ctx)

        # Attach witness to each input
        tx = rs.claim_tx
        for i in range(len(tx.vin)):
            tx.vin[i].witness = make_keypath_witness(final_sig)

        from io import BytesIO
        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()

        txid = self.rpc.send_raw_transaction(tx_hex)
        rs.claim_txid = txid
        return txid

    # ── Fallback paths ─────────────────────────────────────────────────────────

    def build_htlc_claim_info(self, rs: RoundState, winner_address: str) -> dict:
        """
        Return the data needed for the winner to broadcast the HTLC claim tx.
        Called when cooperative path fails (some participant didn't sign).
        """
        utxos = list(rs.contributions.values())
        scripts = rs.scripts

        tx = build_htlc_claim_tx(utxos, winner_address, network=self.network)
        htlc_script = scripts.tap_tree.leaf1.script
        sibling_hash = scripts.tap_tree.leaf2.leaf_hash
        control_block = build_control_block(
            internal_key_xonly=scripts.internal_key_xonly,
            output_key_parity=scripts.output_key_parity,
            sibling_hash=sibling_hash,
        )

        from io import BytesIO
        buf = BytesIO()
        tx.write_to(buf)

        return {
            "tx": tx,
            "tx_hex_unsigned": buf.getvalue().hex(),
            "htlc_script": htlc_script,
            "control_block": control_block,
            "utxos": utxos,
            "preimage": rs.htlc_preimage,  # sent only to winner
        }

    def build_refund_info(self, rs: RoundState, participant_addresses: list[str]) -> dict:
        """
        Return data needed for participants to build a collective refund.
        Called when winner disappears and T_refund has passed.
        """
        utxos = list(rs.contributions.values())
        scripts = rs.scripts

        tx = build_refund_tx(
            utxos=utxos,
            participant_addresses=participant_addresses,
            t_refund=self.params.t_refund,
            network=self.network,
        )
        refund_script = scripts.tap_tree.leaf2.script
        sibling_hash = scripts.tap_tree.leaf1.leaf_hash
        control_block = build_control_block(
            internal_key_xonly=scripts.internal_key_xonly,
            output_key_parity=scripts.output_key_parity,
            sibling_hash=sibling_hash,
        )

        from io import BytesIO
        buf = BytesIO()
        tx.write_to(buf)

        return {
            "tx": tx,
            "tx_hex_unsigned": buf.getvalue().hex(),
            "refund_script": refund_script,
            "control_block": control_block,
            "utxos": utxos,
        }

    def broadcast_refund(
        self,
        rs: RoundState,
        tx: object,
        sigs: list[bytes],
        refund_script: bytes,
        control_block: bytes,
    ) -> str:
        """Attach refund witness and broadcast."""
        for i in range(len(tx.vin)):
            tx.vin[i].witness = make_refund_witness(sigs, refund_script, control_block)

        from io import BytesIO
        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()
        return self.rpc.send_raw_transaction(tx_hex)

    # ── Utilities ──────────────────────────────────────────────────────────────

    def wait_for_confirmations(self, n: int = 1):
        """Mine *n* blocks to confirm transactions (regtest helper)."""
        self.rpc.mine(n)

    def get_round_address(self, setup: TandaSetup, round_idx: int) -> str:
        return setup.rounds[round_idx].scripts.address
