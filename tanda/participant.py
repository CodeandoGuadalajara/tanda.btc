"""
Participant logic for the tanda protocol.

Each participant:
  - Holds a private key (sk) and knows the round parameters
  - Sends their contribution to the round's taproot address
  - Participates in MuSig2 signing for the cooperative claim
  - Can independently claim via HTLC (if they are the winner and coop fails)
  - Can participate in collective refund (if winner disappears)
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import Optional

from embit.ec import PrivateKey, PublicKey

from .musig2 import (
    SecNonce,
    PubNonce,
    AggNonce,
    SessionContext,
    key_agg,
    nonce_gen,
    partial_sign,
    partial_sig_verify,
)
from .protocol import (
    UTXO,
    RoundScripts,
    compute_taproot_sighash,
    sign_tapscript,
    make_htlc_claim_witness,
    make_refund_witness,
    build_control_block,
    btc_to_sats,
    REGTEST,
    TAPSCRIPT_LEAF_VERSION,
)
from .htlc import verify_preimage
from .rpc import BitcoinRPC


# ── Participant class ─────────────────────────────────────────────────────────

class Participant:
    """
    Represents one tanda participant.

    Args:
        idx:      0-based index in the participant list
        sk_bytes: 32-byte private key
        rpc:      BitcoinRPC connected to their wallet
    """

    def __init__(
        self,
        idx: int,
        sk_bytes: bytes,
        rpc: BitcoinRPC,
        network: dict = REGTEST,
    ):
        self.idx = idx
        self._sk = PrivateKey(sk_bytes)
        self._sk_bytes = sk_bytes
        self.pubkey = self._sk.get_public_key().sec()  # 33-byte compressed
        self.rpc = rpc
        self.network = network

        # MuSig2 nonce pair (generated fresh each round)
        self._sec_nonce: Optional[SecNonce] = None
        self._pub_nonce: Optional[PubNonce] = None

    # ── Setup ─────────────────────────────────────────────────────────────────

    def acknowledge_setup(self, setup_info: dict) -> bytes:
        """
        Receive round parameters and return pubkey as acknowledgement.
        In a real system this would verify the setup_info signature.
        """
        return self.pubkey

    # ── Contribution ──────────────────────────────────────────────────────────

    def contribute(self, address: str, amount_btc: float) -> str:
        """
        Send contribution to the round's taproot address.

        Returns:
            txid of the contribution transaction
        """
        txid = self.rpc.fund_address(address, amount_btc)
        return txid

    # ── MuSig2 nonce generation ───────────────────────────────────────────────

    def generate_nonce(self, agg_pk: bytes, msg: Optional[bytes] = None) -> PubNonce:
        """
        Generate a fresh (sec_nonce, pub_nonce) pair and return the public part.
        The secret nonce is stored internally for use during signing.
        """
        sec, pub = nonce_gen(
            sk=self._sk_bytes,
            pk=self.pubkey,
            agg_pk=agg_pk,
            msg=msg,
        )
        self._sec_nonce = sec
        self._pub_nonce = pub
        return pub

    # ── MuSig2 partial signing ────────────────────────────────────────────────

    def sign_claim(self, session_ctx: SessionContext) -> int:
        """
        Produce a MuSig2 partial signature for the cooperative claim.

        Args:
            session_ctx: session context from coordinator

        Returns:
            Partial signature scalar s_i
        """
        if self._sec_nonce is None:
            raise RuntimeError("Call generate_nonce() before sign_claim()")

        psig = partial_sign(
            sec_nonce=self._sec_nonce,
            sk=self._sk_bytes,
            session_ctx=session_ctx,
        )
        # Zero out sec_nonce (use-once)
        self._sec_nonce = None
        return psig

    # ── HTLC winner claim (fallback leaf1) ────────────────────────────────────

    def claim_htlc(
        self,
        tx: object,            # unsigned Transaction
        utxos: list[UTXO],
        htlc_script: bytes,
        control_block: bytes,
        preimage: bytes,
    ) -> str:
        """
        Sign and broadcast the HTLC scriptpath claim (leaf1).
        Called by the round winner when cooperative signing failed.

        Args:
            tx:            unsigned claim transaction
            utxos:         list of input UTXOs
            htlc_script:   the raw tapscript bytes for leaf1
            control_block: the control block bytes
            preimage:      the HTLC pre-image (secret received from coordinator)

        Returns:
            txid of the broadcast transaction
        """
        if not verify_preimage(preimage, self._derive_htlc_hash_from_script(htlc_script)):
            raise ValueError("Preimage does not match hash in script")

        # Sign each input
        for i in range(len(tx.vin)):
            sig = sign_tapscript(
                tx=tx,
                input_index=i,
                utxos=utxos,
                privkey=self._sk,
                script=htlc_script,
            )
            tx.vin[i].witness = make_htlc_claim_witness(
                winner_sig=sig,
                preimage=preimage,
                htlc_script=htlc_script,
                control_block=control_block,
            )

        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()
        return self.rpc.send_raw_transaction(tx_hex)

    def _derive_htlc_hash_from_script(self, htlc_script: bytes) -> bytes:
        """
        Parse the HTLC script to extract the 32-byte hash.
        Script: <pk> OP_CHECKSIGVERIFY OP_SHA256 <H> OP_EQUAL
        """
        # The hash is the 32 bytes after OP_SHA256 (0xA8)
        idx = htlc_script.index(0xA8) + 1  # skip OP_SHA256
        push_len = htlc_script[idx]         # should be 0x20 = 32
        return htlc_script[idx + 1: idx + 1 + push_len]

    # ── Collective refund signing (fallback leaf2) ────────────────────────────

    def sign_refund(
        self,
        tx: object,            # unsigned refund Transaction
        utxos: list[UTXO],
        refund_script: bytes,
    ) -> bytes:
        """
        Produce a Schnorr signature for the refund script-path (leaf2).

        Returns:
            64-byte Schnorr signature (or 65 if explicit sighash type)
        """
        sig = sign_tapscript(
            tx=tx,
            input_index=0,
            utxos=utxos,
            privkey=self._sk,
            script=refund_script,
        )
        return sig

    def broadcast_refund(
        self,
        tx: object,
        sigs: list[bytes],      # sig per participant (b"" if not signing)
        refund_script: bytes,
        control_block: bytes,
    ) -> str:
        """
        Attach witness and broadcast the refund transaction.

        Args:
            sigs:          one sig per participant in sorted-key order
            refund_script: the raw tapscript bytes for leaf2

        Returns:
            txid
        """
        for i in range(len(tx.vin)):
            tx.vin[i].witness = make_refund_witness(sigs, refund_script, control_block)

        buf = BytesIO()
        tx.write_to(buf)
        tx_hex = buf.getvalue().hex()
        return self.rpc.send_raw_transaction(tx_hex)

    # ── Informational ─────────────────────────────────────────────────────────

    def get_address(self) -> str:
        return self.rpc.get_new_address()

    def get_balance(self) -> float:
        return self.rpc.get_balance()
