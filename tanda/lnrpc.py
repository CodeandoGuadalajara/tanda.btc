"""
CLN RPC wrapper using pyln-client unix socket.

hold plugin v0.3+ API (BoltzExchange/hold):
  holdinvoice      payment_hash amount_msat
  settleholdinvoice preimage
  cancelholdinvoice payment_hash
  listholdinvoices  [payment_hash] [bolt11]  → {invoices: [...]}

Hold invoice states:
  UNPAID    → created, no HTLC received yet
  ACCEPTED  → HTLC(s) held, waiting for settle/cancel
  PAID      → preimage revealed, settled
  CANCELLED → cancelled, HTLCs returned

Key difference from daywalker90/holdinvoice:
  - Creation takes payment_hash (not preimage); coordinator keeps the preimage secret
  - Settlement takes preimage (not payment_hash); revealing it to claim the funds
"""

from __future__ import annotations

from pyln.client import LightningRpc


class CLNRpc:
    def __init__(self, socket_path: str):
        self._rpc = LightningRpc(socket_path)

    # ── Node management ────────────────────────────────────────────────────────

    def get_info(self) -> dict:
        return self._rpc.getinfo()

    def new_address(self) -> str:
        """Return a bech32 on-chain address for funding this CLN node."""
        return self._rpc.newaddr()["bech32"]

    def connect(self, node_id: str, host: str, port: int = 9735) -> dict:
        return self._rpc.connect(node_id, host, port)

    def fund_channel(self, node_id: str, amount_sat: int, push_msat: int = 0) -> dict:
        """Open a channel; push_msat sats are pushed to the remote peer on open."""
        return self._rpc.fundchannel(node_id, amount_sat, push_msat=push_msat)

    def list_peer_channels(self) -> list[dict]:
        return self._rpc.listpeerchannels().get("channels", [])

    def get_incoming_htlc_hashes(self) -> set[str]:
        """Return payment_hashes of all currently-held incoming HTLCs across all channels."""
        result: set[str] = set()
        for ch in self.list_peer_channels():
            for htlc in ch.get("htlcs", []):
                if htlc.get("direction") == "in":
                    ph = htlc.get("payment_hash", "")
                    if ph:
                        result.add(ph)
        return result

    def list_funds(self) -> dict:
        return self._rpc.listfunds()

    # ── Hold invoices (BoltzExchange/hold plugin) ──────────────────────────────

    def holdinvoice(self, payment_hash_hex: str, amount_msat: int) -> dict:
        """
        Create a hold invoice.

        The coordinator generates the preimage externally, computes
        payment_hash = sha256(preimage), and passes payment_hash here.
        CLN holds any incoming HTLC for this hash until settleholdinvoice
        or cancelholdinvoice is called.

        Returns a dict containing at least {"bolt11": ..., "payment_hash": ...}.
        """
        return self._rpc.call("holdinvoice", {
            "payment_hash": payment_hash_hex,
            "amount": amount_msat,
        })

    def settle_holdinvoice(self, preimage_hex: str) -> dict:
        """
        Settle a hold invoice by revealing the preimage.

        Call AFTER paying the winner so the coordinator recovers liquidity last.
        The plugin derives payment_hash = sha256(preimage) internally.
        """
        return self._rpc.call("settleholdinvoice", {"preimage": preimage_hex})

    def cancel_holdinvoice(self, payment_hash_hex: str) -> dict:
        """Cancel a hold invoice and return any pending HTLCs (fallback path)."""
        return self._rpc.call("cancelholdinvoice", {"payment_hash": payment_hash_hex})

    def list_holdinvoices(self, payment_hash_hex: str | None = None) -> list[dict]:
        """
        List hold invoices managed by the hold plugin.
        Each invoice has a 'state' field: UNPAID, ACCEPTED, PAID, CANCELLED.
        """
        params: dict = {}
        if payment_hash_hex:
            params["payment_hash"] = payment_hash_hex
        return self._rpc.call("listholdinvoices", params).get("invoices", [])

    # ── Regular payments ───────────────────────────────────────────────────────

    def list_invoices(
        self,
        label: str | None = None,
        payment_hash_hex: str | None = None,
    ) -> list[dict]:
        """Non-blocking invoice poll via CLN's standard listinvoices."""
        params: dict = {}
        if label:
            params["label"] = label
        if payment_hash_hex:
            params["payment_hash"] = payment_hash_hex
        return self._rpc.listinvoices(**params).get("invoices", [])

    def invoice(self, amount_msat: int, label: str, description: str) -> dict:
        """Create a regular (non-hold) invoice. Returns {"bolt11": ...}."""
        return self._rpc.invoice(amount_msat, label, description)

    def pay(self, bolt11: str) -> dict:
        """Pay a bolt11 invoice. Returns payment result dict."""
        return self._rpc.pay(bolt11)

    def wait_invoice(self, label: str) -> dict:
        """Block until the invoice with this label is paid."""
        return self._rpc.waitinvoice(label)

    # ── Message signing ────────────────────────────────────────────────────────

    def sign_message(self, message: str) -> str:
        """
        Sign a UTF-8 message with this node's private key.
        Returns a zbase32-encoded signature.
        CLN prepends "lightning:" internally before hashing — checkmessage handles this.
        """
        return self._rpc.call("signmessage", {"message": message})["zbase"]

    def check_message(self, message: str, zbase: str, node_id: str) -> bool:
        """
        Verify a zbase32 signature produced by signmessage.
        Returns True if the signature is valid and was produced by node_id.
        """
        result = self._rpc.call("checkmessage", {"message": message, "zbase": zbase})
        return result.get("verified", False) and result.get("pubkey") == node_id
