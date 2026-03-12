"""
Unit tests for tanda/lnrpc.py.

All tests use unittest.mock to stub pyln.client.LightningRpc,
so no running CLN node is required.

Plugin: BoltzExchange/hold v0.3+
  holdinvoice      payment_hash amount_msat  → {bolt11, payment_hash}
  settleholdinvoice preimage                 → {}
  cancelholdinvoice payment_hash             → {}
  listholdinvoices  [payment_hash]           → {invoices: [...]}
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from tanda.lnrpc import CLNRpc


SOCKET_PATH = "/tmp/fake/regtest/lightning-rpc"


@pytest.fixture
def mock_rpc():
    """Patch LightningRpc so no real unix socket is opened."""
    with patch("tanda.lnrpc.LightningRpc") as MockClass:
        instance = MagicMock()
        MockClass.return_value = instance
        cln = CLNRpc(SOCKET_PATH)
        yield cln, instance
        MockClass.assert_called_once_with(SOCKET_PATH)


# ── Node management ────────────────────────────────────────────────────────────

class TestGetInfo:
    def test_delegates_to_rpc(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.getinfo.return_value = {"id": "abc123", "alias": "test"}
        result = cln.get_info()
        rpc.getinfo.assert_called_once_with()
        assert result["id"] == "abc123"


class TestNewAddress:
    def test_returns_bech32(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.newaddr.return_value = {"bech32": "bcrt1qtest", "p2sh-segwit": "2Ntest"}
        result = cln.new_address()
        rpc.newaddr.assert_called_once_with()
        assert result == "bcrt1qtest"


class TestConnect:
    def test_passes_node_id_host_port(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.connect.return_value = {"id": "nodeid"}
        cln.connect("nodeid", "cln-p0", 9735)
        rpc.connect.assert_called_once_with("nodeid", "cln-p0", 9735)

    def test_default_port_9735(self, mock_rpc):
        cln, rpc = mock_rpc
        cln.connect("nodeid", "host")
        rpc.connect.assert_called_once_with("nodeid", "host", 9735)


class TestFundChannel:
    def test_passes_capacity_and_push(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.fundchannel.return_value = {"txid": "deadbeef", "outnum": 0}
        result = cln.fund_channel("nodeid", 200_000, push_msat=150_000_000)
        rpc.fundchannel.assert_called_once_with("nodeid", 200_000, push_msat=150_000_000)
        assert result["txid"] == "deadbeef"

    def test_default_push_zero(self, mock_rpc):
        cln, rpc = mock_rpc
        cln.fund_channel("nodeid", 100_000)
        rpc.fundchannel.assert_called_once_with("nodeid", 100_000, push_msat=0)


class TestListPeerChannels:
    def test_returns_channels_list(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listpeerchannels.return_value = {
            "channels": [{"state": "CHANNELD_NORMAL"}, {"state": "CHANNELD_AWAITING_LOCKIN"}]
        }
        result = cln.list_peer_channels()
        assert len(result) == 2
        assert result[0]["state"] == "CHANNELD_NORMAL"

    def test_missing_key_returns_empty(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listpeerchannels.return_value = {}
        assert cln.list_peer_channels() == []


class TestGetIncomingHtlcHashes:
    def test_returns_incoming_payment_hashes(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listpeerchannels.return_value = {
            "channels": [{
                "state": "CHANNELD_NORMAL",
                "htlcs": [
                    {"direction": "in", "payment_hash": PAYMENT_HASH, "id": 0},
                    {"direction": "out", "payment_hash": "c" * 64, "id": 1},
                ]
            }]
        }
        result = cln.get_incoming_htlc_hashes()
        assert result == {PAYMENT_HASH}

    def test_excludes_outgoing_htlcs(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listpeerchannels.return_value = {
            "channels": [{"htlcs": [{"direction": "out", "payment_hash": PAYMENT_HASH}]}]
        }
        assert cln.get_incoming_htlc_hashes() == set()

    def test_empty_when_no_htlcs(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listpeerchannels.return_value = {"channels": [{"state": "CHANNELD_NORMAL"}]}
        assert cln.get_incoming_htlc_hashes() == set()

    def test_aggregates_across_channels(self, mock_rpc):
        cln, rpc = mock_rpc
        hash1 = "a" * 64
        hash2 = "b" * 64
        rpc.listpeerchannels.return_value = {
            "channels": [
                {"htlcs": [{"direction": "in", "payment_hash": hash1}]},
                {"htlcs": [{"direction": "in", "payment_hash": hash2}]},
            ]
        }
        result = cln.get_incoming_htlc_hashes()
        assert result == {hash1, hash2}


# ── Hold invoices (BoltzExchange/hold plugin) ──────────────────────────────────

PAYMENT_HASH = "a" * 64    # 64 hex chars = 32 bytes
PREIMAGE_HEX = "b" * 64    # 64 hex chars = 32 bytes


class TestHoldInvoice:
    """
    holdinvoice v0.3+ (BoltzExchange/hold):
      - Takes payment_hash + amount_msat (coordinator keeps preimage secret)
      - No label, description, cltv, or expiry parameters
    """

    def test_calls_holdinvoice_with_payment_hash_and_amount(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {"bolt11": "lnbcrt...", "payment_hash": PAYMENT_HASH}

        result = cln.holdinvoice(
            payment_hash_hex=PAYMENT_HASH,
            amount_msat=10_000_000,
        )

        rpc.call.assert_called_once_with("holdinvoice", {
            "payment_hash": PAYMENT_HASH,
            "amount": 10_000_000,
        })
        assert result["bolt11"] == "lnbcrt..."

    def test_payment_hash_is_sha256_of_preimage(self, mock_rpc):
        """Coordinator derives payment_hash = sha256(preimage) before calling holdinvoice."""
        cln, rpc = mock_rpc
        preimage_bytes = bytes.fromhex(PREIMAGE_HEX)
        expected_hash = hashlib.sha256(preimage_bytes).hexdigest()
        rpc.call.return_value = {"payment_hash": expected_hash, "bolt11": "lnbcrt..."}

        cln.holdinvoice(payment_hash_hex=expected_hash, amount_msat=1_000)

        sent = rpc.call.call_args[0][1]
        assert sent["payment_hash"] == expected_hash
        # Preimage is NOT sent to the plugin; it stays secret with the coordinator
        assert "preimage" not in sent


class TestSettleHoldInvoice:
    """
    settleholdinvoice takes preimage (not payment_hash).
    The plugin derives payment_hash = sha256(preimage) internally.
    """

    def test_calls_settleholdinvoice_with_preimage(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {}
        cln.settle_holdinvoice(PREIMAGE_HEX)
        rpc.call.assert_called_once_with("settleholdinvoice", {"preimage": PREIMAGE_HEX})


class TestCancelHoldInvoice:
    def test_calls_cancelholdinvoice_with_payment_hash(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {}
        cln.cancel_holdinvoice(PAYMENT_HASH)
        rpc.call.assert_called_once_with("cancelholdinvoice", {"payment_hash": PAYMENT_HASH})


class TestListHoldInvoices:
    """listholdinvoices is a real non-blocking command in BoltzExchange/hold."""

    def test_no_filter_returns_all(self, mock_rpc):
        cln, rpc = mock_rpc
        invoices = [{"payment_hash": PAYMENT_HASH, "state": "ACCEPTED"}]
        rpc.call.return_value = {"invoices": invoices}
        result = cln.list_holdinvoices()
        rpc.call.assert_called_once_with("listholdinvoices", {})
        assert result[0]["state"] == "ACCEPTED"

    def test_with_payment_hash_filter(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {"invoices": [{"payment_hash": PAYMENT_HASH, "state": "PAID"}]}
        result = cln.list_holdinvoices(payment_hash_hex=PAYMENT_HASH)
        rpc.call.assert_called_once_with("listholdinvoices", {"payment_hash": PAYMENT_HASH})
        assert result[0]["state"] == "PAID"

    def test_missing_key_returns_empty(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {}
        assert cln.list_holdinvoices() == []

    def test_states_unpaid_accepted_paid_cancelled(self, mock_rpc):
        """BoltzExchange/hold states differ from daywalker90/holdinvoice."""
        cln, rpc = mock_rpc
        rpc.call.return_value = {"invoices": [
            {"state": "UNPAID"},
            {"state": "ACCEPTED"},
            {"state": "PAID"},
            {"state": "CANCELLED"},
        ]}
        result = cln.list_holdinvoices()
        states = {inv["state"] for inv in result}
        assert states == {"UNPAID", "ACCEPTED", "PAID", "CANCELLED"}


# ── Regular payments ───────────────────────────────────────────────────────────

class TestListInvoices:
    """list_invoices uses CLN standard listinvoices for non-hold invoice polling."""

    def test_no_filter_calls_listinvoices(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listinvoices.return_value = {"invoices": []}
        result = cln.list_invoices()
        rpc.listinvoices.assert_called_once_with()
        assert result == []

    def test_with_label_filter(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listinvoices.return_value = {"invoices": [{"label": "winner", "status": "paid"}]}
        result = cln.list_invoices(label="winner")
        rpc.listinvoices.assert_called_once_with(label="winner")
        assert result[0]["status"] == "paid"

    def test_missing_key_returns_empty(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.listinvoices.return_value = {}
        assert cln.list_invoices() == []


class TestInvoice:
    def test_delegates_to_rpc_invoice(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.invoice.return_value = {"bolt11": "lnbcrt100...", "label": "winner"}
        result = cln.invoice(100_000_000, "winner", "pot round 0")
        rpc.invoice.assert_called_once_with(100_000_000, "winner", "pot round 0")
        assert result["bolt11"] == "lnbcrt100..."


class TestPay:
    def test_delegates_to_rpc_pay(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.pay.return_value = {"payment_hash": PAYMENT_HASH, "status": "complete"}
        result = cln.pay("lnbcrt...")
        rpc.pay.assert_called_once_with("lnbcrt...")
        assert result["status"] == "complete"


class TestWaitInvoice:
    def test_delegates_to_rpc_waitinvoice(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.waitinvoice.return_value = {"label": "lbl", "status": "paid"}
        result = cln.wait_invoice("lbl")
        rpc.waitinvoice.assert_called_once_with("lbl")
        assert result["status"] == "paid"


# ── Message signing ─────────────────────────────────────────────────────────────

NODE_ID = "02" + "ab" * 32
ZBASE   = "rbxyz" * 10   # fake zbase32 signature


class TestSignMessage:
    def test_returns_zbase(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {"zbase": ZBASE, "message": "hello"}
        result = cln.sign_message("hello")
        rpc.call.assert_called_once_with("signmessage", {"message": "hello"})
        assert result == ZBASE

    def test_passes_full_message(self, mock_rpc):
        cln, rpc = mock_rpc
        msg = "tanda-renew:cycle=2:sats=10000:coordinator=03abc"
        rpc.call.return_value = {"zbase": ZBASE}
        cln.sign_message(msg)
        rpc.call.assert_called_once_with("signmessage", {"message": msg})


class TestCheckMessage:
    def test_returns_true_when_verified_and_pubkey_matches(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {"verified": True, "pubkey": NODE_ID}
        assert cln.check_message("hello", ZBASE, NODE_ID) is True
        rpc.call.assert_called_once_with("checkmessage", {"message": "hello", "zbase": ZBASE})

    def test_returns_false_when_not_verified(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {"verified": False, "pubkey": NODE_ID}
        assert cln.check_message("hello", ZBASE, NODE_ID) is False

    def test_returns_false_when_pubkey_mismatch(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {"verified": True, "pubkey": "03" + "ff" * 32}
        assert cln.check_message("hello", ZBASE, NODE_ID) is False

    def test_returns_false_when_verified_missing(self, mock_rpc):
        cln, rpc = mock_rpc
        rpc.call.return_value = {"pubkey": NODE_ID}
        assert cln.check_message("hello", ZBASE, NODE_ID) is False
