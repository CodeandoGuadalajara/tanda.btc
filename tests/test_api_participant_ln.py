"""
Unit tests for tanda/api_participant_ln.py.

Uses FastAPI TestClient and mocks CLNRpc so no CLN node is required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


SOCKET_PATH = "/tmp/fake/regtest/lightning-rpc"
NODE_ID     = "02" + "ab" * 32   # 33-byte compressed pubkey in hex
BOLT11      = "lnbcrt100u1p..."
PAYMENT_HASH = "c" * 64


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """
    Start the FastAPI app with CLN_RPC_PATH set and CLNRpc mocked out.
    Returns (TestClient, mock_cln_instance).
    """
    mock_cln = MagicMock()

    # Default stubs so /health works on startup
    mock_cln.get_info.return_value = {"id": NODE_ID, "alias": "test", "address": []}
    mock_cln.list_peer_channels.return_value = []

    with patch.dict("os.environ", {"CLN_RPC_PATH": SOCKET_PATH}):
        with patch("tanda.api_participant_ln.CLNRpc", return_value=mock_cln):
            from tanda.api_participant_ln import app
            with TestClient(app) as tc:
                yield tc, mock_cln


# ── /health ────────────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_ok_and_pubkey(self, client):
        tc, mock_cln = client
        mock_cln.get_info.return_value = {"id": NODE_ID, "address": []}
        mock_cln.list_peer_channels.return_value = []

        r = tc.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["pubkey_hex"] == NODE_ID

    def test_includes_channels(self, client):
        tc, mock_cln = client
        channels = [{"state": "CHANNELD_NORMAL", "peer_id": "03" + "cd" * 32}]
        mock_cln.get_info.return_value = {"id": NODE_ID, "address": []}
        mock_cln.list_peer_channels.return_value = channels

        r = tc.get("/health")
        assert r.status_code == 200
        assert r.json()["channels"] == channels

    def test_cln_error_propagates(self, client):
        tc, mock_cln = client
        mock_cln.get_info.side_effect = RuntimeError("socket not found")
        # TestClient re-raises unhandled server exceptions by default
        with pytest.raises(RuntimeError, match="socket not found"):
            tc.get("/health")


# ── /node_info ─────────────────────────────────────────────────────────────────

class TestNodeInfo:
    def test_returns_id_and_first_address(self, client):
        tc, mock_cln = client
        mock_cln.get_info.return_value = {
            "id": NODE_ID,
            "address": [{"type": "ipv4", "address": "1.2.3.4", "port": 9735}],
        }
        r = tc.get("/node_info")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == NODE_ID
        assert data["address"]["address"] == "1.2.3.4"

    def test_empty_address_list(self, client):
        tc, mock_cln = client
        mock_cln.get_info.return_value = {"id": NODE_ID, "address": []}
        r = tc.get("/node_info")
        assert r.status_code == 200
        assert r.json()["address"] == {}

    def test_missing_address_field(self, client):
        tc, mock_cln = client
        mock_cln.get_info.return_value = {"id": NODE_ID}
        r = tc.get("/node_info")
        assert r.status_code == 200
        assert r.json()["address"] == {}


# ── POST /pay_invoice ──────────────────────────────────────────────────────────

class TestPayInvoice:
    def test_returns_payment_hash(self, client):
        tc, mock_cln = client
        mock_cln.pay.return_value = {"payment_hash": PAYMENT_HASH, "status": "complete"}

        r = tc.post("/pay_invoice", json={"bolt11": BOLT11})
        assert r.status_code == 200
        assert r.json()["payment_hash"] == PAYMENT_HASH
        mock_cln.pay.assert_called_once_with(BOLT11)

    def test_cln_error_returns_500(self, client):
        tc, mock_cln = client
        mock_cln.pay.side_effect = Exception("route not found")

        r = tc.post("/pay_invoice", json={"bolt11": BOLT11})
        assert r.status_code == 500
        assert "payment failed" in r.json()["detail"]

    def test_missing_payment_hash_in_response(self, client):
        tc, mock_cln = client
        mock_cln.pay.return_value = {}   # no payment_hash key

        r = tc.post("/pay_invoice", json={"bolt11": BOLT11})
        assert r.status_code == 200
        assert r.json()["payment_hash"] == ""   # defaults to empty string

    def test_missing_bolt11_field_returns_422(self, client):
        tc, mock_cln = client
        r = tc.post("/pay_invoice", json={})
        assert r.status_code == 422


# ── POST /create_invoice ───────────────────────────────────────────────────────

class TestCreateInvoice:
    def test_returns_bolt11(self, client):
        tc, mock_cln = client
        mock_cln.invoice.return_value = {"bolt11": BOLT11, "label": "pot-round-0"}

        r = tc.post("/create_invoice", json={"amount_msat": 30_000_000, "label": "pot-round-0"})
        assert r.status_code == 200
        assert r.json()["bolt11"] == BOLT11
        mock_cln.invoice.assert_called_once_with(30_000_000, "pot-round-0", "pot-round-0")

    def test_cln_error_returns_500(self, client):
        tc, mock_cln = client
        mock_cln.invoice.side_effect = Exception("duplicate label")

        r = tc.post("/create_invoice", json={"amount_msat": 1_000, "label": "lbl"})
        assert r.status_code == 500
        assert "invoice creation failed" in r.json()["detail"]

    def test_missing_fields_returns_422(self, client):
        tc, mock_cln = client
        r = tc.post("/create_invoice", json={"amount_msat": 1_000})
        assert r.status_code == 422

    def test_label_used_as_description(self, client):
        """label is passed as both label and description to cln.invoice()."""
        tc, mock_cln = client
        mock_cln.invoice.return_value = {"bolt11": BOLT11}

        tc.post("/create_invoice", json={"amount_msat": 5_000, "label": "my-label"})
        mock_cln.invoice.assert_called_once_with(5_000, "my-label", "my-label")


# ── POST /renew ─────────────────────────────────────────────────────────────────

COORDINATOR_ID = "03" + "cd" * 32
ZBASE          = "rbxyz" * 10


class TestRenew:
    def _body(self, cycle=2, sats=10_000, coordinator_id=COORDINATOR_ID):
        return {"cycle": cycle, "contribution_sats": sats, "coordinator_id": coordinator_id}

    def test_returns_accept_and_zbase(self, client):
        tc, mock_cln = client
        mock_cln.sign_message.return_value = ZBASE

        r = tc.post("/renew", json=self._body())
        assert r.status_code == 200
        data = r.json()
        assert data["accept"] is True
        assert data["cycle"] == 2
        assert data["zbase"] == ZBASE

    def test_signs_canonical_message(self, client):
        tc, mock_cln = client
        mock_cln.sign_message.return_value = ZBASE

        tc.post("/renew", json=self._body(cycle=3, sats=5_000, coordinator_id=COORDINATOR_ID))
        expected = f"tanda-renew:cycle=3:sats=5000:coordinator={COORDINATOR_ID}"
        mock_cln.sign_message.assert_called_once_with(expected)

    def test_sign_message_error_returns_500(self, client):
        tc, mock_cln = client
        mock_cln.sign_message.side_effect = Exception("hsm not available")

        r = tc.post("/renew", json=self._body())
        assert r.status_code == 500
        assert "sign_message failed" in r.json()["detail"]

    def test_missing_coordinator_id_returns_422(self, client):
        tc, mock_cln = client
        r = tc.post("/renew", json={"cycle": 1, "contribution_sats": 10_000})
        assert r.status_code == 422
