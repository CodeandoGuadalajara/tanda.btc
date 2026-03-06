"""
Bitcoin Core RPC wrapper for regtest operations.

Supports two authentication modes:
  - Username/password (rpcuser/rpcpassword in bitcoin.conf)
  - Cookie file (~/.bitcoin/regtest/.cookie)
"""

import hashlib
import os
import struct
import subprocess
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from typing import Optional


def _read_cookie(data_dir: Optional[str] = None) -> Optional[tuple[str, str]]:
    """Try to read Bitcoin Core's .cookie auth file."""
    candidates = []
    if data_dir:
        candidates.append(os.path.join(data_dir, "regtest", ".cookie"))
    home = os.path.expanduser("~")
    candidates += [
        os.path.join(home, ".bitcoin", "regtest", ".cookie"),
        "/tmp/regtest/.cookie",
    ]
    for path in candidates:
        try:
            with open(path) as f:
                user, pwd = f.read().strip().split(":", 1)
                return user, pwd
        except Exception:
            continue
    return None


class BitcoinRPC:
    """Thin wrapper around Bitcoin Core JSON-RPC for regtest."""

    def __init__(
        self,
        rpc_user: str = "user",
        rpc_password: str = "password",
        rpc_host: str = "127.0.0.1",
        rpc_port: int = 18443,
        wallet: Optional[str] = None,
        data_dir: Optional[str] = None,
    ):
        # Try cookie auth first, fall back to user/password
        cookie = _read_cookie(data_dir)
        if cookie:
            rpc_user, rpc_password = cookie

        base_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}"
        if wallet:
            base_url += f"/wallet/{wallet}"
        self._url = base_url
        self._base_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}"
        self._rpc = AuthServiceProxy(base_url)
        self._wallet = wallet

    def _conn(self) -> AuthServiceProxy:
        """Return a (possibly reconnected) proxy."""
        return AuthServiceProxy(self._url)

    def _chain(self) -> AuthServiceProxy:
        """Chain-level endpoint — never uses /wallet/… path."""
        return AuthServiceProxy(self._base_url)

    # ── Block management ──────────────────────────────────────────────────────

    def mine(self, n: int = 1, address: Optional[str] = None) -> list[str]:
        """
        Mine *n* blocks in regtest.

        Tries `generatetoaddress` (wallet-enabled nodes) first; falls back to
        the wallet-less `_mine_walletless()` path using getblocktemplate +
        bitcoin-util grind + submitblock.
        """
        if address is None:
            address = self._default_mine_addr()
        # Try generatetoaddress on both wallet URL and base URL before wallet-less path
        for url in dict.fromkeys([self._url, self._base_url]):
            try:
                return AuthServiceProxy(url).generatetoaddress(n, address)
            except JSONRPCException:
                pass
        # Wallet-less fallback
        block_hashes = []
        for _ in range(n):
            bh = self._mine_walletless(address)
            block_hashes.append(bh)
        return block_hashes

    def _default_mine_addr(self) -> str:
        """Return a stable bech32 P2WPKH address for coinbase block rewards."""
        from embit.ec import PrivateKey
        from embit.script import Script
        sk = PrivateKey(hashlib.sha256(b"regtest_mine_key").digest())
        pub = sk.get_public_key()
        # P2WPKH: OP_0 <20-byte-pubkey-hash>
        import hashlib as _hl
        pk_hash = _hl.new("ripemd160", _hl.sha256(pub.sec()).digest()).digest()
        spk = bytes([0x00, 0x14]) + pk_hash  # OP_0 <20>
        return Script(spk).address(network={"bech32": "bcrt", "p2sh": 0xC4, "p2pkh": 0x6F})

    def _mine_walletless(self, coinbase_address: str) -> str:
        """
        Mine one block to *coinbase_address* without wallet RPC support.

        Uses:
          1. getblocktemplate to get block parameters
          2. Build coinbase transaction
          3. Compute merkle root
          4. bitcoin-util grind to solve PoW
          5. submitblock
        """
        # Use the base URL (no /wallet/…) — getblocktemplate is a chain-level RPC
        rpc = AuthServiceProxy(self._base_url)
        template = rpc.getblocktemplate({"rules": ["segwit"]})

        version = template["version"]
        prev_hash = bytes.fromhex(template["previousblockhash"])[::-1]
        bits = int(template["bits"], 16)
        curtime = template["curtime"]
        height = template["height"]
        coinbasevalue = template["coinbasevalue"]
        txns_data = template.get("transactions", [])

        # Build coinbase transaction
        coinbase_tx = self._build_coinbase_tx(
            height=height,
            value=coinbasevalue,
            address=coinbase_address,
        )
        coinbase_txid = self._tx_txid(coinbase_tx)

        # All transactions (coinbase first)
        all_txns = [coinbase_tx] + [bytes.fromhex(t["data"]) for t in txns_data]
        all_txids = [coinbase_txid] + [
            bytes.fromhex(t["txid"])[::-1] for t in txns_data
        ]

        # Compute merkle root
        merkle_root = self._merkle_root(all_txids)

        # Build 80-byte block header (nonce = 0 initially)
        header = (
            struct.pack("<I", version)
            + prev_hash
            + merkle_root
            + struct.pack("<I", curtime)
            + struct.pack("<I", bits)
            + struct.pack("<I", 0)        # nonce placeholder
        )

        # Use bitcoin-util grind to find valid nonce
        header_hex = header.hex()
        result = subprocess.run(
            ["bitcoin-util", "-regtest", "grind", header_hex],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"bitcoin-util grind failed: {result.stderr}")
        solved_header = bytes.fromhex(result.stdout.strip())

        # Build complete block: header + varint(num_txns) + transactions
        block = solved_header + self._varint(len(all_txns))
        for tx in all_txns:
            block += tx

        block_hex = block.hex()
        rpc.submitblock(block_hex)

        # Return block hash
        block_hash = hashlib.sha256(hashlib.sha256(solved_header).digest()).digest()
        return block_hash[::-1].hex()

    @staticmethod
    def _build_coinbase_tx(height: int, value: int, address: str) -> bytes:
        """Serialize a minimal coinbase transaction paying to *address*."""
        from embit.script import Script

        # Coinbase script: push block height (BIP-34)
        height_bytes = height.to_bytes((height.bit_length() + 7) // 8, "little")
        coinbase_script = bytes([len(height_bytes)]) + height_bytes + b"\x00" * 4

        # Input: coinbase (all zeros txid, 0xFFFFFFFF vout)
        txin = (
            b"\x00" * 32                            # txid
            + b"\xff\xff\xff\xff"                    # vout
            + bytes([len(coinbase_script)]) + coinbase_script  # script
            + b"\xff\xff\xff\xff"                    # sequence
        )

        # Output: pay to address
        spk = Script.from_address(address).serialize()
        txout = struct.pack("<q", value) + bytes([len(spk)]) + spk

        # Segwit marker + flag + witness (empty for non-segwit coinbase)
        tx = (
            struct.pack("<I", 2)    # version
            + b"\x01"               # vin count
            + txin
            + b"\x01"               # vout count
            + txout
            + struct.pack("<I", 0)  # locktime
        )
        return tx

    @staticmethod
    def _tx_txid(tx_bytes: bytes) -> bytes:
        """Return txid (internal byte order) for a serialized transaction."""
        txid = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
        return txid[::-1]  # little-endian for merkle tree

    @staticmethod
    def _merkle_root(txids: list[bytes]) -> bytes:
        """Compute Bitcoin merkle root from a list of txids (in little-endian)."""
        if not txids:
            return b"\x00" * 32
        hashes = list(txids)
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                next_level.append(hashlib.sha256(hashlib.sha256(combined).digest()).digest())
            hashes = next_level
        return hashes[0]

    @staticmethod
    def _varint(n: int) -> bytes:
        if n < 0xFD:
            return bytes([n])
        if n <= 0xFFFF:
            return b"\xfd" + struct.pack("<H", n)
        if n <= 0xFFFFFFFF:
            return b"\xfe" + struct.pack("<I", n)
        return b"\xff" + struct.pack("<Q", n)

    def get_block_height(self) -> int:
        return self._chain().getblockcount()

    # ── Wallet / funds (wallet-less implementation) ───────────────────────────

    def create_wallet(self, name: str, descriptor: bool = True) -> dict:
        rpc = self._conn()
        try:
            return rpc.createwallet(name, False, False, "", False, descriptor)
        except JSONRPCException as e:
            if "already exists" in str(e):
                try:
                    return rpc.loadwallet(name)
                except JSONRPCException:
                    return {"name": name}
            # If createwallet not available, silently ignore
            return {"name": name}

    def get_new_address(self, label: str = "") -> str:
        """Generate a new address using wallet RPC or a deterministic fallback."""
        rpc = self._conn()
        try:
            return rpc.getnewaddress(label)
        except Exception:
            # Wallet not available - generate deterministic address
            seed = hashlib.sha256(f"{label}_{self._wallet or 'default'}".encode()).digest()
            from embit.ec import PrivateKey
            from embit.script import Script
            sk = PrivateKey(seed)
            xonly = sk.get_public_key().xonly()
            spk = Script(bytes([0x51, 0x20]) + xonly)
            return spk.address(network={"bech32": "bcrt", "p2sh": 0xC4, "p2pkh": 0x6F})

    def get_balance(self) -> float:
        """Return wallet balance (wallet-required; returns 0.0 if unavailable)."""
        rpc = self._conn()
        try:
            return rpc.getbalance()
        except JSONRPCException:
            return 0.0

    def fund_address(self, address: str, amount: float, from_utxos: Optional[list] = None) -> str:
        """
        Send *amount* BTC to *address*.

        With wallet: uses sendtoaddress.
        Without wallet: requires *from_utxos* (list of UTXO dicts with txid/vout/amount/privkey).
        """
        rpc = self._conn()
        try:
            return rpc.sendtoaddress(address, amount)
        except JSONRPCException:
            if not from_utxos:
                raise RuntimeError(
                    "Wallet not available and no from_utxos provided for fund_address()"
                )
            return self._fund_address_raw(address, amount, from_utxos)

    def _fund_address_raw(self, address: str, amount_btc: float, from_utxos: list) -> str:
        """
        Build + sign + broadcast a funding transaction from given UTXOs.
        Each UTXO dict must have: txid, vout, amount (BTC), privkey (WIF or hex), scriptPubKey.
        """
        # Use base URL — createrawtransaction / signrawtransactionwithkey / sendrawtransaction
        # are chain-level RPCs and must not be called on a /wallet/<name> path.
        rpc = AuthServiceProxy(self._base_url)
        amount_sats = round(amount_btc * 100_000_000)

        inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in from_utxos]
        total_in = sum(round(u["amount"] * 100_000_000) for u in from_utxos)
        fee_sats = 5000  # fixed regtest fee
        change_sats = total_in - amount_sats - fee_sats

        outputs = {address: amount_btc}
        if change_sats > 546:
            # Send change back to first input's address (or a known address)
            change_addr = from_utxos[0].get("change_address", address)
            outputs[change_addr] = change_sats / 100_000_000

        raw_tx = rpc.createrawtransaction(inputs, outputs)

        # Prepare prevtx info for signing
        prevtxs = [
            {
                "txid": u["txid"],
                "vout": u["vout"],
                "scriptPubKey": u["scriptPubKey"],
                "amount": u["amount"],
            }
            for u in from_utxos
        ]
        privkeys = [u["privkey"] for u in from_utxos]

        signed = rpc.signrawtransactionwithkey(raw_tx, privkeys, prevtxs)
        if not signed.get("complete", False):
            raise RuntimeError(f"Transaction signing incomplete: {signed}")

        return rpc.sendrawtransaction(signed["hex"])

    def list_unspent(
        self,
        min_conf: int = 1,
        addresses: Optional[list[str]] = None,
    ) -> list[dict]:
        rpc = self._conn()
        try:
            if addresses:
                return rpc.listunspent(min_conf, 9999999, addresses)
            return rpc.listunspent(min_conf)
        except JSONRPCException:
            # Wallet not available - use scantxoutset
            if addresses:
                results = []
                for addr in addresses:
                    for u in self.scan_utxos(addr):
                        if u.get("confirmations", 0) >= min_conf:
                            results.append(u)
                return results
            return []

    # ── Transaction helpers ───────────────────────────────────────────────────

    def get_raw_transaction(self, txid: str, verbose: bool = True) -> dict:
        return self._chain().getrawtransaction(txid, verbose)

    def decode_raw_transaction(self, hex_tx: str) -> dict:
        return self._chain().decoderawtransaction(hex_tx)

    def send_raw_transaction(self, hex_tx: str) -> str:
        """Broadcast a raw hex transaction; returns txid."""
        return self._chain().sendrawtransaction(hex_tx)

    def test_mempool_accept(self, hex_tx: str) -> list[dict]:
        return self._chain().testmempoolaccept([hex_tx])

    def get_tx_out(self, txid: str, vout: int) -> Optional[dict]:
        return self._chain().gettxout(txid, vout)

    # ── UTXO helpers ──────────────────────────────────────────────────────────

    def scan_utxos(self, address: str) -> list[dict]:
        """Return UTXOs for a given address (uses scantxoutset)."""
        result = self._chain().scantxoutset("start", [f"addr({address})"])
        return result.get("unspents", [])

    def get_utxos_for_address(self, address: str, min_conf: int = 1) -> list[dict]:
        """Return UTXOs sent to *address* via listunspent (wallet-aware)."""
        return self.list_unspent(min_conf, [address])

    # ── Fee estimation ────────────────────────────────────────────────────────

    def estimate_fee_rate(self, target_blocks: int = 6) -> float:
        """Return estimated fee rate in BTC/kB (min 0.00001)."""
        res = self._chain().estimatesmartfee(target_blocks)
        return max(res.get("feerate", 0.00001), 0.00001)

    # ── Descriptor / address utilities ───────────────────────────────────────

    def import_address(self, address: str, label: str = "", rescan: bool = False):
        """Watch-only import of an address."""
        self._conn().importaddress(address, label, rescan)

    def get_descriptor_info(self, descriptor: str) -> dict:
        return self._conn().getdescriptorinfo(descriptor)

    # ── Raw helpers ───────────────────────────────────────────────────────────

    def call(self, method: str, *args):
        """Generic RPC call."""
        return getattr(self._conn(), method)(*args)
