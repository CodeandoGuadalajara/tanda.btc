# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## Test files

| File | Node required | What it covers |
|---|---|---|
| `test_protocol.py` | No | Scripts, MuSig2 round-trips, transaction structure, helpers |
| `test_coordinator.py` | No (mock RPC) | Coordinator setup, MuSig2 claim flow, partial sig verify, refund info, Participant |
| `test_e2e_regtest.py` | **Yes** (regtest) | Full on-chain: Round0 cooperative, Round1 HTLC fallback, Round2 collective refund |

```bash
# No node needed
python -m pytest tests/test_protocol.py tests/test_coordinator.py -v

# Regtest tests (node must be running)
python -m pytest tests/test_e2e_regtest.py -v -s

# Single test
python -m pytest tests/test_e2e_regtest.py::TestRound0Cooperative -v -s
```

---

## test_e2e_regtest.py — structure

### Shared fixture: `regtest_env`

All three round classes share the `regtest_env` session-scoped fixture. It:
1. Starts Bitcoin Core regtest (or skips all tests if not reachable)
2. Creates 3 deterministic privkeys from seeds `b"participant_0_key"`, `b"participant_1_key"`, `b"participant_2_key"`
3. Derives P2TR addresses for each participant and funds them via raw transactions
4. Mines enough blocks for coinbase maturity and confirmations
5. Returns `coord`, `setup`, `params`, `privkeys`, `pubkeys`, `funded`, `seeds`

### Local helpers

- `rpc()` — returns a `BitcoinRPC()` instance
- `mine(n)` — mines n blocks
- `_pubkey(seed)` — `sha256(seed)` → coincurve compressed pubkey (33 bytes)
- `_p2tr_addr(pk_bytes)` — derives `bcrt1p...` address from compressed pubkey
- `_p2tr_spk(pk_bytes)` — returns raw 34-byte P2TR scriptPubKey (`OP_1 <32-byte xonly>`)
- `contribute_raw(sk, src_utxos, dest_addr, dest_spk, amount_sats)` — builds and broadcasts a raw P2TR-to-P2TR transaction; signs with `signrawtransactionwithkey`
- `wait_for_utxos(address, count, min_sats, spk)` — polls `scantxoutset` until `count` UTXOs appear; returns `list[UTXO]` with raw-bytes `script_pubkey`

### Round tests

**Round 0 (cooperative):** All 3 contribute → mine 1 block → MuSig2 sign every input → `testmempoolaccept` → broadcast.
- Each input has a distinct sighash. The signing loop iterates `for inp_idx in range(len(tx.vin))` with fresh nonces per input.
- Asserts `kac.agg_pk == rs.scripts.output_key_xonly` before signing.

**Round 1 (HTLC fallback):** All 3 contribute → mine `T_CLAIM` blocks → winner signs leaf1 + reveals preimage for every input.
- Uses `sign_tapscript(tx, i, utxos, winner_privkey, htlc_script)` per input.
- Witness: `[winner_sig, preimage, htlc_script, control_block]`.

**Round 2 (refund fallback):** All 3 contribute → mine `T_REFUND` blocks → P₀ and P₁ sign leaf2 for every input, P₂ abstains.
- Signing loop: `for inp_idx in range(len(tx.vin))` — signs with correct `inp_idx` for each input; fresh `sigs_by_pk` dict per input.
- Witness: `make_refund_witness(sigs, refund_script, control_block)` where `sigs = [sigs_by_pk.get(pk, b"") for pk in sorted_pks]`.
- After broadcasting and mining 1 block, checks that P₀ and P₁ each received a refund UTXO.

---

## Common pitfalls when writing new tests

### UTXO.script_pubkey must be raw bytes

Use `_p2tr_spk(pk)` (34 bytes) or `rs.scripts.script_pubkey.data` (34 bytes).
**Never** use `rs.scripts.script_pubkey.serialize()` (35 bytes — includes compact_size prefix) for `UTXO.script_pubkey`; it corrupts the BIP-341 sighash.

### Multi-input transactions: sign each input separately

BIP-341 sighash includes `input_index`. Always loop:

```python
for inp_idx in range(len(tx.vin)):
    sighash = compute_taproot_sighash(tx, inp_idx, utxos, ...)
    # generate fresh nonces here, sign, attach witness
    tx.vin[inp_idx].witness = ...
```

### MuSig2: kac must be tweaked before signing

The `KeyAggContext` from `coordinator.setup()` already has the Taproot tweak applied. When constructing a `KeyAggContext` manually in a test, apply the tweak:

```python
from tanda.musig2 import key_agg, apply_tweak
from tanda.protocol import taproot_tweak
kac = key_agg(pubkeys)
kac = apply_tweak(kac, taproot_tweak(scripts.internal_key_xonly, scripts.merkle_root), is_xonly=True)
assert kac.agg_pk == scripts.output_key_xonly
```

### scantxoutset scriptPubKey

`rpc.scan_utxos(address)` returns `scriptPubKey` as a hex **string**. `wait_for_utxos` converts it:

```python
spk_bytes = bytes.fromhex(u["scriptPubKey"]) if isinstance(u.get("scriptPubKey"), str) else ...
```

### Pytest mark warning

The `@pytest.mark.e2e` mark produces an `Unknown mark` warning. Register it in `pytest.ini` or `pyproject.toml` to suppress:

```ini
# pytest.ini
[pytest]
markers =
    e2e: end-to-end tests requiring a live regtest node
```
