# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A trustless tanda/rosca savings circle on Bitcoin regtest. Participants each contribute the same amount to a shared Taproot address every round; a winner determined by the round order claims the pot. The protocol is fully non-custodial and handles three spending paths without trust in the coordinator.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt -r requirements-demo.txt

# Unit tests — no node required (on-chain + LN mocks)
python -m pytest tests/test_protocol.py tests/test_coordinator.py \
                 tests/test_lnrpc.py tests/test_api_participant_ln.py -v
make test

# Single unit test class
python -m pytest tests/test_protocol.py::TestMuSig2 -v

# E2E regtest tests — requires a running Bitcoin Core node
bash scripts/regtest_setup.sh
python -m pytest tests/test_e2e_regtest.py -v -s
make test-e2e

# E2E Docker LN tests — requires Docker
make test-ln

# Demo single machine
make demo
make demo-interactive

# Demo multi-PC (simula N PCs en una sola máquina)
make multipc
make multipc-interactive

# Stop the regtest node
bitcoin-cli -regtest stop
```

Bitcoin Core is compiled **without wallet support**. Mining uses `getblocktemplate + bitcoin-util grind + submitblock`. UTXO discovery uses `scantxoutset`.

## Key dependencies

- **embit** — Bitcoin primitives (Script, Transaction, Taproot)
- **coincurve** — secp256k1 EC operations (used by musig2.py)
- **pyln-client** — Core Lightning RPC (used by lnrpc.py)
- **FastAPI / uvicorn** — participant HTTP API

## Architecture

The protocol has two layers: an **on-chain layer** (Taproot + MuSig2) and an optional **Lightning Network layer** (CLN + hold invoices). The LN layer uses hold invoices so the coordinator never has unilateral access: participants pay hold invoices → coordinator verifies all N HTLCs accepted → pays winner via regular invoice → settles hold invoices. If the coordinator disappears, hold invoice HTLCs time out and refund automatically.

```
tanda/
  protocol.py           — Taproot scripts, transaction builders, BIP-341/342 sighash
  musig2.py             — BIP-327 MuSig2 implementation (key agg, nonce gen, signing, aggregation)
  htlc.py               — HTLC secret generation and preimage verification
  coordinator.py        — Trustless round orchestration (setup, collect contributions, MuSig2 flow, fallbacks)
  participant.py        — Participant actions (contribute, nonce gen, sign_claim, HTLC claim, refund)
  rpc.py                — Bitcoin Core JSON-RPC wrapper (wallet-less + wallet paths)
  lnrpc.py              — CLN RPC wrapper over pyln-client unix socket
  api_participant.py    — FastAPI participant server (on-chain, env: SK_IDX, SK_SEED, BITCOIND_RPC_URL)
  api_participant_ln.py — FastAPI participant server (LN, env: CLN_RPC_PATH, hold invoice endpoints)
  ledger.py             — Per-participant debt/pot ledger with JSON persistence

tests/
  test_protocol.py           — Unit: scripts, transactions, MuSig2 (no node)
  test_coordinator.py        — Unit: coordinator + participant with mock RPC (no node)
  test_lnrpc.py              — Unit: CLNRpc with mock (no node)
  test_api_participant_ln.py — Unit: FastAPI endpoints with mock CLN (no node)
  test_e2e_regtest.py        — E2E regtest: Round0 cooperative, Round1 HTLC, Round2 refund
  test_e2e_ln_docker.py      — E2E Docker: full LN protocol with live CLN nodes

scripts/
  regtest_setup.sh       — Start bitcoind regtest, mine initial blocks
  run_coordinator_ln.py  — LN demo coordinator: bootstrap channels + N rounds via hold invoices
  start_coordinator.sh   — Multi-PC: bitcoind + CLN coordinator + coordinator script
  start_participant.sh   — Multi-PC: CLN node + FastAPI on participant's PC
  test_local_multipc.sh  — Simulate N PCs on one machine (shifted ports per participant)

deploy/
  coord.yml / coord.local.yml       — Multi-PC coordinator stack
  participant.yml                   — Multi-PC participant stack
  run.yml / run.local.yml           — Multi-PC coordinator script container
```

### Module import layering

Modules only import downward — never create circular imports:

```
rpc.py                ← no tanda imports
htlc.py               ← no tanda imports
musig2.py             ← no tanda imports
lnrpc.py              ← no tanda imports
ledger.py             ← no tanda imports
protocol.py           ← imports musig2
coordinator.py        ← imports protocol, musig2, htlc, rpc
participant.py        ← imports protocol, musig2, htlc, rpc
api_participant_ln.py ← imports lnrpc, ledger
```

### Taproot output structure (per round)

Each contribution UTXO is locked to a Taproot address built as:

```
internal_key: MuSig2 aggregate of all N participant pubkeys
tap_tree:
  leaf1 (HTLC winner): <winner_xonly> OP_CHECKSIGVERIFY OP_SHA256 <H> OP_EQUAL
  leaf2 (refund):      <t_refund> OP_CSV OP_DROP <pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD ... <k_min> OP_NUMEQUAL
```

Three spending paths:
- **keypath** — all N sign cooperatively via MuSig2 → `claim_tx` pays winner
- **leaf1** — winner signs + reveals HTLC preimage after `t_claim` blocks
- **leaf2** — `k_min`-of-N sign collectively after `t_refund` blocks

### MuSig2 signing flow (cooperative path)

1. `coordinator.setup()` calls `key_agg(pubkeys)` then **`apply_tweak(kac, taproot_tweak(...), is_xonly=True)`** — the stored `kac.agg_pk` must equal `scripts.output_key_xonly`
2. For each input, participants generate fresh nonces, exchange public nonces, aggregate, build `SessionContext`, produce partial signatures, aggregate with `partial_sig_agg`
3. **Each input in a multi-input tx has a distinct sighash** (BIP-341 includes `input_index`). Sign and witness every input separately with fresh nonces

## Critical invariants

### embit Script bytes

`Script.serialize()` returns `compact_size(len) + raw_script` — **35 bytes** for a P2TR output.
`Script.data` returns the raw script — **34 bytes** for P2TR.
`UTXO.script_pubkey` must be **raw bytes** (use `.data`, not `.serialize()`) for `compute_taproot_sighash` to produce the correct BIP-341 sighash.

### BIP-341 sighash format

The signature message begins with epoch byte `0x00`, then `hash_type`. For non-ANYONECANPAY inputs, only `input_index` (4 bytes LE) follows `spend_type` — **not** outpoint + amount + scriptPubKey + sequence for the current input. `hash_outputs()` calls `out.script_pubkey.serialize()` directly (already includes compact_size prefix; do not add another one).

### BIP-327 partial_sig_agg with Taproot tweak

```python
g = 1 if _has_even_y(ctx.Q) else N - 1
s = sum(s_i) + e * g * tacc   (mod n)
```

When the tweaked output key Q has odd y, **both** the signing key parity and the `tacc` accumulator must be negated (multiplied by `g`). Omitting `g` produces a valid-looking signature that fails `schnorr_verify`.

### scantxoutset scriptPubKey format

`scantxoutset` returns `scriptPubKey` as a **hex string** (not a dict). The test helper `wait_for_utxos` handles both `str` and `dict` cases.

### Refund witness order

`make_refund_witness(sigs, script, control_block)` reverses `sigs` before building the witness stack (LIFO evaluation). `sigs` must be ordered by **sorted pubkeys** (ascending), with `b""` for non-signers.

### embit txid byte order

embit's `write_to()` reverses txid bytes internally. Pass display-order txid hex strings directly to `UTXO(txid=...)` without manual byte-reversal.

## Common pitfalls when writing tests

### Multi-input transactions: sign each input separately

BIP-341 sighash includes `input_index`. Always loop with fresh nonces per input:

```python
for inp_idx in range(len(tx.vin)):
    sighash = compute_taproot_sighash(tx, inp_idx, utxos, ...)
    # generate fresh nonces here, sign, attach witness
    tx.vin[inp_idx].witness = ...
```

### Manually constructing KeyAggContext in tests

When building a `KeyAggContext` outside of `coordinator.setup()`, apply the Taproot tweak manually:

```python
from tanda.musig2 import key_agg, apply_tweak
from tanda.protocol import taproot_tweak
kac = key_agg(pubkeys)
kac = apply_tweak(kac, taproot_tweak(scripts.internal_key_xonly, scripts.merkle_root), is_xonly=True)
assert kac.agg_pk == scripts.output_key_xonly
```

### pytest e2e mark warning

The `@pytest.mark.e2e` mark produces an `Unknown mark` warning. Suppress by adding to `pytest.ini`:

```ini
[pytest]
markers =
    e2e: end-to-end tests requiring a live regtest node
```
