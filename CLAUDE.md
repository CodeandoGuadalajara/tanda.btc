# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A trustless tanda/rosca savings circle on Bitcoin regtest. Participants each contribute the same amount to a shared Taproot address every round; a winner determined by the round order claims the pot. The protocol is fully non-custodial and handles three spending paths without trust in the coordinator.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Unit tests — no Bitcoin node required
python -m pytest tests/test_protocol.py tests/test_coordinator.py -v

# Single unit test class
python -m pytest tests/test_protocol.py::TestMuSig2 -v

# E2E regtest tests — requires a running Bitcoin Core node
python -m pytest tests/test_e2e_regtest.py -v -s

# Start the regtest node (idempotent)
bash scripts/regtest_setup.sh
```

Bitcoin Core is compiled **without wallet support**. Mining uses `getblocktemplate + bitcoin-util grind + submitblock`. UTXO discovery uses `scantxoutset`.

## Architecture

```
tanda/
  protocol.py      — Taproot scripts, transaction builders, BIP-341/342 sighash
  musig2.py        — BIP-327 MuSig2 implementation (key agg, nonce gen, signing, aggregation)
  htlc.py          — HTLC secret generation and preimage verification
  coordinator.py   — Trustless round orchestration (setup, collect contributions, MuSig2 flow, fallbacks)
  participant.py   — Participant actions (contribute, nonce gen, sign_claim, HTLC claim, refund)
  rpc.py           — Bitcoin Core JSON-RPC wrapper (wallet-less + wallet paths)

tests/
  test_protocol.py      — Unit tests for scripts, transactions, MuSig2 (no node)
  test_coordinator.py   — Unit tests for coordinator + participant with mock RPC (no node)
  test_e2e_regtest.py   — Full regtest integration: Round0 (cooperative), Round1 (HTLC), Round2 (refund)

scripts/
  regtest_setup.sh — Start bitcoind regtest, create wallets, mine initial blocks
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
