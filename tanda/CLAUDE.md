# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## Package overview

The `tanda/` package implements the full tanda protocol. Modules are layered — import only downward:

```
rpc.py                ← no tanda imports
htlc.py               ← no tanda imports
musig2.py             ← no tanda imports
lnrpc.py              ← no tanda imports
protocol.py           ← imports musig2
coordinator.py        ← imports protocol, musig2, htlc, rpc
participant.py        ← imports protocol, musig2, htlc, rpc
ledger.py             ← no tanda imports
api_participant_ln.py ← imports lnrpc, ledger
```

---

## protocol.py

Central module. Exports used everywhere else.

**Key types:**
- `UTXO(txid, vout, amount_sats, script_pubkey)` — `script_pubkey` must be **raw bytes** (34 bytes for P2TR), **not** `Script.serialize()` output (which adds a compact_size prefix, making 35 bytes)
- `RoundScripts` — result of `build_taproot_output()`; holds `.address`, `.output_key_xonly`, `.internal_key_xonly`, `.merkle_root`, `.script_pubkey` (embit Script), `.tap_tree`, `.output_key_parity`
- `TapTree(leaf1, leaf2)` / `TapLeaf(script, version)` — leaf1 = HTLC winner, leaf2 = collective refund

**Key functions:**
- `build_taproot_output(winner_pubkey, all_pubkeys, htlc_hash, t_refund, k_min)` → `RoundScripts`
- `build_claim_tx(utxos, winner_address)` → `Transaction`
- `build_htlc_claim_tx(utxos, winner_address)` → `Transaction`
- `build_refund_tx(utxos, participant_addresses, t_refund)` → `Transaction` (CSV sequence = `t_refund & 0xFFFF`)
- `compute_taproot_sighash(tx, input_index, utxos, sighash_type=0, script_path=None)` → 32-byte sighash
- `sign_tapscript(tx, input_index, utxos, privkey, script)` → Schnorr signature bytes
- `taproot_tweak(internal_key_xonly, merkle_root)` → 32-byte tweak scalar
- `build_control_block(internal_key_xonly, output_key_parity, sibling_hash)` → 65-byte bytes

**Witness builders:**
- `make_keypath_witness(sig)` → Witness with 64-byte Schnorr sig
- `make_htlc_claim_witness(winner_sig, preimage, htlc_script, control_block)` → Witness stack: `[sig, preimage, script, control_block]`
- `make_refund_witness(sigs, refund_script, control_block)` → Witness stack: `[*reversed(sigs), script, control_block]`

**Script internals (used in tests):**
- `_build_htlc_winner_script(winner_xonly, htlc_hash)` → leaf1 tapscript bytes
- `_build_refund_script(participants_xonly, k_min, t_refund)` → leaf2 tapscript bytes
- `_tap_leaf_hash(script)`, `_tap_branch_hash(h1, h2)`

### compute_taproot_sighash — BIP-341 format

The message is: `0x00 || hash_type || nVersion(4LE) || nLockTime(4LE) || sha_prevouts || sha_amounts || sha_scriptpubkeys || sha_sequences || sha_outputs || spend_type(1) || input_index(4LE)` (non-ANYONECANPAY keypath). For script-path spending, append `leaf_hash(32) || 0x00 || codesep_pos(4LE)`.

`hash_outputs()` calls `out.script_pubkey.serialize()` which already includes the compact_size length prefix — do **not** add another prefix manually.

---

## musig2.py

BIP-327 implementation using `coincurve` for EC operations.

**Key types (dataclasses):**
- `KeyAggContext(pubkeys, coeffs, Q, gacc, tacc, agg_pk)` — `agg_pk` is the 32-byte x-only aggregate public key
- `SecNonce(k1, k2)` — use-once; zeroed after `partial_sign`
- `PubNonce` / `AggNonce` — 66-byte serialized (two compressed EC points)
- `SessionContext(agg_nonce, key_agg_ctx, msg)` — computed lazily: `R`, `e`, `b` on first access

**Key functions:**
- `key_agg(pubkeys)` → `KeyAggContext` — sorts pubkeys internally; the second unique sorted key always gets coefficient 1
- `apply_tweak(kac, tweak, is_xonly=True)` → new `KeyAggContext` with tweak applied; **must be called** in `coordinator.setup()` to make `kac.agg_pk == scripts.output_key_xonly`
- `nonce_gen(sk, pk, agg_pk=None, msg=None)` → `(SecNonce, PubNonce)`
- `nonce_agg(pub_nonces)` → `AggNonce`
- `partial_sign(sec_nonce, sk, session_ctx)` → scalar `int`
- `partial_sig_verify(psig, pub_nonce, pk, session_ctx)` → bool
- `partial_sig_agg(psigs, session_ctx)` → 64-byte Schnorr signature
- `schnorr_verify(sig, msg, pubkey_xonly)` → bool

### partial_sig_agg parity correction

```python
g = 1 if _has_even_y(ctx.Q) else N - 1
s = _mod(sum(psigs) + _mod(e * _mod(g * ctx.tacc)))
```

When the tweaked key Q has odd y, BIP-340's verifier uses `lift_x(Q.x) = -Q`, so both the signing keys and the tweak accumulator `tacc` must be negated via `g`.

---

## coordinator.py

`Coordinator` drives the full protocol from the coordinator's perspective.

**Setup:**
```python
coord = Coordinator(rpc, params, pubkeys)
setup = coord.setup()   # generates HTLC secrets, builds scripts, applies Taproot tweak to kac
```

After `setup()`, each `RoundState.key_agg_ctx.agg_pk == round.scripts.output_key_xonly`.

**MuSig2 signing flow:**
1. `prepare_claim_session(rs, winner_address)` — builds `claim_tx`, optionally generates coordinator nonce
2. `collect_pub_nonce(rs, idx, pub_nonce)` — registers participant nonce
3. `finalize_nonce_aggregation(rs)` → `AggNonce`
4. `build_session_context(rs, winner_address)` → `SessionContext` (computes sighash for input 0)
5. `collect_partial_sig(rs, idx, psig)`
6. `aggregate_and_broadcast(rs)` → txid

**Fallback paths:**
- `build_htlc_claim_info(rs, winner_address)` — returns tx + htlc_script + control_block + preimage for leaf1 spend
- `build_refund_info(rs, participant_addresses)` — returns tx + refund_script + control_block for leaf2 spend

---

## participant.py

`Participant` is a thin wrapper around one private key.

- `generate_nonce(agg_pk)` — stores `SecNonce` internally; must be called before `sign_claim`
- `sign_claim(session_ctx)` → partial sig scalar; **zeroes the sec_nonce** (use-once)
- `claim_htlc(tx, utxos, htlc_script, control_block, preimage)` — signs + broadcasts leaf1 spend; signs each input in a loop
- `sign_refund(tx, utxos, refund_script)` → sig for input 0 only (caller must handle multi-input)
- `broadcast_refund(tx, sigs, refund_script, control_block)` — attaches identical witness to all inputs (only safe if all sigs are correct per-input — see tests for correct multi-input usage)

---

## htlc.py

Minimal. `generate_htlc_secret()` → `(preimage, sha256(preimage))`. `verify_preimage(preimage, htlc_hash)` → bool.

---

## rpc.py

`BitcoinRPC` wraps Bitcoin Core JSON-RPC.

- Auto-detects cookie auth (`~/.bitcoin/regtest/.cookie`) before falling back to user/password
- `mine(n)` — tries `generatetoaddress`; falls back to wallet-less `getblocktemplate + bitcoin-util grind + submitblock`
- `scan_utxos(address)` — uses `scantxoutset`; returns `scriptPubKey` as a **hex string**, not a dict
- `fund_address(address, amount)` — uses `sendtoaddress` if wallet available; otherwise requires `from_utxos`
- `list_unspent()` — falls back to `scantxoutset` if wallet unavailable

---

## lnrpc.py

`CLNRpc` wraps Core Lightning via `pyln-client` unix socket.

- `CLNRpc(rpc_path)` — connects to `lightning-rpc` socket; path set via `CLN_RPC_PATH` env var
- `getinfo()` → dict with `id`, `alias`, `color`, `our_features`, etc.
- `listfunds()` → dict with `channels` and `outputs`
- `listpeerchannels()` → dict with `channels` list; each channel has `htlcs` list
- `invoice(amount_msat, label, description)` → dict with `bolt11`, `payment_hash`
- `holdinvoice(payment_hash, amount_msat)` → hold invoice (requires BoltzExchange/hold plugin)
- `settleholdinvoice(preimage)` → settles HTLC, reveals preimage to payer
- `cancelholdinvoice(payment_hash)` → returns HTLCs to payer
- `pay(bolt11)` → pays a BOLT11 invoice
- `connect(node_id, host, port)` → opens P2P connection
- `fundchannel(node_id, amount_sat, push_msat)` → opens channel with optional push
- `sign_message(message)` → zbase32 signature with node's private key
- `check_message(message, zbase, node_id)` → bool; True only if verified AND pubkey matches node_id

**Hold invoice states:** `UNPAID → ACCEPTED → PAID / CANCELLED`

**HTLC detection:** poll `listpeerchannels().channels[*].htlcs` where `direction == "in"` and `payment_hash` matches.

**Renewal signing message format:** `tanda-renew:cycle={N}:sats={S}:coordinator={node_id}` — both sides construct this independently from the request fields.

---

## api_participant_ln.py

FastAPI participant server. Reads `CLN_RPC_PATH` env var on startup.

**Endpoints:**
- `GET /health` → `{"status":"ok","pubkey_hex":"03...","channels":[...]}`
- `GET /node_info` → `{"id":"03...","address":{"type":"ipv4",...}}`
- `POST /pay_invoice` `{"bolt11":"lnbcrt..."}` → `{"payment_hash":"hex"}` — participant pays coordinator's hold invoice (blocks until settled/cancelled by coordinator)
- `POST /create_invoice` `{"amount_msat":N,"label":"str"}` → `{"bolt11":"lnbcrt..."}` — winner creates regular invoice so coordinator can pay the pot
- `POST /renew` `{"cycle":N,"contribution_sats":S,"coordinator_id":"03..."}` → `{"accept":true,"cycle":N,"zbase":"..."}` — participant signs renewal terms with node key; coordinator verifies with `check_message`

**Lifespan:** CLNRpc instance created once at startup; shared across requests via `app.state.cln`.

---

## ledger.py

`Ledger` tracks per-participant debt and pot contributions. JSON persistence to disk.

- `Ledger(path)` — loads from `path` if exists, else starts fresh
- `record_contribution(participant_id, round_idx, amount_sats)` — marks participant paid for round
- `record_win(participant_id, round_idx, amount_sats)` — marks participant received pot
- `balance(participant_id)` → net sats (positive = owed, negative = received more than contributed)
- `save()` — writes JSON to disk
