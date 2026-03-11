# tanda-btc

A trustless tanda/rosca savings circle implemented on Bitcoin using Taproot, MuSig2, and HTLCs. No custodian, no trusted coordinator — every spending path is enforced by Bitcoin script.

## What is a tanda?

A tanda (also called rosca, susu, or hui) is a rotating savings circle: N participants each contribute the same amount every round. One participant wins the full pot each round, rotating until everyone has received it once. Traditionally this requires trust in an organizer. This implementation removes that trust entirely.

## Protocol layers

### On-chain layer (Taproot + MuSig2)

Each round, all N participants send their contribution to a shared **Taproot address**. The output key is the MuSig2 aggregate of all participant public keys. The script tree provides two fallback paths if cooperation fails:

```
Taproot output
├── keypath  — MuSig2(P₁, …, Pₙ)  →  cooperative claim by winner
├── leaf1    — <Pₖ> OP_CHECKSIGVERIFY OP_SHA256 <H> OP_EQUAL  →  HTLC claim (winner + preimage)
└── leaf2    — <T_refund> OP_CSV OP_DROP  +  thresh(k_min, P₁, …, Pₙ)  →  collective refund
```

| Path | Who | When | How |
|---|---|---|---|
| **Keypath** | All participants | Cooperative case | MuSig2 aggregate signature pays winner |
| **Leaf 1 (HTLC)** | Round winner Pₖ | Coordinator disappears after `t_claim` blocks | Pₖ signs + reveals SHA-256 preimage |
| **Leaf 2 (Refund)** | k_min-of-N participants | Winner disappears after `t_refund` blocks | Schnorr multisig returns funds pro-rata |

### Lightning Network layer (CLN + hold invoices)

The demo runs over Lightning Network using Core Lightning (CLN) with the BoltzExchange/hold plugin. Each round:

1. Coordinator issues N **hold invoices** (one per participant) — HTLCs lock in coordinator's node
2. All participants pay their invoice → funds locked but not settled
3. Coordinator verifies all N HTLCs accepted, then pays the winner via a regular invoice
4. Coordinator settles all hold invoices, recovering N × contribution from participants

The coordinator never has unilateral access to funds: if it disappears after step 2, participants' HTLCs time out and refund automatically.

## Architecture

```
tanda/
  protocol.py           — Taproot scripts, transaction builders, BIP-341/342 sighash
  musig2.py             — BIP-327 MuSig2 (key aggregation, nonce gen, partial signing, aggregation)
  htlc.py               — HTLC secret generation and preimage verification
  coordinator.py        — On-chain round orchestration: setup, MuSig2 flow, fallbacks
  participant.py        — On-chain participant: contribute, sign claim, HTLC claim, sign refund
  rpc.py                — Bitcoin Core JSON-RPC wrapper (wallet-less + wallet paths)
  lnrpc.py              — CLN RPC wrapper (pyln-client unix socket)
  api_participant_ln.py — FastAPI participant server (hold invoice endpoints)
  ledger.py             — Per-participant debt/pot ledger (JSON persistence)

tests/
  test_protocol.py           — Unit: scripts, MuSig2, transactions (no node)
  test_coordinator.py        — Unit: coordinator + participant with mock RPC (no node)
  test_lnrpc.py              — Unit: CLNRpc with mock (no node)
  test_api_participant_ln.py — Unit: FastAPI endpoints with mock CLN (no node)
  test_e2e_regtest.py        — E2E regtest: cooperative, HTLC fallback, refund fallback
  test_e2e_ln_docker.py      — E2E Docker: full LN protocol with live CLN nodes

scripts/
  regtest_setup.sh       — Start bitcoind regtest and mine initial blocks
  run_coordinator_ln.py  — LN demo coordinator: bootstrap channels + N rounds
  start_coordinator.sh   — Multi-PC: start bitcoind + CLN coordinator, run rounds
  start_participant.sh   — Multi-PC: start CLN node + FastAPI on a participant PC
  test_local_multipc.sh  — Simulate N PCs on one machine (shifted ports)

deploy/
  coord.yml              — Multi-PC: bitcoind + CLN coordinator (coordinator's PC)
  participant.yml        — Multi-PC: CLN node + FastAPI (participant's PC)
  run.yml                — Multi-PC: coordinator script container
  *.local.yml            — Linux overrides (extra_hosts)
```

## Running the demo

### Option A — Single machine

```bash
# Full LN stack (bitcoind + coordinator CLN + N participant CLN + N FastAPI):
docker compose up --build
make demo

# Run coordinator interactively (pause between rounds):
INTERACTIVE=1 docker compose run --rm -it coordinator
make demo-interactive
```

### Option B — Multi-PC (live demo)

```bash
# On each participant's PC:
./scripts/start_participant.sh 192.168.1.10   # coordinator's IP

# On the coordinator's PC:
INTERACTIVE=1 ./scripts/start_coordinator.sh 192.168.1.10 192.168.1.11 192.168.1.12
```

Verify the multi-PC flow on a single machine before the live demo:

```bash
./scripts/test_local_multipc.sh        # 3 participants, shifted ports
make multipc-interactive               # with pause between rounds
```

See `docs/local-network-ln.md` for the full multi-PC tutorial.

## Running tests

```bash
# Unit tests — no node required
make test

# E2E regtest (Bitcoin Core):
make test-e2e

# E2E Docker LN (Docker):
make test-ln
```

## Requirements

- Python 3.11+
- Docker + Docker Compose v2 (for LN demo and e2e Docker tests)
- Bitcoin Core without wallet support (for regtest e2e only)

```bash
pip install -r requirements.txt          # protocol + tests
pip install -r requirements-demo.txt     # FastAPI + httpx + pyln-client
```

## Key design decisions

- **One Taproot address per round** — each round has a fresh HTLC hash, so addresses are unlinkable
- **MuSig2 keypath hides script tree** — on-chain cooperative spends are indistinguishable from single-key P2TR
- **BIP-342 CHECKSIGADD for refund multisig** — efficient Tapscript threshold with explicit absent-signer slots (`b""`)
- **Per-input sighash** — BIP-341 commits to `input_index`; multi-input transactions require fresh nonces and separate signatures per input
- **Hold invoices for LN rounds** — HTLC-based commitment prevents coordinator from paying winner before collecting from all participants
- **Star topology with push_msat** — coordinator opens all channels and pushes 150k sats of outbound liquidity to each participant; no participant-to-participant channels needed
- **CLN + BoltzExchange/hold plugin** — hold invoices are not part of the BOLT spec; the hold plugin exposes `holdinvoice` / `settleholdinvoice` / `cancelholdinvoice` as CLN commands
