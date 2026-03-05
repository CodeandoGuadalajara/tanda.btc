# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## regtest_setup.sh

Idempotent setup script for a local Bitcoin Core regtest node. Safe to re-run.
Works with Bitcoin Core compiled **without wallet support**.

**What it does:**
1. Creates `~/.bitcoin/bitcoin.conf` with `regtest=1`, `txindex=1`, RPC credentials (`user`/`password`, port 18443)
2. Starts `bitcoind -daemon -regtest` if not already running
3. Mines 101 blocks via `BitcoinRPC.mine()` (Python, wallet-less path) if height < 101

**Requires:** `bitcoind`, `bitcoin-cli`, `bitcoin-util`, and `python3` with `tanda` installed in PATH/PYTHONPATH.

**Does NOT use wallet RPCs** (`createwallet`, `generatetoaddress`, `sendtoaddress`). Those methods don't exist when Bitcoin Core is built without the wallet module. Mining uses `getblocktemplate + bitcoin-util grind + submitblock`.

**Note:** The e2e tests fund participants directly via raw transactions using deterministic private keys. No wallet setup is needed.

```bash
bash scripts/regtest_setup.sh
```

To stop the node:
```bash
bitcoin-cli -regtest stop
```
