"""
Taproot script construction and transaction building for the tanda protocol.

Script tree for each contribution UTXO in round k:

  TaprootOutput:
    internal_key: musig2_aggregate(pk_1, ..., pk_n)
    script_tree:
      leaf1 (HTLC winner claim):
        and_v(v:pk(Pₖ), sha256(Hₖ))
      leaf2 (refund collective):
        and_v(after(T_refund), thresh(k_min, pk(P₁), ..., pk(Pₙ)))

Spending paths:
  keypath  — all participants sign cooperatively via MuSig2 → claim_tx to Pₖ
  leaf1    — Pₖ signs + reveals preimage after T_claim blocks
  leaf2    — k_min-of-N participants sign after T_refund blocks
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

# embit imports
from embit.ec import PrivateKey, PublicKey, SchnorrSig
from embit.hashes import tagged_hash
from embit.script import Script
from embit.transaction import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    Witness,
    SIGHASH,
)
from embit import psbt as psbt_mod
from embit.psbt import PSBT, InputScope, OutputScope

from .musig2 import key_agg, KeyAggContext, apply_tweak

# ── Network helpers ───────────────────────────────────────────────────────────

REGTEST = {"bech32": "bcrt", "p2sh": 0xC4, "p2pkh": 0x6F}

SATS_PER_BTC = 100_000_000

# ── Script primitives ─────────────────────────────────────────────────────────

def _op(byte: int) -> bytes:
    return bytes([byte])


# Bitcoin script opcodes
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF
OP_CHECKSEQUENCEVERIFY = 0xB2  # CSV
OP_CHECKLOCKTIMEVERIFY = 0xB1  # CLTV
OP_DROP = 0x75
OP_2DROP = 0x6D
OP_VERIFY = 0x69
OP_EQUAL = 0x87
OP_SHA256 = 0xA8
OP_SWAP = 0x7C
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_TRUE = 0x51
OP_RETURN = 0x6A
OP_CHECKSIGADD = 0xBA  # Tapscript (BIP-342)
OP_NUMEQUAL = 0x9C
OP_NUMEQUALVERIFY = 0x9D
OP_1 = 0x51
OP_0 = 0x00

TAPSCRIPT_LEAF_VERSION = 0xC0


def _push_bytes(data: bytes) -> bytes:
    """Minimal push of data bytes as Bitcoin script element."""
    n = len(data)
    if n == 0:
        return bytes([0x00])
    if n <= 75:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([0x4C, n]) + data
    raise ValueError(f"Data too large to push: {n} bytes")


def _push_int(n: int) -> bytes:
    """Push integer n (script number encoding)."""
    if n == 0:
        return bytes([OP_0])
    if 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    # Encode as script number (little-endian with sign bit)
    negative = n < 0
    absval = abs(n)
    result = []
    while absval:
        result.append(absval & 0xFF)
        absval >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return _push_bytes(bytes(result))


# ── Taproot primitives ────────────────────────────────────────────────────────

def _tap_leaf_hash(script_bytes: bytes, version: int = TAPSCRIPT_LEAF_VERSION) -> bytes:
    """BIP-341 tapleaf hash."""
    ser = bytes([version]) + _compact_size(len(script_bytes)) + script_bytes
    return tagged_hash("TapLeaf", ser)


def _tap_branch_hash(left: bytes, right: bytes) -> bytes:
    """BIP-341 tapbranch hash (lexicographic order)."""
    if left > right:
        left, right = right, left
    return tagged_hash("TapBranch", left + right)


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _taproot_tweak(internal_key_xonly: bytes, merkle_root: bytes) -> bytes:
    """Compute the Taproot tweak scalar bytes from internal key + script tree merkle root."""
    t = tagged_hash("TapTweak", internal_key_xonly + merkle_root)
    return t


# Public alias for use in coordinator and tests
taproot_tweak = _taproot_tweak


def _tweak_pubkey(internal_key_xonly: bytes, tweak: bytes) -> tuple[bytes, bool]:
    """
    Return (output_key_xonly, parity) after applying tweak to internal key.
    parity=True means the output key has odd y.
    """
    import coincurve
    G = coincurve.PublicKey(
        bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
    )
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    t_int = int.from_bytes(tweak, "big") % N

    # Reconstruct internal pubkey with even y from xonly
    P = coincurve.PublicKey(b"\x02" + internal_key_xonly)
    tG = coincurve.PublicKey(
        bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    ).multiply(tweak)

    Q = coincurve.PublicKey.combine_keys([P, tG])
    q_compressed = Q.format(compressed=True)
    parity = q_compressed[0] == 0x03
    return q_compressed[1:], parity  # xonly, parity


# ── Script builders ───────────────────────────────────────────────────────────

def _build_htlc_winner_script(winner_xonly: bytes, htlc_hash: bytes) -> bytes:
    """
    leaf1: HTLC winner claim
    Tapscript: <winner_xonly> OP_CHECKSIGVERIFY OP_SHA256 <H> OP_EQUAL

    The witness for spending is: [preimage, winner_sig]
    (witness stack is evaluated in LIFO order)
    """
    return (
        _push_bytes(winner_xonly)         # <winner_xonly>
        + bytes([OP_CHECKSIGVERIFY])       # OP_CHECKSIGVERIFY
        + bytes([OP_SHA256])               # OP_SHA256
        + _push_bytes(htlc_hash)           # <H>
        + bytes([OP_EQUAL])                # OP_EQUAL
    )


def _build_refund_script(participants_xonly: list[bytes], k_min: int, t_refund: int) -> bytes:
    """
    leaf2: collective refund after t_refund blocks.

    Tapscript (BIP-342 CHECKSIGADD for Taproot multisig):
      <t_refund> OP_CSV OP_DROP
      <pk_1> OP_CHECKSIG
      <pk_2> OP_CHECKSIGADD
      ...
      <pk_n> OP_CHECKSIGADD
      <k_min> OP_NUMEQUAL

    Witness: [sig_or_empty_for_each_key_in_reverse_order]
    """
    script = (
        _push_int(t_refund)
        + bytes([OP_CHECKSEQUENCEVERIFY])
        + bytes([OP_DROP])
        + _push_bytes(participants_xonly[0])
        + bytes([OP_CHECKSIG])
    )
    for pk_xonly in participants_xonly[1:]:
        script += _push_bytes(pk_xonly) + bytes([OP_CHECKSIGADD])

    script += _push_int(k_min) + bytes([OP_NUMEQUAL])
    return script


# ── TapTree builder ───────────────────────────────────────────────────────────

@dataclass
class TapLeaf:
    script: bytes
    version: int = TAPSCRIPT_LEAF_VERSION

    @property
    def leaf_hash(self) -> bytes:
        return _tap_leaf_hash(self.script, self.version)


@dataclass
class TapTree:
    """Simple binary tap tree (exactly two leaves: leaf1 and leaf2)."""
    leaf1: TapLeaf
    leaf2: TapLeaf

    @property
    def merkle_root(self) -> bytes:
        return _tap_branch_hash(self.leaf1.leaf_hash, self.leaf2.leaf_hash)


# ── Main protocol script builder ──────────────────────────────────────────────

@dataclass
class RoundScripts:
    """All script information for a tanda round."""
    internal_key_xonly: bytes       # MuSig2 aggregate key (32 bytes, even y)
    output_key_xonly: bytes         # tweaked output key
    output_key_parity: bool         # True = odd y
    tap_tree: TapTree
    merkle_root: bytes
    script_pubkey: Script           # OP_1 <32:xonly>
    address: str                    # bech32m regtest address


def build_taproot_output(
    winner_pubkey: bytes,           # 33-byte compressed pubkey of round winner
    all_pubkeys: list[bytes],       # 33-byte compressed pubkeys of ALL participants
    htlc_hash: bytes,               # 32-byte SHA-256 hash (H_k)
    t_refund: int,                  # block height delta for refund timelock
    k_min: int,                     # minimum signatures for refund
    network: dict = REGTEST,
) -> RoundScripts:
    """
    Build the Taproot output for one tanda round.

    Returns a RoundScripts with address, script, and auxiliary data.
    """
    # 1. MuSig2 key aggregation → internal key
    kac = key_agg(all_pubkeys)
    # Ensure even y for internal key (BIP-340)
    if kac.Q.format(compressed=True)[0] == 0x03:
        # Internal key must have even y; we negate to get even y
        # (we track this via gacc in KeyAggContext)
        import coincurve
        q_bytes = kac.Q.format(compressed=True)
        q_negated = coincurve.PublicKey(bytes([0x02]) + q_bytes[1:])
        kac.Q = q_negated
        kac.gacc = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - kac.gacc) % \
                   0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    internal_key_xonly = kac.agg_pk  # 32 bytes

    # 2. Build x-only pubkeys for scripts
    winner_xonly = PublicKey.parse(winner_pubkey).xonly()
    participants_xonly = [PublicKey.parse(pk).xonly() for pk in sorted(all_pubkeys)]

    # 3. Build leaf scripts
    leaf1 = TapLeaf(_build_htlc_winner_script(winner_xonly, htlc_hash))
    leaf2 = TapLeaf(_build_refund_script(participants_xonly, k_min, t_refund))
    tap_tree = TapTree(leaf1, leaf2)

    # 4. Tweak internal key with merkle root → output key
    merkle_root = tap_tree.merkle_root
    tweak = _taproot_tweak(internal_key_xonly, merkle_root)
    output_key_xonly, parity = _tweak_pubkey(internal_key_xonly, tweak)

    # 5. Build scriptPubKey: OP_1 <32:xonly>
    spk_bytes = bytes([0x51, 0x20]) + output_key_xonly
    script_pubkey = Script(spk_bytes)
    address = script_pubkey.address(network=network)

    return RoundScripts(
        internal_key_xonly=internal_key_xonly,
        output_key_xonly=output_key_xonly,
        output_key_parity=parity,
        tap_tree=tap_tree,
        merkle_root=merkle_root,
        script_pubkey=script_pubkey,
        address=address,
    )


# ── UTXO / amount helpers ────────────────────────────────────────────────────

@dataclass
class UTXO:
    txid: str
    vout: int
    amount_sats: int          # satoshis
    script_pubkey: bytes      # serialized scriptPubKey

    @property
    def outpoint(self) -> tuple[str, int]:
        return (self.txid, self.vout)


def btc_to_sats(btc: float) -> int:
    return round(btc * SATS_PER_BTC)


def sats_to_btc(sats: int) -> float:
    return sats / SATS_PER_BTC


# ── Transaction builders ──────────────────────────────────────────────────────

def _build_tx_input(utxo: UTXO, sequence: int = 0xFFFFFFFD) -> TransactionInput:
    # embit's TransactionInput.write_to reverses self.txid, so pass display order (no reversal)
    txid_bytes = bytes.fromhex(utxo.txid)
    return TransactionInput(txid_bytes, utxo.vout, sequence=sequence)


def _build_tx_output(address: str, amount_sats: int, network: dict = REGTEST) -> TransactionOutput:
    spk = Script.from_address(address)
    return TransactionOutput(amount_sats, spk)


def _estimate_fee_sats(n_inputs: int, n_outputs: int, feerate_sat_vb: int = 2) -> int:
    """
    Rough fee estimate for a Taproot keypath spend.
    vbytes ≈ 10.5 (overhead) + 57.5*n_inputs + 43*n_outputs
    """
    vbytes = 10.5 + 57.5 * n_inputs + 43 * n_outputs
    return int(vbytes * feerate_sat_vb) + 10  # small buffer


def build_claim_tx(
    utxos: list[UTXO],
    winner_address: str,
    feerate_sat_vb: int = 2,
    network: dict = REGTEST,
) -> Transaction:
    """
    Build the cooperative claim transaction (keypath spend via MuSig2).
    All UTXOs → winner_address (minus fee).
    """
    total_in = sum(u.amount_sats for u in utxos)
    fee = _estimate_fee_sats(len(utxos), 1, feerate_sat_vb)
    amount_out = total_in - fee

    tx = Transaction(
        version=2,
        vin=[_build_tx_input(u, sequence=0xFFFFFFFD) for u in utxos],
        vout=[_build_tx_output(winner_address, amount_out, network)],
    )
    return tx


def build_htlc_claim_tx(
    utxos: list[UTXO],
    winner_address: str,
    feerate_sat_vb: int = 2,
    network: dict = REGTEST,
) -> Transaction:
    """
    Build the HTLC scriptpath claim transaction (leaf1 spend).
    Sequence is set to 0xFFFFFFFD (RBF; no CSV restriction on leaf1).
    """
    return build_claim_tx(utxos, winner_address, feerate_sat_vb, network)


def build_refund_tx(
    utxos: list[UTXO],
    participant_addresses: list[str],
    t_refund: int,
    feerate_sat_vb: int = 2,
    network: dict = REGTEST,
) -> Transaction:
    """
    Build the collective refund transaction (leaf2 spend with CSV).
    Each participant receives a pro-rata share minus fee.
    Sequence must encode t_refund for CSV validation.
    """
    n = len(participant_addresses)
    total_in = sum(u.amount_sats for u in utxos)
    fee = _estimate_fee_sats(len(utxos), n, feerate_sat_vb)
    each = (total_in - fee) // n

    # CSV sequence encoding (type=0 = block-based relative lock)
    csv_sequence = t_refund & 0xFFFF

    tx = Transaction(
        version=2,
        vin=[_build_tx_input(u, sequence=csv_sequence) for u in utxos],
        vout=[_build_tx_output(addr, each, network) for addr in participant_addresses],
    )
    return tx


# ── Sighash computation (BIP-341 / BIP-342) ──────────────────────────────────

def _read_uint32_le(b: bytes, offset: int) -> int:
    return struct.unpack_from("<I", b, offset)[0]


def compute_taproot_sighash(
    tx: Transaction,
    input_index: int,
    utxos: list[UTXO],
    sighash_type: int = 0,  # SIGHASH_DEFAULT
    script_path: Optional[bytes] = None,  # None for keypath
    leaf_version: int = TAPSCRIPT_LEAF_VERSION,
    codesep_pos: int = 0xFFFFFFFF,
) -> bytes:
    """
    Compute the sighash for a Taproot input (BIP-341 for keypath, BIP-342 for scriptpath).

    Implements the BIP-341 common signature message:
      epoch(1) || hash_type(1) || nVersion(4) || nLockTime(4)
      || sha_prevouts(32) || sha_amounts(32) || sha_scriptpubkeys(32) || sha_sequences(32)
      || sha_outputs(32) || spend_type(1) || input_index(4)  [for non-ANYONECANPAY]
      [|| tap_leaf_hash(32) || key_version(1) || codesep_pos(4)  for script path]
    """
    def hash_prevouts() -> bytes:
        h = hashlib.sha256()
        for u in utxos:
            h.update(bytes.fromhex(u.txid)[::-1])
            h.update(struct.pack("<I", u.vout))
        return h.digest()

    def hash_amounts() -> bytes:
        h = hashlib.sha256()
        for u in utxos:
            h.update(struct.pack("<q", u.amount_sats))
        return h.digest()

    def hash_script_pubkeys() -> bytes:
        h = hashlib.sha256()
        for u in utxos:
            spk = u.script_pubkey
            h.update(_compact_size(len(spk)) + spk)
        return h.digest()

    def hash_sequences() -> bytes:
        h = hashlib.sha256()
        for inp in tx.vin:
            h.update(struct.pack("<I", inp.sequence))
        return h.digest()

    def hash_outputs() -> bytes:
        h = hashlib.sha256()
        for out in tx.vout:
            h.update(struct.pack("<q", out.value))
            # Script.serialize() already includes compact_size prefix; don't add another
            h.update(out.script_pubkey.serialize())
        return h.digest()

    ext_flag = 0 if script_path is None else 1

    # BIP-341: out_type and in_type derivation
    SIGHASH_ALL_VAL = 1
    SIGHASH_ANYONECANPAY_FLAG = 0x80
    out_type = SIGHASH_ALL_VAL if sighash_type == 0 else (sighash_type & 3)
    in_type  = SIGHASH_ALL_VAL if sighash_type == 0 else (sighash_type & 0xC0)

    # Common fields: epoch(0x00) || hash_type || nVersion || nLockTime
    data = bytes([0x00, sighash_type])
    data += struct.pack("<I", tx.version)
    data += struct.pack("<I", tx.locktime)

    # All-inputs hashes (omitted for ANYONECANPAY)
    if in_type != SIGHASH_ANYONECANPAY_FLAG:
        data += hash_prevouts()
        data += hash_amounts()
        data += hash_script_pubkeys()
        data += hash_sequences()

    # All-outputs hash (only for SIGHASH_ALL)
    if out_type == SIGHASH_ALL_VAL:
        data += hash_outputs()

    # spend_type: bit1 = ext_flag (script path), bit0 = annex present (always 0 here)
    spend_type = ext_flag * 2
    data += bytes([spend_type])

    inp = tx.vin[input_index]
    utxo = utxos[input_index]

    if in_type == SIGHASH_ANYONECANPAY_FLAG:
        # ANYONECANPAY: include this input's outpoint, amount, scriptPubKey, sequence
        data += bytes.fromhex(utxo.txid)[::-1]
        data += struct.pack("<I", utxo.vout)
        data += struct.pack("<q", utxo.amount_sats)
        spk = utxo.script_pubkey
        data += _compact_size(len(spk)) + spk
        data += struct.pack("<I", inp.sequence)
    else:
        # Non-ANYONECANPAY: only the input index (per-input data is in sha_* above)
        data += struct.pack("<I", input_index)

    # Script path extension (BIP-342)
    if script_path is not None:
        leaf_hash = _tap_leaf_hash(script_path, leaf_version)
        data += leaf_hash
        data += bytes([0])           # key_version = 0
        data += struct.pack("<I", codesep_pos)

    return tagged_hash("TapSighash", data)


# ── Witness builders ──────────────────────────────────────────────────────────

def make_keypath_witness(schnorr_sig: bytes) -> Witness:
    """Witness for keypath (MuSig2) spend: just the 64-byte sig."""
    return Witness([schnorr_sig])


def make_htlc_claim_witness(
    winner_sig: bytes,
    preimage: bytes,
    htlc_script: bytes,
    control_block: bytes,
) -> Witness:
    """
    Witness for leaf1 HTLC claim spend.
    Stack (bottom to top): preimage, winner_sig, script, control_block
    """
    return Witness([preimage, winner_sig, htlc_script, control_block])


def make_refund_witness(
    sigs: list[bytes],          # one per participant (empty bytes = not signing)
    refund_script: bytes,
    control_block: bytes,
) -> Witness:
    """
    Witness for leaf2 refund spend.
    Stack: [sigs in reverse order of keys], script, control_block
    """
    return Witness(list(reversed(sigs)) + [refund_script, control_block])


# ── Control block builder ─────────────────────────────────────────────────────

def build_control_block(
    internal_key_xonly: bytes,
    output_key_parity: bool,
    sibling_hash: bytes,
    leaf_version: int = TAPSCRIPT_LEAF_VERSION,
) -> bytes:
    """
    Build the control block for a script-path spend (BIP-341).

    For a 2-leaf tree, the sibling_hash is the hash of the other leaf.
    """
    parity_bit = 0x01 if output_key_parity else 0x00
    first_byte = leaf_version | parity_bit
    return bytes([first_byte]) + internal_key_xonly + sibling_hash


# ── Signing helpers ───────────────────────────────────────────────────────────

def sign_taproot_keypath(
    tx: Transaction,
    input_index: int,
    utxos: list[UTXO],
    privkey: PrivateKey,
    sighash_type: int = 0,
) -> bytes:
    """
    Sign a keypath taproot input with a single private key (for testing).
    In production, replace with MuSig2 partial_sign + partial_sig_agg.
    """
    sighash = compute_taproot_sighash(tx, input_index, utxos, sighash_type)
    sig = privkey.schnorr_sign(sighash)
    sig_bytes = sig.serialize()
    if sighash_type != 0:
        sig_bytes += bytes([sighash_type])
    return sig_bytes


def sign_tapscript(
    tx: Transaction,
    input_index: int,
    utxos: list[UTXO],
    privkey: PrivateKey,
    script: bytes,
    sighash_type: int = 0,
) -> bytes:
    """
    Sign a script-path taproot input (BIP-342 Schnorr signature).
    """
    sighash = compute_taproot_sighash(
        tx, input_index, utxos, sighash_type,
        script_path=script,
    )
    sig = privkey.schnorr_sign(sighash)
    sig_bytes = sig.serialize()
    if sighash_type != 0:
        sig_bytes += bytes([sighash_type])
    return sig_bytes
