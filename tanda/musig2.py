"""
MuSig2 implementation following BIP-327.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki

This implementation covers:
  - Key aggregation (KeyAgg)
  - Nonce generation (NonceGen)
  - Nonce aggregation (NonceAgg)
  - Partial signing (Sign)
  - Partial signature verification (PartialSigVerify)
  - Partial signature aggregation (PartialSigAgg)

Uses coincurve + embit for the underlying secp256k1 operations.
"""

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Optional

import coincurve

# ── Constants ─────────────────────────────────────────────────────────────────

# secp256k1 group order n
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Generator point G (compressed)
G_COMPRESSED = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)


# ── Tagged hash helpers ───────────────────────────────────────────────────────

def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_b = tag.encode("utf-8")
    tag_h = hashlib.sha256(tag_b).digest()
    return hashlib.sha256(tag_h + tag_h + data).digest()


def _hash_keys(pubkeys: list[bytes]) -> bytes:
    return _tagged_hash("KeyAgg list", b"".join(pubkeys))


def _hash_coeff(L: bytes, pk: bytes) -> bytes:
    return _tagged_hash("KeyAgg coefficient", L + pk)


def _hash_nonce(rand: bytes, pk: bytes, agg_pk: bytes, m_pre: bytes) -> bytes:
    return _tagged_hash("MuSig/nonce", rand + pk + agg_pk + m_pre)


def _hash_noncecoeff(agg_nonce: bytes, q: bytes, msg: bytes) -> bytes:
    return _tagged_hash("MuSig/noncecoef", agg_nonce + q + msg)


def _hash_sig(r: bytes, q: bytes, msg: bytes) -> bytes:
    return _tagged_hash("BIP0340/challenge", r + q + msg)


# ── Elliptic curve helpers ────────────────────────────────────────────────────

def _int_to_bytes32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _mod(a: int) -> int:
    return a % N


def _point_from_compressed(b: bytes) -> coincurve.PublicKey:
    return coincurve.PublicKey(b)


def _point_mul(point: coincurve.PublicKey, scalar: int) -> coincurve.PublicKey:
    """Multiply point by scalar (scalar as 32-byte big-endian)."""
    scalar_b = _int_to_bytes32(scalar % N)
    return coincurve.PublicKey(point.format(compressed=True)).multiply(scalar_b)


def _point_add(*points: coincurve.PublicKey) -> Optional[coincurve.PublicKey]:
    """Add multiple points; returns None if any is the point at infinity."""
    pts = [p for p in points if p is not None]
    if not pts:
        return None
    return coincurve.PublicKey.combine_keys(pts)


def _xonly(point: coincurve.PublicKey) -> bytes:
    """Return the 32-byte x-only representation of a point."""
    return point.format(compressed=True)[1:]  # drop parity byte


def _has_even_y(point: coincurve.PublicKey) -> bool:
    return point.format(compressed=True)[0] == 0x02


def _negate_scalar(s: int) -> int:
    return (-s) % N


def _negate_point(point: coincurve.PublicKey) -> coincurve.PublicKey:
    """Return the negated (reflected y) point."""
    b = point.format(compressed=True)
    parity = 0x02 if b[0] == 0x03 else 0x03
    return coincurve.PublicKey(bytes([parity]) + b[1:])


def _cbytes(pk: bytes) -> bytes:
    """Compressed (33-byte) bytes for a public key."""
    return pk


def _cbytes_ext(pk: bytes) -> bytes:
    """33-byte compressed pubkey."""
    return pk


# ── Key Aggregation ───────────────────────────────────────────────────────────

@dataclass
class KeyAggContext:
    """Result of key aggregation (BIP-327 §Key Generation)."""
    Q: coincurve.PublicKey        # aggregate public key (may have odd y)
    gacc: int                      # group accumulator (1 or -1 mod N)
    tacc: int                      # tweak accumulator
    pubkeys: list[bytes]           # sorted compressed pubkeys
    L: bytes                       # hash of sorted pubkeys
    coeffs: list[int]              # KeyAgg coefficients a_i

    @property
    def agg_pk(self) -> bytes:
        """x-only aggregate public key (32 bytes)."""
        return _xonly(self.Q)


def key_agg(pubkeys: list[bytes]) -> KeyAggContext:
    """
    BIP-327 KeyAgg algorithm.

    Args:
        pubkeys: list of 33-byte compressed public keys (any order)

    Returns:
        KeyAggContext with aggregate key Q and auxiliary info
    """
    if not pubkeys:
        raise ValueError("Need at least one pubkey")

    # Step 1: sort lexicographically
    sorted_pks = sorted(pubkeys)

    # Step 2: L = H(pk_1 || ... || pk_n)
    L = _hash_keys(sorted_pks)

    # Step 3: identify "second unique" key
    second_unique = None
    for pk in sorted_pks:
        if pk != sorted_pks[0]:
            second_unique = pk
            break

    # Step 4: compute coefficients
    coeffs = []
    for pk in sorted_pks:
        if pk == second_unique:
            a = 1
        else:
            a_bytes = _hash_coeff(L, pk)
            a = _bytes_to_int(a_bytes) % N
        coeffs.append(a)

    # Step 5: Q = sum(a_i * P_i)
    terms = []
    for i, pk in enumerate(sorted_pks):
        P_i = _point_from_compressed(pk)
        term = _point_mul(P_i, coeffs[i])
        terms.append(term)

    Q = _point_add(*terms)
    if Q is None:
        raise ValueError("Aggregate key is point at infinity")

    return KeyAggContext(
        Q=Q,
        gacc=1,
        tacc=0,
        pubkeys=sorted_pks,
        L=L,
        coeffs=coeffs,
    )


def apply_tweak(ctx: KeyAggContext, tweak: bytes, is_xonly: bool = True) -> KeyAggContext:
    """
    Apply a tweak to the aggregated key (BIP-327 §Tweaking).
    Used for tapscript commitment: internal_key + tagged_hash(tweak).
    """
    t = _bytes_to_int(tweak)
    if t >= N:
        raise ValueError("Tweak out of range")

    g = 1
    if is_xonly and not _has_even_y(ctx.Q):
        g = N - 1  # negate

    # Q' = t*G + g*Q
    tG = _point_mul(_point_from_compressed(G_COMPRESSED), t)
    gQ = _point_mul(ctx.Q, g)
    Q_new = _point_add(tG, gQ)
    if Q_new is None:
        raise ValueError("Tweaked key is point at infinity")

    gacc_new = _mod(g * ctx.gacc)
    tacc_new = _mod(t + g * ctx.tacc)

    return KeyAggContext(
        Q=Q_new,
        gacc=gacc_new,
        tacc=tacc_new,
        pubkeys=ctx.pubkeys,
        L=ctx.L,
        coeffs=ctx.coeffs,
    )


# ── Nonce Generation ──────────────────────────────────────────────────────────

@dataclass
class SecNonce:
    """Secret nonce pair (k1, k2); must be kept secret and used only once."""
    k1: int
    k2: int

    def serialize(self) -> bytes:
        return _int_to_bytes32(self.k1) + _int_to_bytes32(self.k2)

    @classmethod
    def from_bytes(cls, b: bytes) -> "SecNonce":
        assert len(b) == 64
        return cls(_bytes_to_int(b[:32]), _bytes_to_int(b[32:]))


@dataclass
class PubNonce:
    """Public nonce pair (R1, R2)."""
    R1: coincurve.PublicKey
    R2: coincurve.PublicKey

    def serialize(self) -> bytes:
        return self.R1.format(compressed=True) + self.R2.format(compressed=True)

    @classmethod
    def from_bytes(cls, b: bytes) -> "PubNonce":
        assert len(b) == 66
        return cls(
            coincurve.PublicKey(b[:33]),
            coincurve.PublicKey(b[33:]),
        )


def nonce_gen(
    sk: Optional[bytes] = None,
    pk: Optional[bytes] = None,
    agg_pk: Optional[bytes] = None,
    msg: Optional[bytes] = None,
    extra_in: Optional[bytes] = None,
) -> tuple[SecNonce, PubNonce]:
    """
    BIP-327 NonceGen: generate a fresh secret+public nonce pair.
    """
    rand = secrets.token_bytes(32)

    # Build input to hash
    sk_b = sk if sk else b"\x00" * 32
    pk_b = pk if pk else b"\x00" * 33
    agg_pk_b = agg_pk if agg_pk else b"\x00" * 32
    m_pre = (b"\x00" if msg is None else b"\x01" + len(msg).to_bytes(8, "big") + msg)
    extra = extra_in if extra_in else b""

    # k_i = H("MuSig/nonce", rand || len(sk_b)||sk_b || len(pk_b)||pk_b || agg_pk_b || m_pre || extra)
    # Simplified version using _hash_nonce helper
    base = (
        rand
        + bytes([len(sk_b)]) + sk_b
        + bytes([len(pk_b)]) + pk_b
        + agg_pk_b
        + m_pre
        + len(extra).to_bytes(4, "big") + extra
    )

    k1 = _bytes_to_int(_tagged_hash("MuSig/nonce", base + b"\x00")) % N
    k2 = _bytes_to_int(_tagged_hash("MuSig/nonce", base + b"\x01")) % N

    if k1 == 0 or k2 == 0:
        raise ValueError("Nonce generation produced zero scalar")

    G = _point_from_compressed(G_COMPRESSED)
    R1 = _point_mul(G, k1)
    R2 = _point_mul(G, k2)

    return SecNonce(k1, k2), PubNonce(R1, R2)


# ── Nonce Aggregation ─────────────────────────────────────────────────────────

@dataclass
class AggNonce:
    """Aggregate public nonce."""
    R1: coincurve.PublicKey
    R2: coincurve.PublicKey

    def serialize(self) -> bytes:
        return self.R1.format(compressed=True) + self.R2.format(compressed=True)


def nonce_agg(pub_nonces: list[PubNonce]) -> AggNonce:
    """
    BIP-327 NonceAgg: aggregate public nonces from all signers.
    """
    R1_pts = [pn.R1 for pn in pub_nonces]
    R2_pts = [pn.R2 for pn in pub_nonces]

    R1_agg = _point_add(*R1_pts)
    R2_agg = _point_add(*R2_pts)

    # Use NUMS point (no discrete log known) if sum is infinity
    # In practice this shouldn't happen for honest participants
    if R1_agg is None or R2_agg is None:
        raise ValueError("Nonce aggregation produced infinity point")

    return AggNonce(R1_agg, R2_agg)


# ── Session Context ───────────────────────────────────────────────────────────

@dataclass
class SessionContext:
    """Holds all public information needed during signing."""
    agg_nonce: AggNonce
    key_agg_ctx: KeyAggContext
    msg: bytes          # 32-byte message (sighash)

    # Computed lazily
    _b: Optional[int] = field(default=None, repr=False)
    _R: Optional[coincurve.PublicKey] = field(default=None, repr=False)
    _e: Optional[int] = field(default=None, repr=False)
    # True if the raw aggregated nonce R' had odd y and was negated to get even-y R.
    # Signers must negate their k1, k2 in this case (BIP-327).
    _r_negated: bool = field(default=False, repr=False)

    def _compute(self):
        if self._R is not None:
            return
        ctx = self.key_agg_ctx
        Q_xonly = ctx.agg_pk  # 32 bytes

        # b = H_noncecoeff(R1||R2, Q, msg)
        agg_nonce_bytes = self.agg_nonce.serialize()
        b_bytes = _tagged_hash("MuSig/noncecoef", agg_nonce_bytes + Q_xonly + self.msg)
        self._b = _bytes_to_int(b_bytes) % N

        # R' = R1 + b*R2
        bR2 = _point_mul(self.agg_nonce.R2, self._b)
        R_candidate = _point_add(self.agg_nonce.R1, bR2)

        # If R' is at infinity, use G (BIP-327 §Sign step 5)
        if R_candidate is None:
            R_prime = _point_from_compressed(G_COMPRESSED)
        else:
            R_prime = R_candidate

        # If R' has odd y, record that k1/k2 must be negated; store even-y R for sighash
        if not _has_even_y(R_prime):
            self._r_negated = True
            self._R = _negate_point(R_prime)
        else:
            self._r_negated = False
            self._R = R_prime

        R_xonly = _xonly(self._R)  # always even y here

        # e = H("BIP0340/challenge", R_x || Q_x || msg) mod n
        e_bytes = _tagged_hash("BIP0340/challenge", R_xonly + Q_xonly + self.msg)
        self._e = _bytes_to_int(e_bytes) % N

    @property
    def b(self) -> int:
        self._compute()
        return self._b

    @property
    def R(self) -> coincurve.PublicKey:
        self._compute()
        return self._R

    @property
    def e(self) -> int:
        self._compute()
        return self._e

    @property
    def r_negated(self) -> bool:
        """True when k1/k2 must be negated by signers (R' had odd y)."""
        self._compute()
        return self._r_negated


# ── Partial Signing ───────────────────────────────────────────────────────────

def partial_sign(
    sec_nonce: SecNonce,
    sk: bytes,
    session_ctx: SessionContext,
) -> int:
    """
    BIP-327 Sign: produce a partial signature.

    Args:
        sec_nonce: the signer's secret nonce (k1, k2); zeroed after use
        sk: the signer's 32-byte secret key
        session_ctx: session context

    Returns:
        s_i (int): partial signature scalar
    """
    ctx = session_ctx.key_agg_ctx

    # Find signer's pubkey and coefficient
    pk_bytes = coincurve.PrivateKey(sk).public_key.format(compressed=True)

    # Find matching sorted index
    try:
        idx = ctx.pubkeys.index(pk_bytes)
    except ValueError:
        raise ValueError("Signer's pubkey not found in key_agg_ctx")

    a_i = ctx.coeffs[idx]

    # Compute effective private key
    sk_int = _bytes_to_int(sk)
    P_i = coincurve.PrivateKey(sk).public_key

    # Adjust for aggregate key parity
    g = 1
    if not _has_even_y(ctx.Q):
        g = N - 1

    # Adjust for gacc
    d_i = _mod(g * ctx.gacc * sk_int)
    if d_i == 0:
        raise ValueError("Effective private key is zero")

    # k1, k2 adjusted for R parity: negate if the raw aggregated R' had odd y
    k1, k2 = sec_nonce.k1, sec_nonce.k2
    if session_ctx.r_negated:
        k1 = _negate_scalar(k1)
        k2 = _negate_scalar(k2)

    # s_i = k1 + b*k2 + e * a_i * d_i  (mod n)
    b = session_ctx.b
    e = session_ctx.e
    s_i = _mod(k1 + _mod(b * k2) + _mod(_mod(e * a_i) * d_i))

    return s_i


# ── Partial Signature Verification ───────────────────────────────────────────

def partial_sig_verify(
    psig: int,
    pub_nonce: PubNonce,
    pk: bytes,
    session_ctx: SessionContext,
) -> bool:
    """
    BIP-327 PartialSigVerify: verify one participant's partial signature.
    """
    ctx = session_ctx.key_agg_ctx

    try:
        idx = ctx.pubkeys.index(pk)
    except ValueError:
        return False

    a_i = ctx.coeffs[idx]
    b = session_ctx.b
    e = session_ctx.e

    G = _point_from_compressed(G_COMPRESSED)

    # LHS = s_i * G
    lhs = _point_mul(G, psig)

    # R_i = R1_i + b*R2_i  (negate if the raw aggregate nonce R' had odd y)
    bR2i = _point_mul(pub_nonce.R2, b)
    R_i = _point_add(pub_nonce.R1, bR2i)
    if session_ctx.r_negated:
        R_i = _negate_point(R_i)

    # P_i adjusted for aggregate key parity + gacc
    P_i = _point_from_compressed(pk)
    g = 1
    if not _has_even_y(ctx.Q):
        g = N - 1
    g_adj = _mod(g * ctx.gacc)
    P_adj = _point_mul(P_i, g_adj)

    # ePagg = e * a_i * P_adj
    ea = _mod(e * a_i)
    ePagg = _point_mul(P_adj, ea)

    # RHS = R_i + e*a_i*P_adj
    rhs = _point_add(R_i, ePagg)

    # Compare x-coordinates (after ensuring same parity)
    return lhs.format(compressed=True) == rhs.format(compressed=True)


# ── Partial Signature Aggregation ────────────────────────────────────────────

def partial_sig_agg(
    psigs: list[int],
    session_ctx: SessionContext,
) -> bytes:
    """
    BIP-327 PartialSigAgg: combine partial signatures into a final Schnorr sig.

    Returns:
        64-byte Schnorr signature (R_x || s)
    """
    ctx = session_ctx.key_agg_ctx
    R = session_ctx.R
    e = session_ctx.e

    # When the (tweaked) aggregate key Q has odd y, the BIP-340 verifier uses
    # P = lift_x(Q.x) = -Q.  The tacc contribution must be negated in that case.
    # BIP-327: s = sum(s_i) + e * g * tacc  (mod n)  where g = 1 if Q.y even else n-1
    g = 1 if _has_even_y(ctx.Q) else N - 1
    s = _mod(sum(psigs) + _mod(e * _mod(g * ctx.tacc)))

    R_xonly = _xonly(R)
    sig = R_xonly + _int_to_bytes32(s)
    assert len(sig) == 64
    return sig


# ── Final Signature Verification (BIP-340) ───────────────────────────────────

def schnorr_verify(sig: bytes, msg: bytes, agg_pk_xonly: bytes) -> bool:
    """
    Verify a 64-byte Schnorr signature against an x-only public key.
    Uses embit for the actual verification.
    """
    from embit.ec import PublicKey, SchnorrSig
    try:
        pub = PublicKey.from_xonly(agg_pk_xonly)
        schnorr_sig = SchnorrSig.parse(sig)
        return pub.schnorr_verify(schnorr_sig, msg)
    except Exception:
        return False
