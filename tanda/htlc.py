"""
HTLC helpers for the tanda protocol.

An HTLC (Hash Time Lock Contract) lets the round winner (Pₖ) claim the pot
by revealing the pre-image of a hash published by the coordinator.
"""

import hashlib
import os
import secrets


def generate_htlc_secret() -> tuple[bytes, bytes]:
    """
    Generate a random 32-byte pre-image and its SHA-256 hash.

    Returns:
        (preimage, hash): both as 32-byte raw bytes
    """
    preimage = secrets.token_bytes(32)
    htlc_hash = hashlib.sha256(preimage).digest()
    return preimage, htlc_hash


def verify_preimage(preimage: bytes, htlc_hash: bytes) -> bool:
    """
    Check that SHA-256(preimage) == htlc_hash.

    Args:
        preimage: the secret pre-image
        htlc_hash: the published 32-byte hash

    Returns:
        True if the pre-image is valid
    """
    return hashlib.sha256(preimage).digest() == htlc_hash


def encode_preimage_for_witness(preimage: bytes) -> bytes:
    """Return the raw preimage as a witness stack element (plain bytes)."""
    return preimage


def hash_hex(htlc_hash: bytes) -> str:
    return htlc_hash.hex()


def preimage_hex(preimage: bytes) -> str:
    return preimage.hex()
