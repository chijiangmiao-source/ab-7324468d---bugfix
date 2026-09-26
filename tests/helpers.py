"""Shared helpers: generate test P-256 keys and sign canonical messages."""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import crypto


def generate_keys(n: int):
    """Return [(private_key, key_id, compressed_pubkey_hex), ...]."""
    out = []
    for _ in range(n):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        out.append((priv, crypto.key_fingerprint(pub), crypto.public_key_hex(pub)))
    return out


def sign(priv, group_id: str, prev_digest: str, seq: int, config: str) -> str:
    """Produce a DER ECDSA/SHA-256 signature over the canonical message (hex)."""
    message = crypto.canonical_message(group_id, prev_digest, seq, config)
    der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return der.hex()


def signature_entry(priv, key_id: str, group_id: str, prev_digest: str, seq: int, config: str) -> dict:
    return {"key_id": key_id, "signature": sign(priv, group_id, prev_digest, seq, config)}


def priv_to_pem_hex(priv) -> str:
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
