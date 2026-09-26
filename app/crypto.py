"""Canonical message construction and P-256 ECDSA primitives.

Every reviewer signature commits to one unambiguous byte string:

    DOMAIN_SEPARATOR || 0x00
    || uint16BE(len(group_id)) || group_id          (UTF-8)
    || prev_digest                                  (32 raw bytes)
    || uint64BE(seq)
    || config                                       (UTF-8)

The confirmed package digest is SHA-256 over exactly these bytes, so the
chain hash and the signed payload can never drift apart.
"""
from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

# Domain separator: signatures made for any other purpose (or protocol
# version) can never be replayed as a config-package approval.
DOMAIN_SEPARATOR = b"LXe-ConfigSeal/v1"

# Predecessor digest expected of the first package in a chain (seq == 1).
GENESIS_DIGEST = "00" * 32

_DIGEST_LEN = 32
_RAW_SIG_LEN = 64  # P-256 r || s


class CryptoError(ValueError):
    """Key or signature material is malformed."""


def canonical_message(group_id: str, prev_digest: str, seq: int, config: str) -> bytes:
    """Return the canonical UTF-8 byte sequence that reviewers sign."""
    gid = group_id.encode("utf-8")
    if not gid or len(gid) > 0xFFFF:
        raise CryptoError("group_id must be 1..65535 UTF-8 bytes")
    try:
        prev = bytes.fromhex(prev_digest)
    except ValueError as exc:
        raise CryptoError("prev_digest must be hex") from exc
    if len(prev) != _DIGEST_LEN:
        raise CryptoError("prev_digest must be 32 bytes (64 hex chars)")
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 < seq < 1 << 63:
        raise CryptoError("seq must be an integer in 1..2^63-1")
    return (
        DOMAIN_SEPARATOR
        + b"\x00"
        + len(gid).to_bytes(2, "big")
        + gid
        + prev
        + seq.to_bytes(8, "big")
        + config.encode("utf-8")
    )


def package_digest(group_id: str, prev_digest: str, seq: int, config: str) -> str:
    """Confirmed digest of a package: SHA-256 over the signed canonical message."""
    return hashlib.sha256(canonical_message(group_id, prev_digest, seq, config)).hexdigest()


def _compressed_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )


def key_fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """Stable reviewer key id: SHA-256 of the compressed SEC1 encoding."""
    return hashlib.sha256(_compressed_bytes(public_key)).hexdigest()


def load_public_key(text: str) -> ec.EllipticCurvePublicKey:
    """Parse a P-256 public key from SEC1 hex (compressed/uncompressed) or PEM.

    Anything not on curve P-256 (secp256r1) is rejected.
    """
    text = text.strip()
    key = None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raw = None
    if raw is not None:
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except ValueError as exc:
            raise CryptoError(f"invalid P-256 point encoding: {exc}") from exc
    else:
        try:
            key = serialization.load_pem_public_key(text.encode("utf-8"))
        except ValueError as exc:
            raise CryptoError("public key must be SEC1 hex or PEM") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise CryptoError("public key is not on curve P-256 (secp256r1)")
    return key


def public_key_hex(public_key: ec.EllipticCurvePublicKey) -> str:
    """Canonical compressed-SEC1 hex encoding of a public key."""
    return _compressed_bytes(public_key).hex()


def _der_from_any(sig: bytes) -> bytes:
    """Normalise a signature to DER, accepting DER or raw r||s (64 bytes)."""
    try:
        decode_dss_signature(sig)
        return sig
    except ValueError:
        pass
    if len(sig) == _RAW_SIG_LEN:
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        return encode_dss_signature(r, s)
    raise CryptoError("signature must be DER or raw r||s (64 bytes)")


def verify_signature(
    public_key: ec.EllipticCurvePublicKey, signature_hex: str, message: bytes
) -> bool:
    """True iff signature_hex is a valid ECDSA/P-256/SHA-256 signature on message."""
    try:
        sig = _der_from_any(bytes.fromhex(signature_hex))
    except (ValueError, CryptoError):
        return False
    try:
        public_key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
