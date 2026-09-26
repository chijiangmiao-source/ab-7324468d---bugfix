"""Business logic: request validation and orchestration.

Validation is layered so that nothing that must not change history ever
touches the database transaction:

1. stateless checks (shape, key parsing, duplicate/unknown signers,
   threshold count, ECDSA verification) — failures reject with no writes;
2. one atomic store transaction (idempotent receipt, head check, package
   + receipt insert, head move) — conflicts reject with a rollback.
"""
from __future__ import annotations

import hashlib
import json

from . import crypto
from .store import OpIdConflict, RaceLost, StalePredecessor, Store

MIN_KEYS = 2
MAX_KEYS = 8
MAX_GROUP_ID_BYTES = 128
MAX_OP_ID_CHARS = 128
MAX_CONFIG_BYTES = 1 << 20  # 1 MiB


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


def _request_hash(body: dict) -> str:
    """Stable hash of the exact logical payload, for idempotency comparison."""
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _require_str(body: dict, field: str, *, max_chars: int, max_bytes: int) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ApiError(400, f"bad_{field}", f"{field} must be a non-empty string")
    if len(value) > max_chars or len(value.encode("utf-8")) > max_bytes:
        raise ApiError(400, f"bad_{field}", f"{field} is too long")
    return value


def _require_int(body: dict, field: str, *, minimum: int) -> int:
    value = body.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ApiError(400, f"bad_{field}", f"{field} must be an integer >= {minimum}")
    return value


def create_group(store: Store, body: dict) -> tuple[int, dict]:
    if not isinstance(body, dict):
        raise ApiError(400, "bad_request", "JSON object expected")
    group_id = _require_str(
        body, "group_id", max_chars=MAX_GROUP_ID_BYTES, max_bytes=MAX_GROUP_ID_BYTES
    )
    threshold = _require_int(body, "threshold", minimum=1)
    keys_in = body.get("public_keys")
    if not isinstance(keys_in, list):
        raise ApiError(400, "bad_public_keys", "public_keys must be a list of strings")
    if not MIN_KEYS <= len(keys_in) <= MAX_KEYS:
        raise ApiError(
            400, "bad_key_count",
            f"need {MIN_KEYS}..{MAX_KEYS} unique public keys, got {len(keys_in)}",
        )
    if threshold > len(keys_in):
        raise ApiError(400, "bad_threshold", "threshold must be <= number of public keys")

    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in keys_in:
        if not isinstance(item, str):
            raise ApiError(400, "bad_key", "each public key must be SEC1 hex or PEM")
        try:
            pubkey = crypto.load_public_key(item)
        except crypto.CryptoError as exc:
            raise ApiError(400, "bad_key", str(exc)) from exc
        fingerprint = crypto.key_fingerprint(pubkey)
        if fingerprint in seen:
            raise ApiError(400, "duplicate_key", "public keys must be unique")
        seen.add(fingerprint)
        parsed.append((fingerprint, crypto.public_key_hex(pubkey)))

    if not store.create_group(group_id, threshold, parsed):
        raise ApiError(409, "group_exists", f"group {group_id!r} is already registered")
    return 201, {
        "group_id": group_id,
        "threshold": threshold,
        "key_ids": [fp for fp, _ in parsed],
        "head": {"seq": 0, "digest": crypto.GENESIS_DIGEST},
    }


def get_group(store: Store, group_id: str) -> tuple[int, dict]:
    group = store.get_group(group_id)
    if group is None:
        raise ApiError(404, "unknown_group", f"no seal group {group_id!r}")
    seq, digest = store.get_head(group_id)
    return 200, {
        "group_id": group_id,
        "threshold": group["threshold"],
        "key_ids": sorted(group["keys"]),
        "head": {"seq": seq, "digest": digest},
    }


def list_packages(store: Store, group_id: str) -> tuple[int, dict]:
    if store.get_group(group_id) is None:
        raise ApiError(404, "unknown_group", f"no seal group {group_id!r}")
    return 200, {"group_id": group_id, "packages": store.list_packages(group_id)}


def submit_package(store: Store, group_id: str, body: dict) -> tuple[int, dict]:
    group = store.get_group(group_id)
    if group is None:
        raise ApiError(404, "unknown_group", f"no seal group {group_id!r}")
    if not isinstance(body, dict):
        raise ApiError(400, "bad_request", "JSON object expected")

    op_id = _require_str(body, "op_id", max_chars=MAX_OP_ID_CHARS, max_bytes=MAX_OP_ID_CHARS)
    prev_digest = _require_str(body, "prev_digest", max_chars=64, max_bytes=64).lower()
    seq = _require_int(body, "seq", minimum=1)
    config = _require_str(body, "config", max_chars=MAX_CONFIG_BYTES, max_bytes=MAX_CONFIG_BYTES)
    sigs_in = body.get("signatures")
    if not isinstance(sigs_in, list) or not sigs_in:
        raise ApiError(400, "bad_signatures", "signatures must be a non-empty list")

    # -- stateless signer/signature validation (no history touched) ---------
    seen: set[str] = set()
    parsed: list[tuple[str, str]] = []
    for entry in sigs_in:
        if not isinstance(entry, dict):
            raise ApiError(400, "bad_signatures", "each signature must be an object")
        key_id = entry.get("key_id")
        signature = entry.get("signature")
        if not isinstance(key_id, str) or not isinstance(signature, str):
            raise ApiError(400, "bad_signatures", "key_id and signature must be strings")
        if key_id in seen:
            raise ApiError(422, "duplicate_signer", f"key {key_id} signed more than once")
        seen.add(key_id)
        if key_id not in group["keys"]:
            raise ApiError(422, "unknown_signer", f"key {key_id} is not registered")
        parsed.append((key_id, signature))

    threshold = group["threshold"]
    if len(parsed) < threshold:
        raise ApiError(
            422, "insufficient_threshold",
            f"{len(parsed)} unique signer(s) but threshold is {threshold}",
        )

    try:
        message = crypto.canonical_message(group_id, prev_digest, seq, config)
    except crypto.CryptoError as exc:
        raise ApiError(400, "bad_request", str(exc)) from exc

    for key_id, signature in parsed:
        pubkey = crypto.load_public_key(group["keys"][key_id])
        if not crypto.verify_signature(pubkey, signature, message):
            raise ApiError(
                422, "invalid_signature",
                f"signature from key {key_id} does not verify",
            )

    digest = hashlib.sha256(message).hexdigest()
    response = {
        "group_id": group_id,
        "seq": seq,
        "digest": digest,
        "prev_digest": prev_digest,
        "op_id": op_id,
        "signers": len(parsed),
        "replay": False,
    }

    # -- single atomic commit: receipt, head check, package, head move ------
    try:
        stored, replayed = store.submit_package(
            group_id=group_id,
            op_id=op_id,
            prev_digest=prev_digest,
            seq=seq,
            config=config,
            digest=digest,
            signer_ids=[kid for kid, _ in parsed],
            request_hash=_request_hash(body),
            response=response,
        )
    except OpIdConflict as exc:
        raise ApiError(
            409, "op_id_conflict",
            f"op_id {op_id!r} was already confirmed with a different payload",
        ) from exc
    except (StalePredecessor, RaceLost) as exc:
        raise ApiError(
            409, "stale_predecessor",
            "prev_digest/seq do not extend the currently confirmed head",
        ) from exc

    if replayed:
        stored = dict(stored, replay=True)
        return 200, stored
    return 201, stored
