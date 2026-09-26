"""SQLite persistence for the threshold-sealed config chain.

All state-changing work for a submission happens inside ONE ``BEGIN
IMMEDIATE`` transaction: idempotency-receipt lookup, chain-head check,
package insert, receipt insert and head move. Competing writers are
serialised by the database write lock, so at most one request can ever
extend a given predecessor.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone

from .crypto import GENESIS_DIGEST

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    group_id   TEXT PRIMARY KEY,
    threshold  INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_keys (
    group_id   TEXT NOT NULL REFERENCES groups(group_id),
    key_id     TEXT NOT NULL,
    pubkey_hex TEXT NOT NULL,
    PRIMARY KEY (group_id, key_id)
);
CREATE TABLE IF NOT EXISTS packages (
    group_id    TEXT NOT NULL REFERENCES groups(group_id),
    seq         INTEGER NOT NULL,
    digest      TEXT NOT NULL,
    prev_digest TEXT NOT NULL,
    op_id       TEXT NOT NULL,
    config      TEXT NOT NULL,
    signers     TEXT NOT NULL,          -- JSON array of signer key ids
    created_at  TEXT NOT NULL,
    PRIMARY KEY (group_id, seq, digest),
    UNIQUE (group_id, digest),
    UNIQUE (group_id, seq)              -- backstop: one package per height
);
CREATE TABLE IF NOT EXISTS receipts (
    group_id      TEXT NOT NULL REFERENCES groups(group_id),
    op_id         TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (group_id, op_id)
);
CREATE TABLE IF NOT EXISTS heads (
    group_id    TEXT PRIMARY KEY REFERENCES groups(group_id),
    head_seq    INTEGER NOT NULL,
    head_digest TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class OpIdConflict(Exception):
    """The op_id was already confirmed with a different payload."""


class StalePredecessor(Exception):
    """prev_digest/seq do not extend the currently confirmed head."""


class RaceLost(Exception):
    """The head moved while this request was committing."""


class Store:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._rebuild_heads()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- schema migration ---------------------------------------------------
    def _migrate(self) -> None:
        """Bring databases written by older schemas up to date.

        The packages table must carry a UNIQUE(group_id, seq) backstop.
        Databases written before that constraint existed may hold forked
        rows (same seq, different digest) confirmed by the consumed-
        predecessor bug; reduce every group to its single canonical chain
        — walked from genesis, earliest confirmed link wins each step — so
        the linear head is again uniquely derivable, then add the index.
        """
        for row in self._conn.execute("PRAGMA index_list(packages)"):
            if not row["unique"]:
                continue
            cols = [
                r["name"]
                for r in self._conn.execute(f'PRAGMA index_info("{row["name"]}")')
            ]
            if cols == ["group_id", "seq"]:
                return  # backstop already in place
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            group_ids = [
                r["group_id"] for r in self._conn.execute("SELECT group_id FROM groups")
            ]
            for gid in group_ids:
                keep = [rowid for rowid, _, _ in self._canonical_chain(gid)]
                stale = self._conn.execute(
                    "SELECT rowid, op_id FROM packages WHERE group_id=?"
                    + (f" AND rowid NOT IN ({','.join('?' * len(keep))})" if keep else ""),
                    (gid, *keep),
                ).fetchall()
                if not stale:
                    continue
                log.warning(
                    "pruning %d forked package(s) from group %s;"
                    " keeping the unique canonical chain",
                    len(stale), gid,
                )
                self._conn.executemany(
                    "DELETE FROM receipts WHERE group_id=? AND op_id=?",
                    [(gid, r["op_id"]) for r in stale],
                )
                self._conn.executemany(
                    "DELETE FROM packages WHERE rowid=?",
                    [(r["rowid"],) for r in stale],
                )
            self._conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS packages_group_seq"
                " ON packages(group_id, seq)"
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def _canonical_chain(self, group_id: str) -> list[tuple[int, int, str]]:
        """(rowid, seq, digest) links of the unique chain from genesis.

        Each step follows the one package whose prev_digest matches the
        current link; if historical data ever held competitors for a step,
        the earliest confirmed (lowest rowid) wins, so the result is always
        deterministic and uniquely derivable from the durable records.
        """
        chain: list[tuple[int, int, str]] = []
        seq, digest = 0, GENESIS_DIGEST
        while True:
            row = self._conn.execute(
                "SELECT rowid, digest FROM packages"
                " WHERE group_id=? AND seq=? AND prev_digest=?"
                " ORDER BY rowid LIMIT 1",
                (group_id, seq + 1, digest),
            ).fetchone()
            if row is None:
                return chain
            seq += 1
            digest = row["digest"]
            chain.append((row["rowid"], seq, digest))

    # -- recovery ---------------------------------------------------------
    def _rebuild_heads(self) -> None:
        """Derive every group's unique chain head from confirmed packages.

        Runs on every startup: after a restart the chain head is recovered
        by walking the single linear chain from genesis through the durable
        package records, never from stale side state.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            group_ids = [
                r["group_id"] for r in self._conn.execute("SELECT group_id FROM groups")
            ]
            for gid in group_ids:
                chain = self._canonical_chain(gid)
                seq, digest = chain[-1][1:] if chain else (0, GENESIS_DIGEST)
                self._conn.execute(
                    "INSERT INTO heads (group_id, head_seq, head_digest) VALUES (?,?,?)"
                    " ON CONFLICT(group_id) DO UPDATE SET"
                    " head_seq=excluded.head_seq, head_digest=excluded.head_digest",
                    (gid, seq, digest),
                )
                if chain:
                    log.info(
                        "recovered chain head: group=%s seq=%d digest=%s…",
                        gid, seq, digest[:16],
                    )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    # -- groups -------------------------------------------------------------
    def create_group(self, group_id: str, threshold: int, keys: list[tuple[str, str]]) -> bool:
        """Register a seal group. Returns False if the group id already exists."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self._conn.execute(
                    "SELECT 1 FROM groups WHERE group_id=?", (group_id,)
                ).fetchone():
                    self._conn.execute("ROLLBACK")
                    return False
                self._conn.execute(
                    "INSERT INTO groups (group_id, threshold, created_at) VALUES (?,?,?)",
                    (group_id, threshold, _now()),
                )
                self._conn.executemany(
                    "INSERT INTO group_keys (group_id, key_id, pubkey_hex) VALUES (?,?,?)",
                    [(group_id, kid, hex_) for kid, hex_ in keys],
                )
                self._conn.execute(
                    "INSERT INTO heads (group_id, head_seq, head_digest) VALUES (?,?,?)",
                    (group_id, 0, GENESIS_DIGEST),
                )
                self._conn.execute("COMMIT")
                return True
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def get_group(self, group_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT group_id, threshold, created_at FROM groups WHERE group_id=?",
                (group_id,),
            ).fetchone()
            if row is None:
                return None
            keys = {
                r["key_id"]: r["pubkey_hex"]
                for r in self._conn.execute(
                    "SELECT key_id, pubkey_hex FROM group_keys WHERE group_id=?",
                    (group_id,),
                )
            }
            return {
                "group_id": row["group_id"],
                "threshold": row["threshold"],
                "created_at": row["created_at"],
                "keys": keys,
            }

    def get_head(self, group_id: str) -> tuple[int, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT head_seq, head_digest FROM heads WHERE group_id=?", (group_id,)
            ).fetchone()
            return (row["head_seq"], row["head_digest"]) if row else None

    def list_packages(self, group_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, digest, prev_digest, op_id, config, signers, created_at"
                " FROM packages WHERE group_id=? ORDER BY seq",
                (group_id,),
            ).fetchall()
            return [
                {
                    "seq": r["seq"],
                    "digest": r["digest"],
                    "prev_digest": r["prev_digest"],
                    "op_id": r["op_id"],
                    "config": r["config"],
                    "signers": json.loads(r["signers"]),
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    # -- package submission -------------------------------------------------
    def submit_package(
        self,
        *,
        group_id: str,
        op_id: str,
        prev_digest: str,
        seq: int,
        config: str,
        digest: str,
        signer_ids: list[str],
        request_hash: str,
        response: dict,
    ) -> tuple[dict, bool]:
        """Confirm a package atomically.

        Inside a single persistent transaction: honour a prior idempotent
        receipt, verify the current head, write the package, write the
        idempotency receipt and move the head. Returns (response, replayed).
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                outcome: tuple
                receipt = self._conn.execute(
                    "SELECT request_hash, response_json FROM receipts"
                    " WHERE group_id=? AND op_id=?",
                    (group_id, op_id),
                ).fetchone()
                if receipt is not None:
                    outcome = ("receipt", receipt)
                else:
                    # The predecessor must be the *current* confirmed head:
                    # a predecessor that was already consumed (genesis after
                    # the first package, or any older link) can never be
                    # extended again, so no fork is ever written.
                    head = self._conn.execute(
                        "SELECT head_seq, head_digest FROM heads WHERE group_id=?",
                        (group_id,),
                    ).fetchone()
                    if (
                        head is None
                        or head["head_digest"] != prev_digest
                        or seq != head["head_seq"] + 1
                    ):
                        outcome = ("stale",)
                    else:
                        self._conn.execute(
                            "INSERT INTO packages (group_id, seq, digest, prev_digest,"
                            " op_id, config, signers, created_at)"
                            " VALUES (?,?,?,?,?,?,?,?)",
                            (
                                group_id, seq, digest, prev_digest, op_id, config,
                                json.dumps(signer_ids), _now(),
                            ),
                        )
                        moved = self._conn.execute(
                            "UPDATE heads SET head_seq=?, head_digest=?"
                            " WHERE group_id=? AND head_seq=? AND head_digest=?",
                            (
                                seq, digest, group_id,
                                head["head_seq"], head["head_digest"],
                            ),
                        )
                        if moved.rowcount != 1:
                            raise RaceLost()
                        self._conn.execute(
                            "INSERT INTO receipts (group_id, op_id, request_hash,"
                            " response_json, created_at) VALUES (?,?,?,?,?)",
                            (group_id, op_id, request_hash, json.dumps(response), _now()),
                        )
                        outcome = ("ok",)
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise RaceLost() from exc
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

        if outcome[0] == "receipt":
            receipt = outcome[1]
            if receipt["request_hash"] != request_hash:
                raise OpIdConflict(op_id)
            return json.loads(receipt["response_json"]), True
        if outcome[0] == "stale":
            raise StalePredecessor()
        return response, False
