"""Acceptance tests for the threshold-sealed config package service."""
from __future__ import annotations

import json
import sqlite3
import threading
import urllib.error
import urllib.request

import pytest

from app import crypto, service
from app.server import build_server
from app.service import ApiError
from app.store import Store

from .helpers import generate_keys, sign, signature_entry

GENESIS = crypto.GENESIS_DIGEST


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "seal.db"))
    yield s
    s.close()


@pytest.fixture()
def group(store):
    """A 2-of-3 seal group; returns (group_id, keys)."""
    keys = generate_keys(3)
    status, body = service.create_group(store, {
        "group_id": "run-2026-09",
        "threshold": 2,
        "public_keys": [k[2] for k in keys],
    })
    assert status == 201
    assert body["head"] == {"seq": 0, "digest": GENESIS}
    return "run-2026-09", keys


def _submit(store, gid, keys, op_id, prev, seq, config, signers=(0, 1)):
    sigs = [signature_entry(keys[i][0], keys[i][1], gid, prev, seq, config) for i in signers]
    return service.submit_package(store, gid, {
        "op_id": op_id, "prev_digest": prev, "seq": seq,
        "config": config, "signatures": sigs,
    })


def _err(excinfo):
    return excinfo.value.status, excinfo.value.code


# --------------------------------------------------------------------------
# group registration
# --------------------------------------------------------------------------

def test_create_group_rejects_bad_key_counts(store):
    keys = generate_keys(2)
    for pubs in ([keys[0][2]], [k[2] for k in generate_keys(9)]):
        with pytest.raises(ApiError) as e:
            service.create_group(store, {"group_id": "g", "threshold": 1, "public_keys": pubs})
        assert _err(e) == (400, "bad_key_count")


def test_create_group_rejects_duplicate_and_nonunique_keys(store):
    keys = generate_keys(2)
    with pytest.raises(ApiError) as e:
        service.create_group(store, {
            "group_id": "g", "threshold": 1,
            "public_keys": [keys[0][2], keys[0][2]],
        })
    assert _err(e) == (400, "duplicate_key")


def test_create_group_rejects_bad_threshold_and_bad_key(store):
    keys = generate_keys(2)
    with pytest.raises(ApiError) as e:
        service.create_group(store, {
            "group_id": "g", "threshold": 3, "public_keys": [k[2] for k in keys],
        })
    assert _err(e) == (400, "bad_threshold")
    with pytest.raises(ApiError) as e:
        service.create_group(store, {
            "group_id": "g", "threshold": 1, "public_keys": [keys[0][2], "not-a-key"],
        })
    assert _err(e) == (400, "bad_key")


def test_create_group_is_not_idempotent_overwrite(store):
    keys = generate_keys(2)
    body = {"group_id": "g", "threshold": 2, "public_keys": [k[2] for k in keys]}
    assert service.create_group(store, body)[0] == 201
    with pytest.raises(ApiError) as e:
        service.create_group(store, body)
    assert _err(e) == (409, "group_exists")


# --------------------------------------------------------------------------
# happy path: first package, continuation, digest/seq/unique head
# --------------------------------------------------------------------------

def test_first_and_continuation_packages(store, group):
    gid, keys = group

    status, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "field=1500V")
    assert status == 201
    assert p1["seq"] == 1
    assert p1["digest"] == crypto.package_digest(gid, GENESIS, 1, "field=1500V")
    assert p1["replay"] is False

    status, p2 = _submit(store, gid, keys, "op-2", p1["digest"], 2, "field=1600V")
    assert status == 201
    assert p2["seq"] == 2
    assert p2["digest"] == crypto.package_digest(gid, p1["digest"], 2, "field=1600V")
    assert p2["prev_digest"] == p1["digest"]

    # unique chain head is the second package
    _, info = service.get_group(store, gid)
    assert info["head"] == {"seq": 2, "digest": p2["digest"]}

    # full chain is linear and recoverable
    _, listing = service.list_packages(store, gid)
    chain = listing["packages"]
    assert [p["seq"] for p in chain] == [1, 2]
    assert chain[0]["prev_digest"] == GENESIS
    assert chain[1]["prev_digest"] == chain[0]["digest"]


def test_restart_recovers_unique_chain_head(tmp_path, group):
    db = str(tmp_path / "seal.db")
    s1 = Store(db)
    keys = generate_keys(3)
    service.create_group(s1, {"group_id": "g", "threshold": 2,
                              "public_keys": [k[2] for k in keys]})
    _, p1 = _submit(s1, "g", keys, "op-1", GENESIS, 1, "a")
    _, p2 = _submit(s1, "g", keys, "op-2", p1["digest"], 2, "b")
    s1.close()

    # restart: head must be recovered from confirmed packages alone
    s2 = Store(db)
    try:
        _, info = service.get_group(s2, "g")
        assert info["head"] == {"seq": 2, "digest": p2["digest"]}
        # and the chain can be extended exactly once from the recovered head
        status, p3 = _submit(s2, "g", keys, "op-3", p2["digest"], 3, "c")
        assert status == 201 and p3["seq"] == 3
    finally:
        s2.close()


def test_restart_after_rejected_forks_keeps_unique_head(tmp_path):
    """Rejected fork attempts must not leak into the recovered state: after a
    restart the unique head, the linear package list and the continuation
    eligibility are exactly what the confirmed history dictates."""
    db = str(tmp_path / "seal.db")
    keys = generate_keys(3)
    s1 = Store(db)
    service.create_group(s1, {"group_id": "g", "threshold": 2,
                              "public_keys": [k[2] for k in keys]})
    _, p1 = _submit(s1, "g", keys, "op-1", GENESIS, 1, "a")
    _, p2 = _submit(s1, "g", keys, "op-2", p1["digest"], 2, "b")
    # sequential fork attempts against consumed predecessors: both rejected
    for i, (prev, seq) in enumerate(((GENESIS, 1), (p1["digest"], 2))):
        with pytest.raises(ApiError) as e:
            _submit(s1, "g", keys, f"op-fork-{i}", prev, seq, f"fork-{i}")
        assert _err(e) == (409, "stale_predecessor")
    s1.close()

    s2 = Store(db)
    try:
        _, info = service.get_group(s2, "g")
        assert info["head"] == {"seq": 2, "digest": p2["digest"]}
        _, listing = service.list_packages(s2, "g")
        assert [p["seq"] for p in listing["packages"]] == [1, 2]
        # consumed predecessors stay consumed across the restart
        with pytest.raises(ApiError) as e:
            _submit(s2, "g", keys, "op-3", GENESIS, 1, "late-fork")
        assert _err(e) == (409, "stale_predecessor")
        # and the unique head still extends normally
        status, p3 = _submit(s2, "g", keys, "op-3", p2["digest"], 3, "c")
        assert status == 201 and p3["seq"] == 3
    finally:
        s2.close()


def test_legacy_forked_database_is_pruned_to_unique_chain(tmp_path):
    """Databases written before the UNIQUE(group_id, seq) backstop may hold
    bug-confirmed forks (same seq, different digest). Opening them must
    reduce every group to the single canonical chain walked from genesis,
    drop the forked rows and their receipts, and add the backstop."""
    db = str(tmp_path / "legacy.db")
    gid = "legacy-g"
    keys = generate_keys(3)
    d1 = crypto.package_digest(gid, GENESIS, 1, "a")
    d1_fork = crypto.package_digest(gid, GENESIS, 1, "b")
    d2 = crypto.package_digest(gid, d1, 2, "c")

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE groups (group_id TEXT PRIMARY KEY, threshold INTEGER NOT NULL,
                             created_at TEXT NOT NULL);
        CREATE TABLE group_keys (group_id TEXT NOT NULL, key_id TEXT NOT NULL,
                                 pubkey_hex TEXT NOT NULL,
                                 PRIMARY KEY (group_id, key_id));
        CREATE TABLE packages (
            group_id TEXT NOT NULL, seq INTEGER NOT NULL, digest TEXT NOT NULL,
            prev_digest TEXT NOT NULL, op_id TEXT NOT NULL, config TEXT NOT NULL,
            signers TEXT NOT NULL, created_at TEXT NOT NULL,
            PRIMARY KEY (group_id, seq, digest), UNIQUE (group_id, digest));
        CREATE TABLE receipts (group_id TEXT NOT NULL, op_id TEXT NOT NULL,
                               request_hash TEXT NOT NULL, response_json TEXT NOT NULL,
                               created_at TEXT NOT NULL, PRIMARY KEY (group_id, op_id));
        CREATE TABLE heads (group_id TEXT PRIMARY KEY, head_seq INTEGER NOT NULL,
                            head_digest TEXT NOT NULL);
    """)
    conn.execute("INSERT INTO groups VALUES (?,?,?)", (gid, 2, "now"))
    conn.executemany(
        "INSERT INTO group_keys VALUES (?,?,?)",
        [(gid, k[1], k[2]) for k in keys],
    )
    conn.executemany(
        "INSERT INTO packages VALUES (?,?,?,?,?,?,?,?)",
        [
            (gid, 1, d1, GENESIS, "op-1", "a", "[]", "now"),
            (gid, 1, d1_fork, GENESIS, "op-fork", "b", "[]", "now"),  # bug-confirmed
            (gid, 2, d2, d1, "op-2", "c", "[]", "now"),
        ],
    )
    conn.executemany(
        "INSERT INTO receipts VALUES (?,?,?,?,?)",
        [(gid, op, "h", "{}", "now") for op in ("op-1", "op-fork", "op-2")],
    )
    # stale side state pointing at the fork, as the buggy version left it
    conn.execute("INSERT INTO heads VALUES (?,?,?)", (gid, 1, d1_fork))
    conn.commit()
    conn.close()

    store = Store(db)
    try:
        # the fork is pruned: unique linear chain and head derived from genesis
        _, listing = service.list_packages(store, gid)
        assert [(p["seq"], p["digest"]) for p in listing["packages"]] == [(1, d1), (2, d2)]
        assert service.get_group(store, gid)[1]["head"] == {"seq": 2, "digest": d2}
        # the pruned fork left no receipt behind: its op_id is free again and
        # the recovered chain extends normally
        status, p3 = _submit(store, gid, keys, "op-fork", d2, 3, "d")
        assert status == 201 and p3["seq"] == 3
    finally:
        store.close()

    # the unique-seq backstop index now exists in the migrated database
    conn = sqlite3.connect(db)
    try:
        found = False
        for row in conn.execute("PRAGMA index_list(packages)"):
            if not row[2]:  # not unique
                continue
            cols = [r[2] for r in conn.execute(f'PRAGMA index_info("{row[1]}")')]
            if cols == ["group_id", "seq"]:
                found = True
        assert found, "UNIQUE(group_id, seq) backstop missing after migration"
    finally:
        conn.close()


# --------------------------------------------------------------------------
# rejections that must not change history
# --------------------------------------------------------------------------

def test_tampered_signature_rejected(store, group):
    gid, keys = group
    good = signature_entry(keys[0][0], keys[0][1], gid, GENESIS, 1, "cfg")
    evil = signature_entry(keys[1][0], keys[1][1], gid, GENESIS, 1, "cfg")
    evil["signature"] = evil["signature"][:-2] + ("00" if not evil["signature"].endswith("00") else "01")
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": [good, evil],
        })
    assert _err(e) == (422, "invalid_signature")
    assert service.get_group(store, gid)[1]["head"]["seq"] == 0


def test_signature_over_wrong_fields_rejected(store, group):
    gid, keys = group
    # signature made for seq=2 is presented for seq=1
    sigs = [signature_entry(keys[i][0], keys[i][1], gid, GENESIS, 2, "cfg") for i in (0, 1)]
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": sigs,
        })
    assert _err(e) == (422, "invalid_signature")


def test_duplicate_signer_rejected(store, group):
    gid, keys = group
    sig = signature_entry(keys[0][0], keys[0][1], gid, GENESIS, 1, "cfg")
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": [sig, sig],
        })
    assert _err(e) == (422, "duplicate_signer")
    assert service.get_group(store, gid)[1]["head"]["seq"] == 0


def test_insufficient_threshold_rejected(store, group):
    gid, keys = group
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-x", GENESIS, 1, "cfg", signers=(0,))
    assert _err(e) == (422, "insufficient_threshold")
    assert service.get_group(store, gid)[1]["head"]["seq"] == 0


def test_unknown_signer_rejected(store, group):
    gid, keys = group
    stranger = generate_keys(1)[0]
    sigs = [signature_entry(keys[0][0], keys[0][1], gid, GENESIS, 1, "cfg"),
            signature_entry(stranger[0], stranger[1], gid, GENESIS, 1, "cfg")]
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": sigs,
        })
    assert _err(e) == (422, "unknown_signer")


def test_stale_predecessor_rejected(store, group):
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "a")
    # replaying an already-consumed predecessor must fail and change nothing
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-2", GENESIS, 1, "b")
    assert _err(e) == (409, "stale_predecessor")
    # skipping ahead must fail too
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-3", p1["digest"], 3, "b")
    assert _err(e) == (409, "stale_predecessor")
    assert service.get_group(store, gid)[1]["head"] == {"seq": 1, "digest": p1["digest"]}


# --------------------------------------------------------------------------
# consumed predecessors can never be extended again (sequential forks)
# --------------------------------------------------------------------------

def test_consumed_genesis_predecessor_cannot_extend_again(store, group):
    """The reported fork: after the first package is confirmed, a second
    package — different op_id, different config, fully valid threshold
    signatures — still points at the genesis digest with seq 1."""
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "field=1500V")

    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-2", GENESIS, 1, "field=9999V")
    assert _err(e) == (409, "stale_predecessor")

    # history holds exactly one seq=1 record; the head is still unique
    _, listing = service.list_packages(store, gid)
    assert [(p["seq"], p["digest"]) for p in listing["packages"]] == [(1, p1["digest"])]
    assert service.get_group(store, gid)[1]["head"] == {"seq": 1, "digest": p1["digest"]}

    # the rejected attempt consumed neither the predecessor nor the op_id:
    # op-2 can be reused for the proper continuation of the chain
    status, p2 = _submit(store, gid, keys, "op-2", p1["digest"], 2, "field=1600V")
    assert status == 201 and p2["seq"] == 2


def test_consumed_midchain_predecessor_cannot_extend_again(store, group):
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "a")
    _, p2 = _submit(store, gid, keys, "op-2", p1["digest"], 2, "b")

    # p1's digest still exists in history but is no longer the head
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-3", p1["digest"], 2, "fork")
    assert _err(e) == (409, "stale_predecessor")

    _, listing = service.list_packages(store, gid)
    assert [p["seq"] for p in listing["packages"]] == [1, 2]
    assert service.get_group(store, gid)[1]["head"] == {"seq": 2, "digest": p2["digest"]}


# --------------------------------------------------------------------------
# idempotency
# --------------------------------------------------------------------------

def test_idempotent_retransmission(store, group):
    gid, keys = group
    body = {
        "op_id": "op-1", "prev_digest": GENESIS, "seq": 1, "config": "cfg",
        "signatures": [signature_entry(keys[i][0], keys[i][1], gid, GENESIS, 1, "cfg")
                       for i in (0, 1)],
    }
    status1, first = service.submit_package(store, gid, body)
    status2, second = service.submit_package(store, gid, json.loads(json.dumps(body)))
    assert status1 == 201 and status2 == 200
    assert second["replay"] is True
    assert second["digest"] == first["digest"] and second["seq"] == first["seq"]
    # history holds exactly one package
    assert len(service.list_packages(store, gid)[1]["packages"]) == 1


def test_op_id_conflict_rejected(store, group):
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "a")
    # same op_id, different payload -> hard conflict, no new history
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-1", GENESIS, 1, "tampered")
    assert _err(e) == (409, "op_id_conflict")
    _, listing = service.list_packages(store, gid)
    assert len(listing["packages"]) == 1
    assert service.get_group(store, gid)[1]["head"]["digest"] == p1["digest"]


# --------------------------------------------------------------------------
# concurrency: competing forks on the same predecessor
# --------------------------------------------------------------------------

def test_concurrent_fork_exactly_one_winner(store, group):
    gid, keys = group
    results, errors = [], []

    def attempt(i):
        try:
            results.append(_submit(store, gid, keys, f"op-{i}", GENESIS, 1, f"cfg-{i}"))
        except ApiError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"expected exactly one winner, got {len(results)}"
    assert all(e.code == "stale_predecessor" for e in errors)
    assert len(errors) == 7
    winner = results[0][1]
    assert service.get_group(store, gid)[1]["head"] == {"seq": 1, "digest": winner["digest"]}
    assert len(service.list_packages(store, gid)[1]["packages"]) == 1


# --------------------------------------------------------------------------
# HTTP smoke test through the real socket server
# --------------------------------------------------------------------------

def test_http_end_to_end(tmp_path):
    httpd, store = build_server("127.0.0.1", 0, str(tmp_path / "http.db"))
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"

    def call(method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        status, health = call("GET", "/healthz")
        assert status == 200 and health["status"] == "ok"

        keys = generate_keys(3)
        status, created = call("POST", "/v1/groups", {
            "group_id": "http-g", "threshold": 2,
            "public_keys": [k[2] for k in keys],
        })
        assert status == 201

        body = {
            "op_id": "op-1", "prev_digest": GENESIS, "seq": 1, "config": "cfg",
            "signatures": [signature_entry(keys[i][0], keys[i][1], "http-g", GENESIS, 1, "cfg")
                           for i in (0, 1)],
        }
        status, pkg = call("POST", "/v1/groups/http-g/packages", body)
        assert status == 201 and pkg["seq"] == 1

        status, replay = call("POST", "/v1/groups/http-g/packages", body)
        assert status == 200 and replay["replay"] is True

        status, info = call("GET", "/v1/groups/http-g")
        assert status == 200 and info["head"]["digest"] == pkg["digest"]

        # correctly signed but does not extend the confirmed head -> 409
        stale = {
            "op_id": "op-2", "prev_digest": pkg["digest"], "seq": 5, "config": "cfg",
            "signatures": [signature_entry(keys[i][0], keys[i][1], "http-g",
                                           pkg["digest"], 5, "cfg") for i in (0, 1)],
        }
        status, err = call("POST", "/v1/groups/http-g/packages", stale)
        assert status == 409 and err["error"] == "stale_predecessor"
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()


def test_http_restart_recovers_unique_head(tmp_path):
    """Real HTTP against a server restarted on the same persisted database:
    the unique confirmed head, the linear package list and continuation
    eligibility must survive the restart unchanged."""
    db = str(tmp_path / "http-restart.db")

    def serve():
        httpd, store = build_server("127.0.0.1", 0, db)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, store, f"http://127.0.0.1:{httpd.server_address[1]}"

    def call(base, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def package(op_id, prev, seq, config):
        return {
            "op_id": op_id, "prev_digest": prev, "seq": seq, "config": config,
            "signatures": [signature_entry(keys[i][0], keys[i][1], "g", prev, seq, config)
                           for i in (0, 1)],
        }

    keys = generate_keys(3)
    httpd, store, base = serve()
    try:
        status, _ = call(base, "POST", "/v1/groups", {
            "group_id": "g", "threshold": 2, "public_keys": [k[2] for k in keys],
        })
        assert status == 201
        status, p1 = call(base, "POST", "/v1/groups/g/packages",
                          package("op-1", GENESIS, 1, "cfg"))
        assert status == 201
        # sequential fork attempt over HTTP: consumed genesis predecessor,
        # different op_id/config, fully valid signatures -> 409, no history
        status, err = call(base, "POST", "/v1/groups/g/packages",
                           package("op-2", GENESIS, 1, "fork"))
        assert status == 409 and err["error"] == "stale_predecessor"
        status, listing = call(base, "GET", "/v1/groups/g/packages")
        assert [p["seq"] for p in listing["packages"]] == [1]
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()

    # restart on the same persisted data
    httpd, store, base = serve()
    try:
        status, info = call(base, "GET", "/v1/groups/g")
        assert status == 200 and info["head"] == {"seq": 1, "digest": p1["digest"]}
        status, listing = call(base, "GET", "/v1/groups/g/packages")
        assert [(p["seq"], p["digest"]) for p in listing["packages"]] == [(1, p1["digest"])]
        # the consumed predecessor is still refused after the restart
        status, err = call(base, "POST", "/v1/groups/g/packages",
                           package("op-3", GENESIS, 1, "late-fork"))
        assert status == 409 and err["error"] == "stale_predecessor"
        # and the unique head extends normally
        status, p2 = call(base, "POST", "/v1/groups/g/packages",
                          package("op-3", p1["digest"], 2, "cfg2"))
        assert status == 201 and p2["seq"] == 2
        status, info = call(base, "GET", "/v1/groups/g")
        assert info["head"] == {"seq": 2, "digest": p2["digest"]}
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()
