"""Acceptance tests for the threshold-sealed config package service."""
from __future__ import annotations

import json
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


def test_sequential_competing_first_packages(store, group):
    """A consumed predecessor cannot be extended a second time.

    Two fully valid packages (different op_id, different config, own
    sufficient signatures) compete for genesis/seq=1 and arrive in strict
    sequence: exactly one confirms; the other gets 409 stale_predecessor
    and writes neither a package nor a receipt, and the head is unmoved.
    """
    gid, keys = group
    status, p1 = _submit(store, gid, keys, "op-A", GENESIS, 1, "config-A")
    assert status == 201

    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-B", GENESIS, 1, "config-B")
    assert _err(e) == (409, "stale_predecessor")

    assert service.get_group(store, gid)[1]["head"] == {
        "seq": 1, "digest": p1["digest"],
    }
    listing = service.list_packages(store, gid)[1]["packages"]
    assert [(p["seq"], p["op_id"], p["digest"]) for p in listing] == [
        (1, "op-A", p1["digest"]),
    ]
    # the loser left no receipt: reusing its op_id against the real head is
    # a fresh confirmation, not an op_id conflict or replay
    status, p2 = _submit(store, gid, keys, "op-B", p1["digest"], 2, "config-B")
    assert status == 201 and p2["seq"] == 2 and p2["replay"] is False
    assert service.get_group(store, gid)[1]["head"] == {
        "seq": 2, "digest": p2["digest"],
    }


def test_rejected_competitor_survives_restart(tmp_path, store, group):
    """After a rejected fork and a restart the unique chain is unchanged."""
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "a")
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-2", GENESIS, 1, "fork")
    assert _err(e) == (409, "stale_predecessor")
    _, p2 = _submit(store, gid, keys, "op-3", p1["digest"], 2, "b")
    store.close()

    reopened = Store(str(tmp_path / "seal.db"))
    try:
        _, info = service.get_group(reopened, gid)
        assert info["head"] == {"seq": 2, "digest": p2["digest"]}
        chain = service.list_packages(reopened, gid)[1]["packages"]
        assert [p["seq"] for p in chain] == [1, 2]
        assert chain[1]["prev_digest"] == p1["digest"]
        # the recovered head is exactly once-extendable; a replayed old
        # predecessor stays rejected after restart
        with pytest.raises(ApiError) as e:
            _submit(reopened, gid, keys, "op-old", GENESIS, 1, "old")
        assert _err(e) == (409, "stale_predecessor")
        status, p3 = _submit(reopened, gid, keys, "op-4", p2["digest"], 3, "c")
        assert status == 201 and p3["seq"] == 3
    finally:
        reopened.close()


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


def test_concurrent_fork_after_head_and_latecomer(store, group):
    """The same predecessor cannot be raced twice: concurrent + sequential.

    8 packages race for seq=2 off the confirmed seq=1 head: exactly one
    wins, all others are stale and write nothing; a ninth valid package
    aimed at the same consumed predecessor arriving strictly afterwards
    loses as well, while a proper continuation off the new head succeeds.
    """
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "cfg-0")

    results, errors = [], []

    def attempt(i):
        try:
            results.append(_submit(store, gid, keys, f"op-race-{i}",
                                   p1["digest"], 2, f"cfg-{i}"))
        except ApiError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1
    assert len(errors) == 7 and all(e.code == "stale_predecessor" for e in errors)
    winner = results[0][1]

    # strictly-late competitor for the same (already consumed) predecessor
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-late", p1["digest"], 2, "cfg-late")
    assert _err(e) == (409, "stale_predecessor")

    assert service.get_group(store, gid)[1]["head"] == {
        "seq": 2, "digest": winner["digest"],
    }
    chain = service.list_packages(store, gid)[1]["packages"]
    assert [p["seq"] for p in chain] == [1, 2]
    assert chain[1]["prev_digest"] == p1["digest"]
    assert chain[1]["digest"] == winner["digest"]

    # only the two winners carry receipts; losers' op_ids were not consumed
    status, p3 = _submit(store, gid, keys, "op-late", winner["digest"], 3, "cfg-next")
    assert status == 201 and p3["seq"] == 3
    assert service.get_group(store, gid)[1]["head"] == {
        "seq": 3, "digest": p3["digest"],
    }


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
