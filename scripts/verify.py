#!/usr/bin/env python3
"""Acceptance verifier for the ``verify`` compose service.

Runs entirely over HTTP against a running seal server:

  0. waits for /healthz, builds + API smoke (group create, get)
  1. threshold shortfall is rejected (422) and leaves history untouched
  2. valid first package: digest/seq/unique head are exactly as expected
  3. idempotent retransmission replays the same receipt, creates no history
  4. same op_id with a changed payload conflicts (409)
  5. concurrent submissions racing for the same predecessor: exactly one wins

Exits 0 only if every check passes.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

# Allow `python scripts/verify.py` from any CWD (image WORKDIR is the project root).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HOST = os.environ.get("SEAL_TARGET_HOST", "seal")
PORT = int(os.environ.get("SEAL_TARGET_PORT", "8080"))
BASE = f"http://{HOST}:{PORT}"

_failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail else ""), flush=True)
    if not ok:
        _failures.append(name)
    return ok


def call(method: str, path: str, body=None, raw: bytes | None = None):
    if raw is None and body is not None:
        raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        BASE + path, data=raw, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_healthy(timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, payload = call("GET", "/healthz")
            if status == 200 and payload.get("status") == "ok":
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def make_keys(n: int):
    out = []
    for _ in range(n):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        out.append((priv, crypto.key_fingerprint(pub), crypto.public_key_hex(pub)))
    return out


def sig(priv, gid, prev, seq, config) -> str:
    msg = crypto.canonical_message(gid, prev, seq, config)
    return priv.sign(msg, ec.ECDSA(hashes.SHA256())).hex()


def package_body(keys, gid, op_id, prev, seq, config, idxs):
    return {
        "op_id": op_id, "prev_digest": prev, "seq": seq, "config": config,
        "signatures": [
            {"key_id": keys[i][1], "signature": sig(keys[i][0], gid, prev, seq, config)}
            for i in idxs
        ],
    }


def main() -> int:
    print(f"== lxe config-seal verifier -> {BASE} ==", flush=True)

    if not check("server health check /healthz", wait_healthy()):
        return 1

    gid = f"verify-{int(time.time())}"
    keys = make_keys(4)

    # -- build/API smoke: register a 2-of-4 group ---------------------------
    status, group = call("POST", "/v1/groups", {
        "group_id": gid, "threshold": 2, "public_keys": [k[2] for k in keys],
    })
    check("create seal group (2-of-4)", status == 201, f"status={status} body={group}")
    status, info = call("GET", f"/v1/groups/{gid}")
    check("read group, genesis head", status == 200
          and info["head"] == {"seq": 0, "digest": crypto.GENESIS_DIGEST},
          f"status={status} head={info.get('head')}")

    # -- 1. threshold shortfall rejected, history unchanged -----------------
    thin = package_body(keys, gid, "op-thin", crypto.GENESIS_DIGEST, 1, "cfg-0", (0,))
    status, err = call("POST", f"/v1/groups/{gid}/packages", thin)
    check("threshold shortfall rejected", status == 422
          and err.get("error") == "insufficient_threshold",
          f"status={status} err={err}")

    # tampered signature also rejected (extra coverage)
    bad = package_body(keys, gid, "op-bad", crypto.GENESIS_DIGEST, 1, "cfg-0", (0, 1))
    bad["signatures"][1]["signature"] = bad["signatures"][1]["signature"][:-2] + "00"
    status, err = call("POST", f"/v1/groups/{gid}/packages", bad)
    check("tampered signature rejected", status == 422
          and err.get("error") == "invalid_signature", f"status={status} err={err}")

    # -- 2. valid first package ---------------------------------------------
    p1_body = package_body(keys, gid, "op-1", crypto.GENESIS_DIGEST, 1, "field=1500V", (0, 1))
    status, p1 = call("POST", f"/v1/groups/{gid}/packages", p1_body)
    expected1 = crypto.package_digest(gid, crypto.GENESIS_DIGEST, 1, "field=1500V")
    check("valid first package confirmed", status == 201 and p1["seq"] == 1
          and p1["digest"] == expected1, f"status={status} p1={p1}")
    status, info = call("GET", f"/v1/groups/{gid}")
    check("unique chain head == package 1",
          info["head"] == {"seq": 1, "digest": expected1}, f"head={info.get('head')}")

    # -- 3. idempotent retransmission ---------------------------------------
    raw = json.dumps(p1_body).encode("utf-8")
    status, replay = call("POST", f"/v1/groups/{gid}/packages", raw=raw)
    check("idempotent retransmission replays receipt",
          status == 200 and replay.get("replay") is True
          and replay["digest"] == expected1 and replay["seq"] == 1,
          f"status={status} replay={replay}")
    status, listing = call("GET", f"/v1/groups/{gid}/packages")
    check("retry wrote no extra history",
          len(listing["packages"]) == 1, f"n={len(listing['packages'])}")

    # -- 4. op_id reused with a different payload conflicts -----------------
    # Properly signed, well-formed, but the op_id is already confirmed for a
    # different payload -> hard 409, no new history.
    conflict = package_body(keys, gid, "op-1", crypto.GENESIS_DIGEST, 1, "field=9999V", (0, 1))
    status, err = call("POST", f"/v1/groups/{gid}/packages", conflict)
    check("same op_id different payload conflicts",
          status == 409 and err.get("error") == "op_id_conflict",
          f"status={status} err={err}")

    # -- 5. concurrent race for the same predecessor ------------------------
    race_results: list[tuple[int, dict]] = []
    lock = threading.Lock()

    def racer(i: int) -> None:
        body = package_body(keys, gid, f"op-race-{i}", expected1, 2, f"fork-{i}", (0, 1))
        st, payload = call("POST", f"/v1/groups/{gid}/packages", body)
        with lock:
            race_results.append((st, payload))

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [p for st, p in race_results if st == 201]
    losers = [(st, p) for st, p in race_results if st != 201]
    ok_race = (
        len(winners) == 1
        and all(st == 409 and p.get("error") == "stale_predecessor" for st, p in losers)
    )
    check("concurrent fork: exactly one winner, others stale",
          ok_race, f"winners={len(winners)} losers={[(st, p.get('error')) for st, p in losers]}")

    status, info = call("GET", f"/v1/groups/{gid}")
    winner_digest = winners[0]["digest"] if winners else None
    check("unique chain head after race",
          status == 200 and info["head"] == {"seq": 2, "digest": winner_digest},
          f"head={info.get('head')}")
    status, listing = call("GET", f"/v1/groups/{gid}/packages")
    check("history holds exactly two linear packages",
          [p["seq"] for p in listing["packages"]] == [1, 2]
          and listing["packages"][1]["prev_digest"] == expected1
          and listing["packages"][1]["digest"] == winner_digest,
          f"seqs={[p['seq'] for p in listing['packages']]}")

    print("-" * 60)
    if _failures:
        print(f"VERIFY FAILED ({len(_failures)} check(s)): {', '.join(_failures)}")
        return 1
    print("VERIFY PASSED: all threshold/idempotency/chain-head checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
