#!/usr/bin/env python3
"""Acceptance verifier for the ``verify`` compose service.

Phase A runs the code-level pytest suite in a clean build. Every later
phase runs over real HTTP against a running seal server:

  0. waits for /healthz, builds + API smoke (group create, get)
  1. threshold shortfall is rejected (422) and leaves history untouched
  2. valid first package: digest/seq/unique head are exactly as expected
  3. idempotent retransmission replays the same receipt, creates no history
  4. same op_id with a changed payload conflicts (409)
  5. a second, independently signed package competing for the same
     predecessor in strict sequence is rejected (409 stale_predecessor)
  6. concurrent submissions racing for the same predecessor: exactly one
     winner, all others 409; history is one linear list with one head
  7. the seal service is restarted reusing its persisted database; the
     unique chain head and package list recover identically and the chain
     can be extended normally (and an old predecessor stays rejected)

Exits 0 only if every phase passes; any failure exits 1.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# Allow `python scripts/verify.py` from any CWD (image WORKDIR is the project root).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import crypto, service  # noqa: E402
from app.store import Store  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

HOST = os.environ.get("SEAL_TARGET_HOST", "seal")
PORT = int(os.environ.get("SEAL_TARGET_PORT", "8080"))
BASE = f"http://{HOST}:{PORT}"
DB_PATH = os.environ.get("SEAL_DB", "/data/seal.db")
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")

_failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail else ""), flush=True)
    if not ok:
        _failures.append(name)
    return ok


def call(method: str, path: str, body=None, raw: bytes | None = None,
         base: str = BASE):
    if raw is None and body is not None:
        raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        base + path, data=raw, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_healthy(timeout: float = 30.0, base: str = BASE) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, payload = call("GET", "/healthz", base=base)
            if status == 200 and payload.get("status") == "ok":
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


# -- code-level test phase --------------------------------------------------

def run_code_tests() -> bool:
    """Phase A: execute the repository pytest acceptance suite."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("-- Phase A: code-level pytest suite (tests/) --", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q"],
        cwd=repo,
    )
    return proc.returncode == 0


# -- Docker Engine socket helpers (restart service over persisted data) ------

class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, unix_path: str):
        super().__init__("docker")
        self._unix_path = unix_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(self._unix_path)
        self.sock = sock


def _docker_request(method: str, path: str, body: dict | None = None) -> tuple[int, bytes]:
    conn = _UnixHTTPConnection(DOCKER_SOCKET)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def start_recovery_container() -> tuple[str, str, str] | None:
    """Start a fresh seal container over the SAME persisted database.

    The recovery probe is a brand-new container from the same image, joined
    to the compose network and mounting the exact named volume the running
    service uses -- so it has none of the original process's memory and can
    only derive the chain head from durable records. Returns
    ``(base_url, container_id, volume_name)``; the original tracked service
    keeps running, which keeps ``docker compose up`` stable.
    """
    try:
        cid = socket.gethostname()
        status, raw = _docker_request("GET", f"/containers/{cid}/json")
        if status != 200:
            print(f"docker API: cannot inspect self ({status})", flush=True)
            return None
        self_info = json.loads(raw)
        project = self_info.get("Config", {}).get("Labels", {}).get(
            "com.docker.compose.project", "")
        if not project:
            print("docker API: running outside a compose project", flush=True)
            return None
        networks = list(self_info.get("NetworkSettings", {}).get("Networks", {}))
        if not networks:
            print("docker API: verifier is attached to no network", flush=True)
            return None
        network = networks[0]

        # locate the running seal service container and its data volume
        status, raw = _docker_request("GET", "/containers/json")
        if status != 200:
            print(f"docker API: cannot list containers ({status})", flush=True)
            return None
        volume = None
        image = self_info["Config"]["Image"]
        for c in json.loads(raw):
            labels = c.get("Labels", {})
            if (labels.get("com.docker.compose.project") == project
                    and labels.get("com.docker.compose.service") == "seal"):
                status, detail_raw = _docker_request("GET", f"/containers/{c['Id']}/json")
                if status != 200:
                    return None
                detail = json.loads(detail_raw)
                image = detail["Config"]["Image"]
                for mount in detail.get("Mounts", []):
                    if mount.get("Destination") == "/data" and mount.get("Type") == "volume":
                        volume = mount["Name"]
                break
        if volume is None:
            print("docker API: seal data volume not found", flush=True)
            return None

        name = f"{project}-seal-recovery-{os.getpid()}"
        config = {
            "Image": image,
            "Env": ["SEAL_HOST=0.0.0.0", "SEAL_PORT=8080", "SEAL_DB=/data/seal.db"],
            "ExposedPorts": {"8080/tcp": {}},
            "HostConfig": {"Binds": [f"{volume}:/data"]},
            "NetworkingConfig": {
                "EndpointsConfig": {network: {"Aliases": [name]}},
            },
        }
        status, raw = _docker_request("POST", "/containers/create"
                                              f"?name={name}", config)
        if status not in (201,):
            print(f"docker API: create failed ({status}) {raw[:200]!r}", flush=True)
            return None
        probe_id = json.loads(raw)["Id"]
        status, _ = _docker_request("POST", f"/containers/{probe_id}/start")
        if status not in (204,):
            print(f"docker API: start failed ({status})", flush=True)
            _docker_request("DELETE", f"/containers/{probe_id}?force=true")
            return None

        deadline = time.time() + 30.0
        while time.time() < deadline:
            status, raw = _docker_request("GET", f"/containers/{probe_id}/json")
            if status == 200:
                nets = json.loads(raw).get("NetworkSettings", {}).get("Networks", {})
                ip = nets.get(network, {}).get("IPAddress")
                if ip:
                    return f"http://{ip}:8080", probe_id, volume
            time.sleep(0.5)
        print("docker API: recovery container never got a network address", flush=True)
        _docker_request("DELETE", f"/containers/{probe_id}?force=true")
        return None
    except (OSError, socket.timeout, ValueError, KeyError) as exc:
        print(f"docker API error: {exc}", flush=True)
        return None


def remove_container(container_id: str) -> None:
    """Gracefully stop the recovery probe (checkpointing its SQLite WAL),
    then remove it."""
    try:
        _docker_request("POST", f"/containers/{container_id}/kill?signal=TERM")
        deadline = time.time() + 20.0
        while time.time() < deadline:
            status, raw = _docker_request("GET", f"/containers/{container_id}/json")
            if status == 200 and not json.loads(raw).get("State", {}).get("Running"):
                break
            time.sleep(0.5)
        _docker_request("DELETE", f"/containers/{container_id}?force=true")
    except OSError:
        pass


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

    # -- Phase A: code-level acceptance suite in the clean build ------------
    if not check("pytest suite (tests/)", run_code_tests()):
        return 1

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

    # -- 5. sequential competition for the same predecessor -----------------
    # The genesis predecessor was consumed by package 1. A second, fully
    # independent package (own op_id, own config, own valid signatures)
    # submitted strictly afterwards must be rejected, write nothing and
    # leave the sole head on package 1.
    fork = package_body(keys, gid, "op-seq-fork",
                        crypto.GENESIS_DIGEST, 1, "field=9001V", (2, 3))
    status, err = call("POST", f"/v1/groups/{gid}/packages", fork)
    check("sequential same-predecessor competitor rejected",
          status == 409 and err.get("error") == "stale_predecessor",
          f"status={status} err={err}")
    status, info = call("GET", f"/v1/groups/{gid}")
    check("head unchanged by rejected competitor",
          info["head"] == {"seq": 1, "digest": expected1}, f"head={info.get('head')}")
    status, listing = call("GET", f"/v1/groups/{gid}/packages")
    check("rejected competitor wrote no package/receipt",
          len(listing["packages"]) == 1 and listing["packages"][0]["op_id"] == "op-1",
          f"packages={[(p['seq'], p['op_id']) for p in listing['packages']]}")

    # -- 6. concurrent race for the same predecessor ------------------------
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

    # a loser's op_id must not have been consumed by a receipt; pick one of
    # the eight racing op_ids that does not belong to the sole winner
    winner_op = winners[0].get("op_id")
    loser_op = next(f"op-race-{i}" for i in range(8) if f"op-race-{i}" != winner_op)
    repeat_status, repeat = call(
        "POST", f"/v1/groups/{gid}/packages",
        package_body(keys, gid, loser_op, winner_digest, 3, "cfg-reuse", (0, 1)),
    )
    check("losing op_id was not consumed by a receipt",
          repeat_status == 201 and repeat["seq"] == 3,
          f"status={repeat_status} body={repeat}")
    if repeat_status != 201:
        return 1
    head_after_race = repeat["digest"]
    status, info = call("GET", f"/v1/groups/{gid}")
    check("linear head advanced to package 3",
          info["head"] == {"seq": 3, "digest": head_after_race},
          f"head={info.get('head')}")

    # -- 7. fresh service process over the SAME persisted database ----------
    # Start a brand-new container from the same image, attached to the same
    # network and mounting the identical named volume. It shares no process
    # state with the running service, so it can only recover the head from
    # durable records. All checks are real HTTP requests to that process.
    print("-- Phase 7: new service process recovering persisted data --", flush=True)
    recovery = start_recovery_container()
    if recovery is None:
        # No Docker API (e.g. running the verifier outside Compose during
        # local development): exercise the same restart-recovery semantics
        # by reopening the on-disk database with a fresh Store instance.
        # Under Compose the socket is mounted and the real-container path
        # above is taken instead.
        print("[SKIP] recovery container (Docker socket unavailable);"
              " verifying recovery in-process against the same DB file",
              flush=True)
        try:
            probe = Store(DB_PATH)
            try:
                _, rec = service.get_group(probe, gid)
                check("[fallback] recovered head from persisted records",
                      rec["head"] == {"seq": 3, "digest": head_after_race},
                      f"head={rec['head']}")
                _, chain = service.list_packages(probe, gid)
                check("[fallback] linear package list recovered",
                      [p["seq"] for p in chain["packages"]] == [1, 2, 3],
                      f"seqs={[p['seq'] for p in chain['packages']]}")
            finally:
                probe.close()
        except Exception as exc:  # noqa: BLE001 - verifier reports, never crashes
            check("[fallback] recovery from persisted records", False, str(exc))
    else:
        rbase, probe_id, volume = recovery
        try:
            healthy = check("recovery service healthy", wait_healthy(60.0, rbase))
            if healthy:
                status, info = call("GET", f"/v1/groups/{gid}", base=rbase)
                check("restart: unique head recovered identically",
                      status == 200
                      and info["head"] == {"seq": 3, "digest": head_after_race},
                      f"head={info.get('head')}")
                status, listing = call(
                    "GET", f"/v1/groups/{gid}/packages", base=rbase)
                seqs = [p["seq"] for p in listing["packages"]]
                check("restart: package list is the same linear chain",
                      status == 200 and seqs == [1, 2, 3]
                      and listing["packages"][-1]["digest"] == head_after_race,
                      f"seqs={seqs} volume={volume}")
                # a predecessor already consumed before restart stays rejected
                stale = package_body(keys, gid, "op-post-old",
                                     winner_digest, 3, "old", (0, 1))
                status, err = call(
                    "POST", f"/v1/groups/{gid}/packages", stale, base=rbase)
                check("restart: consumed predecessor still rejected",
                      status == 409 and err.get("error") == "stale_predecessor",
                      f"status={status} err={err}")
                # the recovered chain can be extended normally, exactly once
                cont = package_body(keys, gid, "op-post-4",
                                    head_after_race, 4, "field=1700V", (0, 1))
                status, p4 = call(
                    "POST", f"/v1/groups/{gid}/packages", cont, base=rbase)
                check("restart: normal continuation confirmed",
                      status == 201 and p4["seq"] == 4
                      and p4["prev_digest"] == head_after_race
                      and p4["digest"] == crypto.package_digest(
                          gid, head_after_race, 4, "field=1700V"),
                      f"status={status} p4={p4}")
                status, info = call("GET", f"/v1/groups/{gid}", base=rbase)
                check("restart: head is the new unique tip",
                      status == 200 and info["head"] == {"seq": 4, "digest": p4["digest"]},
                      f"head={info.get('head')}")
                # idempotent replay of the continuation across the restart
                status, replay4 = call(
                    "POST", f"/v1/groups/{gid}/packages",
                    raw=json.dumps(cont).encode("utf-8"), base=rbase)
                check("restart: continuation replays idempotently",
                      status == 200 and replay4.get("replay") is True
                      and replay4["digest"] == p4["digest"],
                      f"status={status} replay={replay4}")
        finally:
            remove_container(probe_id)

    print("-" * 60)
    if _failures:
        print(f"VERIFY FAILED ({len(_failures)} check(s)): {', '.join(_failures)}")
        return 1
    print("VERIFY PASSED: all threshold/idempotency/chain-head checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
