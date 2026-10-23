# Adapted from Hermes Realms 0.2.0 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Out-of-scope sentinel: stopping the scope also kills orphaned descendants."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .lifecycle import Registry, alive, atomic_json, stop_scope, remove_runtime, private_json


def cleanup(home, realm_id, generation=None):
    registry = Registry(home)
    with registry.lock():
        if not registry.path(realm_id).exists():
            return
        record = registry.get(realm_id)
        if generation is not None and record["generation"] != generation:
            return
        if record["status"] in ("stopped", "deleting"):
            return
        stop_scope(record)
        remove_runtime(registry, record)


def run(home, realm_id, generation=None):
    registry = Registry(home)
    with registry.lock():
        record = registry.get(realm_id)
        if (record['status'] != 'starting'
                or (generation is not None and record['generation'] != generation)):
            return
    runtime = Path(record["runtime_dir"])
    from .runtime_store import RuntimeStore
    runtime_copy = RuntimeStore(home).verify(record['runtime_copy'])
    env = dict(os.environ, PYTHONPATH=str(runtime_copy), PYTHONDONTWRITEBYTECODE='1')
    from .lifecycle import identity

    atomic_json(runtime / "supervisor.json", identity(os.getpid()))
    command = [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "--unit=" + record["scope"],
        "--property=BindsTo=" + record["guardian_unit"],
        "--property=After=" + record["guardian_unit"],
        "--description=T3 Code realm " + record["generation"],
        "--property=TimeoutStopSec=3s",
        "--",
        "systemd-inhibit",
        "--what=sleep",
        "--mode=block",
        "--who=T3 Code Realms",
        "--why=Background realm is active",
        sys.executable,
        "-B",
        "-P",
        "-m",
        "t3realms.bootstrap",
        "worker",
        str(runtime),
    ]
    runner = None
    try:
        runner = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, close_fds=True)
        deadline = time.monotonic() + 25
        ready = runtime / "ready.json"
        while not ready.exists():
            with registry.lock():
                current = registry.get(realm_id)
                if (current['generation'] != record['generation']
                        or current['status'] not in ('starting', 'running')):
                    raise RuntimeError('realm startup cancelled')
            if runner.poll() is not None:
                raise RuntimeError("realm scope exited during startup")
            if time.monotonic() > deadline:
                raise RuntimeError("realm startup timed out")
            time.sleep(0.1)
        startup = private_json(ready)
        while all(alive(process) for process in startup["processes"].values()):
            with registry.lock():
                current = registry.get(realm_id)
                if current['generation'] != record['generation']:
                    raise RuntimeError('realm generation changed')
                abandoned_start = (
                    current["status"] == "starting"
                    and time.time() - current["created_at"] >= 35
                )
                if (
                    abandoned_start
                    or current["status"] not in ("starting", "running")
                    or time.time() - current["last_activity"] >= current["idle_ttl"]
                ):
                    # Linearize expiry with env/reuse renewal. Cleanup may wait
                    # for the lock again, but no caller can renew this lease.
                    current["status"] = "stopping"
                    registry.put(current)
                    print("realm idle lease expired", flush=True)
                    break
            time.sleep(0.2)
        dead = {
            name: process
            for name, process in startup["processes"].items()
            if not alive(process)
        }
        if dead:
            print("realm components exited: " + json.dumps(dead), flush=True)
    except Exception as exc:
        if runtime.exists():
            atomic_json(runtime / "error.json", {"error": str(exc)})
        print(str(exc), file=sys.stderr, flush=True)
    finally:
        try:
            cleanup(home, realm_id, record["generation"])
        finally:
            if runner is not None:
                try:
                    runner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass


if __name__ == "__main__":
    if sys.argv[1] == "cleanup":
        cleanup(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
    else:
        run(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
