# Adapted from Hermes Realms 0.2.0 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Profile-scoped headless desktops. GUI separation, not a hostile-code sandbox."""

from dataclasses import asdict
from contextlib import ExitStack
import hashlib
import hmac
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import stat
import subprocess
import sys
import time
import uuid

from .config import Config, effective_home
from .lifecycle import (
    Registry,
    RealmError,
    OwnershipError,
    NotRunningError,
    BusyError,
    SetupRequired,
    private_json,
    RPC_RESPONSE_LIMIT_BYTES,
    alive,
    atomic_json,
    identity,
    remove_runtime,
    require_retained_workspace,
    scope_info,
    stop_scope,
    validate_live,
    validate_environment,
    validate_sockets,
)


class Manager:
    def __init__(self, home, *, config=None, realm_id=None):
        self.home = effective_home(home)
        if realm_id is None:
            self.config = Config.from_object({} if config is None else config)
        self.registry = Registry(self.home)
        if realm_id is not None:
            # Payload-only launchers attach to an already owned generation.
            # Its validated launch spec, not the host's current config, governs
            # that desktop; importing the host core here would break -P routing.
            with self.registry.lock():
                record = self.registry.get(realm_id)
                validate_live(record)
                spec = Path(record["runtime_dir"]) / "spec.json"
                payload = private_json(spec)
                if payload.pop('runtime_copy', None) != record.get('runtime_copy'):
                    raise OwnershipError('launch spec runtime copy changed')
                self.config = Config.from_object(payload)

    def record(self, realm_id, *, owner=None):
        with self.registry.lock():
            record = self.registry.get(realm_id)
            if owner is not None and owner != record['session_id']:
                raise OwnershipError('realm belongs to another owner')
            return record

    def list(self, owner=None):
        with self.registry.lock():
            self._reconcile_locked()
            return [dict(record, owner=record['session_id'], error=record.get('error', record.get('cleanup_error')),
                         cleanup_note=record.get('cleanup_note'))
                    for record in self.registry.records()
                    if owner is None or record['session_id'] == owner]

    def _reconcile_locked(self):
        for record in self.registry.records():
            if record["status"] == "starting":
                owner = Path(record["runtime_dir"]) / "owner.json"
                if owner.exists():
                    candidate = private_json(owner)
                    if any(
                        candidate.get(key) != record.get(key)
                        for key in (
                            "id",
                            "generation",
                            "uid",
                            "home",
                            "session_id",
                            "runtime_dir",
                            "runtime_copy",
                            "python_executable",
                            "scope",
                            "guardian_unit",
                        )
                    ):
                        raise OwnershipError("startup ownership receipt changed")
                    if alive(candidate.get("supervisor")):
                        validate_live(candidate)
                        guardian = scope_info(record["guardian_unit"])
                        if (
                            guardian["ActiveState"] != "active"
                            or guardian.get("InvocationID")
                            != candidate.get("guardian_invocation_id")
                            or Path(f"/proc/{candidate['supervisor']['pid']}/cgroup")
                            .read_text(encoding="utf-8")
                            .strip()
                            != "0::" + guardian.get("ControlGroup", "")
                        ):
                            raise OwnershipError("startup guardian invocation changed")
                        self.registry.put(candidate)
                        continue
                # A launcher can outlive the caller. Reserve its owner through
                # the startup deadline; absence must be observed on both units.
                if time.time() - record["created_at"] < 35:
                    continue
                guardian = scope_info(record["guardian_unit"])
                scope = scope_info(record["scope"])
                if any(
                    info["ActiveState"] not in ("inactive", "failed")
                    for info in (guardian, scope)
                ):
                    continue
                stop_scope(record)
                remove_runtime(self.registry, record)
            elif record["status"] == "cleanup_failed" or (
                record["status"] in ("running", "stopping")
                and (
                    not alive(record.get("supervisor"))
                    or not Path(record["runtime_dir"]).exists()
                )
            ):
                stop_scope(record)
                remove_runtime(self.registry, record)

    def start(self, session_id, *, before_start=None):
        from .runtime_store import pinned_runtime
        with ExitStack() as pins:
            runtime_copy = pins.enter_context(pinned_runtime(self.home))
            return self._start(session_id, runtime_copy, before_start=before_start,
                               release_runtime=pins.close)

    def _start(self, session_id, runtime_copy, *, before_start=None, release_runtime):
        from .config import validate_owner
        validate_owner(session_id)
        with self.registry.lock():
            for existing in self.registry.records():
                if existing["session_id"] == session_id:
                    require_retained_workspace(existing)
            self._reconcile_locked()
            retained = None
            for existing in self.registry.records():
                if existing["session_id"] == session_id and existing["status"] == "stopped":
                    if scope_info(existing["guardian_unit"])["ActiveState"] not in ("inactive", "failed"):
                        raise BusyError("realm guardian is still stopping; retry after reconciliation")
                    retained = existing
                    continue
                if (
                    existing["session_id"] == session_id
                    and existing["status"] != "running"
                ):
                    raise BusyError(
                        "realm is "
                        + existing["status"]
                        + "; retry after reconciliation"
                    )
                if (
                    existing["session_id"] == session_id
                    and existing["status"] == "running"
                ):
                    validate_live(existing)
                    existing["last_activity"] = time.time()
                    self.registry.put(existing)
                    return existing
            report = self.doctor()
            missing = [name for name, path in report['tools'].items() if path is None]
            if missing or not report['systemd_user'] or sys.platform != 'linux':
                raise SetupRequired(report['message'])
            if before_start is not None:
                before_start()
            generation = uuid.uuid4().hex
            realm_id = retained["id"] if retained else "r-" + generation[:24]
            runtime = Path(f"/run/user/{os.getuid()}/t3r-{generation[:16]}")  # windows-footgun: ok — runtime package rejects non-Linux hosts
            runtime.mkdir(mode=0o700)
            logs = self.registry.root / "logs"
            from .config import private_directory
            private_directory(logs)
            logfile = logs / (realm_id + ".log")
            record = {
                "id": realm_id,
                "session_id": session_id,
                "generation": generation,
                "uid": os.getuid(),  # windows-footgun: ok — runtime package rejects non-Linux hosts
                "home": str(self.home),
                "runtime_dir": str(runtime),
                "runtime_copy": str(runtime_copy),
                "python_executable": sys.executable,
                "scope": "t3code-realm-" + generation + ".scope",
                "status": "starting",
                "guardian_unit": "t3code-realm-" + generation + "-guard.service",
                "created_at": time.time(),
                "last_activity": time.time(),
                "size": self.config.size,
                "renderer": self.config.renderer,
                "overlay": self.config.overlay,
                "cursor_theme": self.config.cursor_theme,
                "idle_ttl": self.config.idle_ttl,
                "log_path": str(logfile),
            }
            from . import workspace

            if retained:
                workspace.validate(retained)
                record["workspace_dir"] = retained["workspace_dir"]
            else:
                workspace.create(record)
            atomic_json(runtime / "workspace.json", record)
            atomic_json(runtime / "spec.json", dict(asdict(self.config), runtime_copy=str(runtime_copy)))
            self.registry.put(record)
            # The durable record now pins the copy. Do not serialize a slow
            # desktop launch with admission of unrelated detached jobs.
            release_runtime()
            env = dict(os.environ)
            env.setdefault('PATH', '/usr/bin:/bin')
            # Fresh -P children resolve the CLI package only from this copy,
            # never the systemd working directory or caller PYTHONPATH.
            env["PYTHONPATH"] = str(runtime_copy)
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{os.getuid()}/bus"  # windows-footgun: ok — runtime package rejects non-Linux hosts
            env["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"  # windows-footgun: ok — runtime package rejects non-Linux hosts
            log_descriptor = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(log_descriptor, 'w') as log:
                cleanup = shlex.join(
                    [
                        sys.executable,
                        "-B",
                        "-P",
                        "-m",
                        "t3realms.supervisor",
                        "cleanup",
                        str(self.home),
                        realm_id,
                        generation,
                    ]
                ).replace("%", "%%")
                command = [
                    "systemd-run",
                    "--user",
                    "--quiet",
                    "--collect",
                    "--pipe",
                    "--service-type=exec",
                    "--expand-environment=no",
                    "--unit=" + record["guardian_unit"],
                    "--description=T3 Code realm guardian " + generation,
                    "--setenv=PYTHONPATH=" + env["PYTHONPATH"],
                    "--setenv=PYTHONDONTWRITEBYTECODE=1",
                    "--setenv=PATH=" + env["PATH"],
                    "--property=ExecStopPost=:" + cleanup,
                    sys.executable,
                    "-B",
                    "-P",
                    "-m",
                    "t3realms.supervisor",
                    str(self.home),
                    realm_id,
                    generation,
                ]
                try:
                    if before_start is not None:
                        before_start(prepared=record)
                    monitor = subprocess.Popen(
                        command,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=log,
                        close_fds=True,
                        start_new_session=True,
                    )
                except BaseException:
                    remove_runtime(self.registry, record)
                    raise
            import threading

            threading.Thread(
                target=monitor.wait, name="realm-launcher-reaper", daemon=True
            ).start()
        try:
            self._wait_for_ready(record, monitor, logfile)
            with self.registry.lock():
                self._validate_start_locked(record)
                ready = private_json(runtime / 'ready.json')
                record['supervisor'] = private_json(runtime / 'supervisor.json')
                info = scope_info(record["scope"])
                if info.get("ActiveState") != "active":
                    raise RealmError("realm scope is not active")
                record.update(
                    status="running",
                    last_activity=time.time(),
                    processes=ready["processes"],
                    vnc_port=None,
                    vnc_socket=ready["vnc_socket"],
                    guardian_invocation_id=scope_info(record["guardian_unit"])[
                        "InvocationID"
                    ],
                    invocation_id=info["InvocationID"],
                    cgroup=info["ControlGroup"],
                )
                validate_live(record)
                validate_environment(record, ready['env'])
                atomic_json(runtime / "owner.json", record)
                self.registry.put(record)
                return record
        except BaseException:
            self._retire_start(record)
            raise

    def _validate_start_locked(self, record):
        current = self.registry.get(record['id'])
        if (any(current.get(key) != record.get(key) for key in (
                'id', 'generation', 'session_id', 'uid', 'home', 'runtime_dir',
                'runtime_copy', 'python_executable', 'scope', 'guardian_unit', 'workspace_dir'))
                or current['status'] not in ('starting', 'running')):
            raise OwnershipError('realm startup ownership or generation changed; startup cancelled')
        return current

    def _wait_for_ready(self, record, monitor, logfile):
        runtime = Path(record['runtime_dir'])
        deadline = time.monotonic() + 30
        while not (runtime / 'ready.json').exists():
            with self.registry.lock():
                self._validate_start_locked(record)
            if (runtime / 'error.json').exists() or monitor.poll() is not None:
                raise RealmError('realm startup failed; see ' + str(logfile) + '\n'
                                 + logfile.read_text(encoding='utf-8')[-5000:])
            if time.monotonic() > deadline:
                raise TimeoutError('realm startup timed out; see ' + str(logfile))
            time.sleep(0.1)

    def _stop_starting_guardian(self, record):
        info = scope_info(record['guardian_unit'])
        if info['ActiveState'] in ('inactive', 'failed'):
            return
        if (info.get('Description') != 'T3 Code realm guardian ' + record['generation']
                or (record.get('guardian_invocation_id')
                    and info.get('InvocationID') != record['guardian_invocation_id'])):
            raise OwnershipError('startup guardian ownership changed')
        from .lifecycle import host_control_env
        # ExecStopPost takes the registry lock, so stop the guardian outside it.
        subprocess.run(['systemctl', '--user', 'stop', record['guardian_unit']],
                       env=host_control_env(), check=True, capture_output=True, timeout=20)

    def _retire_start(self, record):
        with self.registry.lock():
            current = self.registry.get(record['id'])
            if current['generation'] == record['generation']:
                if current['session_id'] != record['session_id']:
                    raise OwnershipError('startup owner changed during cleanup')
                if current['status'] in ('starting', 'running'):
                    self.registry.put(dict(current, status='stopping'))
        self._stop_starting_guardian(record)
        with self.registry.lock():
            # A late scope still belongs to this start, even after a stop. Never
            # overwrite a replacement generation with the old cleanup receipt.
            stop_scope(record)
            current = self.registry.get(record['id'])
            if current['generation'] == record['generation']:
                if current['session_id'] != record['session_id']:
                    raise OwnershipError('startup owner changed during cleanup')
                remove_runtime(self.registry, current)

    def env(self, realm_id, *, renew=False):
        with self.registry.lock():
            record = self.registry.get(realm_id)
            if record["status"] != "running":
                raise NotRunningError("realm is not running")
            validate_live(record)
            env = private_json(Path(record["runtime_dir"]) / "ready.json")[
                "env"
            ]
            validate_environment(record, env)
            if renew:
                record["last_activity"] = time.time()
                self.registry.put(record)
            return env

    def _rpc(self, realm_id, *, renew, **request):
        self.env(realm_id, renew=renew)
        with self.registry.lock():
            record = self.registry.get(realm_id)
        control = Path(record['runtime_dir']) / 'control'
        info = control.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise OwnershipError('realm control socket ownership or mode changed')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(15)
            connection.connect(str(Path(record["runtime_dir"]) / "control"))
            pid, uid, _ = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != os.getuid() or identity(pid) != record["processes"]["worker"]:  # windows-footgun: ok — runtime package rejects non-Linux hosts
                raise OwnershipError("realm control endpoint ownership mismatch")
            request["client_process"] = identity(os.getpid())
            payload = json.dumps(request).encode() + b"\n"
            connection.sendall(payload)
            with connection.makefile("rb") as stream:
                response = json.loads(stream.readline(RPC_RESPONSE_LIMIT_BYTES))
        if "error" in response:
            from .errors import coded_error
            raise coded_error(response.get('code', 'failed'), response['error'])
        return response["result"]

    def shot(self, realm_id, *, format='png', quality=None, scale=1):
        from .capture import capture_options
        options = capture_options(format, quality, scale)
        return self._rpc(realm_id, renew=True, op='shot', **options)

    def touch(self, realm_id):
        self.env(realm_id, renew=True)
        return self.record(realm_id)

    def vnc_endpoint(self, realm_id, *, owner=None):
        with self.registry.lock():
            record = self.registry.get(realm_id)
            if owner is not None and owner != record['session_id']:
                raise OwnershipError('realm belongs to another owner')
            if record['status'] != 'running':
                raise NotRunningError('realm is not running')
            validate_live(record)
            path = Path(record['runtime_dir']) / 'wayvnc.sock'
            if record.get('vnc_socket') != str(path):
                raise OwnershipError('realm VNC endpoint identity changed')
            validate_sockets(record, [path], mode=0o600)
            return {'path': str(path)}

    def outputs(self, realm_id):
        return self._rpc(realm_id, renew=False, op='outputs')

    def windows(self, realm_id):
        from .windows import count_windows
        self.env(realm_id, renew=False)
        return {'count': count_windows(self.record(realm_id))}

    def job(self, realm_id, job_id):
        return self._rpc(realm_id, renew=True, op='job', job_id=job_id)

    def signal(self, realm_id, job_id, number):
        from .errors import signal_number
        return self._rpc(realm_id, renew=True, op='signal', job_id=job_id, signal=signal_number(number))

    def resize(self, realm_id, size):
        from .config import parse_size

        parse_size(size)
        self._rpc(realm_id, renew=True, op="resize", size=size)
        with self.registry.lock():
            record = self.registry.get(realm_id)
            record["size"] = size
            self.registry.put(record)
            return record

    def doctor(self):
        from .diagnostics import doctor
        return doctor(self.home)

    def exec(self, realm_id, command, *, cwd=None, wait=False, timeout=30):
        """Run a captured command in the realm.

        Capture keeps the first 256 KiB per stream, drains overflow without
        breaking writes, and reports *_truncated plus output_complete. Results
        survive five minutes after exit and capture EOF; live output never
        expires. At 128 retained/active jobs, admission fails rather than
        evicting results.
        wait waits for the direct child, not daemonized descendants.
        """
        if (
            not isinstance(command, (list, tuple))
            or not command
            or not all(isinstance(arg, str) and "\x00" not in arg for arg in command)
        ):
            raise ValueError("command must be a nonempty argv list")
        from .host_guard import guard_argv
        guard_argv(command)
        if cwd is not None and (not isinstance(cwd, str) or not Path(cwd).is_absolute() or '\0' in cwd):
            raise ValueError('cwd must be an absolute NUL-free path')
        if cwd is None:
            cwd = str(Path(self.record(realm_id)['workspace_dir']) / 'home')
        job = self._rpc(
            realm_id,
            renew=True,
            op="exec",
            command=list(command),
            cwd=cwd,
        )
        if not wait:
            return job
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self._rpc(realm_id, renew=True, op="job", job_id=job["job_id"])
            if status["returncode"] is not None:
                return status
            time.sleep(0.05)
        raise TimeoutError(
            "command wait timed out; job remains owned by realm: " + job["job_id"]
        )

    def delete_snapshot(self, realm_id, *, session_id):
        """Read-only confirmation capture; never reconcile or stop compute."""
        with self.registry.lock():
            record = self.registry.get(realm_id)
            if not session_id or record["session_id"] != session_id:
                raise OwnershipError("workspace belongs to another session")
            snapshot = self._delete_snapshot_locked(record)
            return dict(snapshot, token=self._delete_token(snapshot))

    def _delete_snapshot_locked(self, record):
        from .workspace import begin_deletion, validate_deletion

        if record["status"] not in ("stopped", "deleting"):
            raise RealmError("only a stopped workspace can be deleted")
        units = {key: scope_info(record[key]) for key in ("scope", "guardian_unit")}
        if any(info["ActiveState"] not in ("inactive", "failed") for info in units.values()):
            raise RealmError("realm compute has not stopped")
        if record["status"] == "deleting":
            validate_deletion(record)
            receipt = record["deletion"]
        else:
            receipt = begin_deletion(record)["deletion"]
        info = self.registry.path(record["id"]).stat()
        # Every atomic registry publication invalidates the prompt, even if a
        # stop/start/stop restores identical record bytes and stable IDs.
        return {"record": record, "deletion": receipt, "compute": units,
                "publication": [info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns]}

    @staticmethod
    def _delete_token(snapshot):
        canonical = json.dumps(snapshot, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True, allow_nan=False).encode('ascii')
        return hashlib.sha256(canonical).hexdigest()

    def delete(self, realm_id, *, session_id=None, token=None):
        """Explicit data deletion, never used by stop/reconciliation.

        This is a profile-administrative API like stop(id). Session surfaces
        must pass their resolved owner, not an owner supplied by the client.
        """
        from .workspace import begin_deletion, finish_deletion, sync_directory

        with self.registry.lock():
            record = self.registry.get(realm_id)
            if not session_id or record["session_id"] != session_id:
                raise OwnershipError("workspace belongs to another session")
            if (not isinstance(token, str) or len(token) != 64
                    or any(character not in '0123456789abcdef' for character in token)):
                raise ValueError("a delete confirmation token is required")
            if not hmac.compare_digest(self._delete_token(self._delete_snapshot_locked(record)), token):
                raise OwnershipError("Delete confirmation target changed; confirm again")
            if record["status"] not in ("stopped", "deleting"):
                raise RealmError("only a stopped workspace can be deleted")
            if any(scope_info(record[key])["ActiveState"] not in ("inactive", "failed")
                   for key in ("scope", "guardian_unit")):
                raise RealmError("realm compute has not stopped")
            if record["status"] != "deleting":
                record = begin_deletion(record)
                self.registry.put(record)
            finish_deletion(record)
            self.registry.remove(realm_id)
            sync_directory(self.registry.root)
            return True

    def preflight_stop(self, session_id=None):
        """Validate the whole affected set without triggering reconciliation.

        Integration must call before revoking authority; stop still rechecks
        the current record under the same registry lock at its own boundary.
        """
        with self.registry.lock():
            records = [record for record in self.registry.records()
                       if session_id is None or record["session_id"] == session_id]
            for record in records:
                require_retained_workspace(record)
            return records

    def stop(self, realm_id):
        with self.registry.lock():
            record = self.registry.get(realm_id)
            require_retained_workspace(record)
            if record["status"] in ("stopped", "deleting"):
                return True
            if record['status'] in ('starting', 'stopping') and not record.get('invocation_id'):
                # The waiting start owns teardown, including a guardian/scope
                # whose systemd admission has not completed yet. Reserve its ID.
                self.registry.put(dict(record, status='stopping'))
                return True
            stop_scope(record)
            remove_runtime(self.registry, record)
        deadline = time.monotonic() + 8
        while alive(record.get("supervisor")) and time.monotonic() < deadline:
            time.sleep(0.1)
        return True

    def stop_owner(self, owner):
        from .config import validate_owner
        validate_owner(owner)
        records = self.preflight_stop(owner)
        for record in records:
            self.stop(record['id'])
        return True
