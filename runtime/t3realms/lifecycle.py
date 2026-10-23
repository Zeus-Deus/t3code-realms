# Adapted from Hermes Realms 0.2.0 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Crash-safe registry and Linux process ownership primitives."""

from contextlib import contextmanager
import fcntl  # windows-footgun: ok — runtime package rejects non-Linux hosts
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


OUTPUT_LIMIT_BYTES = 262144
# Two UTF-8-decoded streams: each raw byte can expand to six JSON bytes
# (control bytes or replacement characters), plus a bounded metadata envelope.
RPC_RESPONSE_LIMIT_BYTES = 2 * 6 * OUTPUT_LIMIT_BYTES + 65536


class RealmError(RuntimeError):
    pass


class OwnershipError(RealmError):
    pass


class NotFoundError(RealmError):
    pass


class NotRunningError(RealmError):
    pass


class SetupRequired(RealmError):
    pass


class BusyError(RealmError):
    pass


def require_retained_workspace(record):
    validate_record(record)


def private_json(path):
    path = Path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4 * 1024 * 1024):
                raise OwnershipError('private JSON ownership, permissions, or size changed')
            return json.load(stream)
    except (ValueError, OSError) as exc:
        raise OwnershipError('private JSON receipt unavailable: ' + str(path)) from exc


def atomic_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def identity(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
        if stat[0] == "Z":
            return None
        return {"pid": int(pid), "start_time": int(stat[19])}
    except (FileNotFoundError, ProcessLookupError):
        return None


def valid_identity(process):
    return (isinstance(process, dict) and set(process) == {'pid', 'start_time'}
            and all(type(value) is int and value > 0 for value in process.values()))


def alive(process):
    return valid_identity(process) and identity(process['pid']) == process


def host_control_env():
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(Path.home()),
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",  # windows-footgun: ok — runtime package rejects non-Linux hosts
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",  # windows-footgun: ok — runtime package rejects non-Linux hosts
    }


def scope_info(scope):
    try:
        result = subprocess.run(
            [
                "systemctl",
                "--user",
                "show",
                scope,
                "--property=LoadState,InvocationID,ControlGroup,ActiveState,Description",
            ],
            env=host_control_env(),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RealmError("could not inspect systemd unit " + scope) from exc
    info = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if not info.get("ActiveState"):
        raise RealmError("could not inspect systemd unit state " + scope)
    return info


def validate_record(record):
    from .config import effective_home, validate_owner
    if not isinstance(record, dict):
        raise OwnershipError('invalid realm record')
    generation = record.get('generation', '')
    if (not isinstance(generation, str) or not re.fullmatch(r'[0-9a-f]{32}', generation)
            or not isinstance(record.get('id'), str)
            or not re.fullmatch(r'r-[0-9a-f]{24}', record['id'])):
        raise OwnershipError('invalid realm generation or id')
    if record.get('uid') != os.getuid():
        raise OwnershipError('realm uid ownership mismatch')
    try:
        effective_home(record.get('home'))
        validate_owner(record.get('session_id'))
    except ValueError as exc:
        raise OwnershipError('invalid realm home or owner') from exc
    if 'runtime_copy' in record:
        from .runtime_store import runtime_reference
        runtime_reference(record['home'], record['runtime_copy'])
    interpreter = record.get('python_executable')
    if interpreter is not None and (not isinstance(interpreter, str)
            or not Path(interpreter).is_absolute() or any(c.isspace() for c in interpreter)
            or '\0' in interpreter):
        raise OwnershipError('invalid recorded Python interpreter')
    if not record.get('workspace_dir'):
        raise OwnershipError('retained workspace binding is required')
    from .workspace import validate
    validate(record)
    expected_runtime = Path(f"/run/user/{os.getuid()}/t3r-{generation[:16]}")  # windows-footgun: ok — runtime package rejects non-Linux hosts
    if (
        record.get("runtime_dir") != str(expected_runtime)
        or record.get("scope") != f"t3code-realm-{generation}.scope"
    ):
        raise OwnershipError("realm runtime or scope ownership mismatch")
    if record.get("guardian_unit") != f"t3code-realm-{generation}-guard.service":
        raise OwnershipError("realm guardian identity changed")
    if record.get("status") == "running" and (
        record.get("vnc_socket") != str(expected_runtime / "wayvnc.sock")
        or record.get("vnc_port") is not None
    ):
        raise OwnershipError("realm VNC endpoint identity changed")
    if expected_runtime.is_symlink():
        raise OwnershipError("realm runtime is a symlink")
    if expected_runtime.exists():
        info = expected_runtime.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):  # windows-footgun: ok — runtime package rejects non-Linux hosts
            raise OwnershipError("realm runtime permissions changed")


def validate_live(record):
    validate_record(record)
    info = scope_info(record["scope"])
    if (
        info.get("ActiveState") != "active"
        or info.get("InvocationID") != record.get("invocation_id")
        or info.get("ControlGroup") != record.get("cgroup")
        or info.get("Description") != "T3 Code realm " + record["generation"]
    ):
        raise OwnershipError("realm scope is not the owned live invocation")
    cgroup = record.get('cgroup', '')
    invocation = record.get('invocation_id', '')
    processes = record.get('processes')
    if (not isinstance(invocation, str) or not re.fullmatch('[0-9a-f]{32}', invocation)
            or not isinstance(cgroup, str) or not cgroup.startswith('/') or cgroup == '/'
            or '..' in Path(cgroup).parts
            or not isinstance(processes, dict)
            or not {'worker', 'bus', 'compositor', 'atspi', 'registry', 'vnc'} <= processes.keys()
            or not Path(record['runtime_dir']).is_dir()):
        raise OwnershipError('incomplete live realm ownership receipt')
    for process in processes.values():
        if not alive(process):
            raise OwnershipError('realm process exited or PID identity changed')
        try:
            membership = Path(f"/proc/{process['pid']}/cgroup").read_text(encoding='utf-8').strip()
        except OSError as exc:
            raise OwnershipError('realm process cgroup unavailable') from exc
        if membership != '0::' + cgroup:
            raise OwnershipError('realm process left its scope')


def validate_environment(record, env):
    runtime = Path(record["runtime_dir"])
    required = {
        "XDG_RUNTIME_DIR": str(runtime),
        "HOME": str(Path(record["workspace_dir"]) / "home"),
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(runtime / "bus"),
        "XAUTHORITY": str(runtime / "Xauthority"),
        "XDG_CURRENT_DESKTOP": "labwc",
        "LABWC_UPDATE_ACTIVATION_ENV": "false",
        "ATSPI_DBUS_IMPLEMENTATION": "dbus-daemon",
        "CUA_DRIVER_RS_ENABLE_WAYLAND": "1",
        "GTK_USE_PORTAL": "0",
    }
    if any(env.get(k) != value for k, value in required.items()):
        raise OwnershipError("private environment binding changed")
    if not re.fullmatch(
        r"wayland-[0-9]+", env.get("WAYLAND_DISPLAY", "")
    ) or not re.fullmatch(r":[0-9]+", env.get("DISPLAY", "")):
        raise OwnershipError("invalid compositor-published displays")
    forbidden = (
        "I3SOCK",
        "CUA_DRIVER_SOCKET",
        "CUA_DRIVER_RS_SOCKET",
        "CUA_DRIVER_RS_SESSION",
        "CUA_DRIVER_RS_STATE_DIR",
        "CUA_DRIVER_RS_PERMISSION_MODE",
        "CUA_DRIVER_PERMISSION_MODE",
        "CUA_DRIVER_RS_BYPASS_APPROVALS",
        "HYPRLAND_INSTANCE_SIGNATURE",
        "HYPRLAND_CMD",
        "YDOTOOL_SOCKET",
        "SWAYSOCK",
        "WAYLAND_SOCKET",
        "CUA_INJECT_SOCKET",
        "CUA_WAYLAND_NEST",
        "LIBEI_SOCKET",
        "DBUS_STARTER_BUS_TYPE",
        "SESSION_MANAGER",
        "GTK_MODULES",
        "GTK3_MODULES",
        "GIO_EXTRA_MODULES",
        "QT_QPA_PLATFORMTHEME",
        "QT_PLUGIN_PATH",
        "GTK_PATH",
        "GDK_DEBUG",
        "PIPEWIRE_REMOTE",
        "PULSE_SERVER",
        "GPG_AGENT_INFO",
        "DBUS_STARTER_ADDRESS",
        "AT_SPI_BUS",
        "SSH_AUTH_SOCK",
        "LISTEN_FDS",
        "LISTEN_PID",
        "XDG_ACTIVATION_TOKEN",
        "DESKTOP_STARTUP_ID",
    )
    if any(key in env for key in forbidden):
        raise OwnershipError("host control environment hint found")
    a11y = env.get("AT_SPI_BUS_ADDRESS", "").split(",", 1)[0]
    if not a11y.startswith("unix:path=" + str(runtime / "at-spi") + "/"):
        raise OwnershipError("accessibility address is not private")
    sockets = [
        runtime / env["WAYLAND_DISPLAY"],
        runtime / "bus",
        Path(a11y.removeprefix("unix:path=")),
        Path("/tmp/.X11-unix/X" + env["DISPLAY"][1:]),  # no-tmp: ok — fixed X11 socket directory
    ]
    validate_sockets(record, sockets)


def validate_sockets(record, sockets, *, mode=None):
    """Require real sockets held open by members of this realm's cgroup."""
    for path in sockets:
        try:
            info = path.lstat()
        except OSError as exc:
            raise OwnershipError('realm socket unavailable: ' + str(path)) from exc
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise OwnershipError('realm socket ownership changed: ' + str(path))
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise OwnershipError('realm socket mode changed: ' + str(path))
    socket_inodes = {}
    for line in Path("/proc/net/unix").read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 8:
            socket_inodes.setdefault(parts[7], set()).add("socket:[" + parts[6] + "]")
    owned = set()
    cgroup = Path("/sys/fs/cgroup") / record["cgroup"].lstrip("/")
    for pid in (cgroup / "cgroup.procs").read_text(encoding="utf-8").split():
        try:
            for fd in Path(f"/proc/{pid}/fd").iterdir():
                try:
                    owned.add(os.readlink(fd))
                except (FileNotFoundError, PermissionError):
                    pass
        except (FileNotFoundError, PermissionError):
            pass
    for path in sockets:
        if not path.is_socket() or not (socket_inodes.get(str(path), set()) & owned):
            raise OwnershipError("realm does not own socket " + str(path))


def stop_scope(record):
    validate_record(record)
    info = scope_info(record["scope"])
    if info.get("ActiveState") in ("inactive", "failed"):
        return
    if info.get("Description") != "T3 Code realm " + record["generation"]:
        raise OwnershipError("scope ownership does not match realm generation")
    if (
        record.get("invocation_id")
        and info.get("InvocationID") != record["invocation_id"]
    ):
        raise OwnershipError("scope invocation identity changed")
    try:
        subprocess.run(
            ["systemctl", "--user", "stop", record["scope"]],
            env=host_control_env(),
            capture_output=True,
            timeout=12,
            check=True,
        )
    except subprocess.CalledProcessError:
        # BindsTo/--collect can retire the scope after ownership validation.
        # A failed stop is safe only after a fresh, successful terminal-state query.
        if scope_info(record["scope"]).get("ActiveState") not in ("inactive", "failed"):
            raise
        return
    if scope_info(record["scope"]).get("ActiveState") not in ("inactive", "failed"):
        raise RealmError("realm scope has not stopped")


def remove_runtime(registry, record):
    """After confirmed scope teardown, retain ownership until deletion succeeds.

    Caller holds the registry lock. Never repair permissions: runtime children
    can be symlinks to paths outside this generation's owned tree.
    """
    validate_record(record)
    if record.get("status") == "deleting":
        return
    runtime = Path(record["runtime_dir"])
    record = dict(record, status="stopping")
    registry.put(record)
    try:
        runtime = Path(record["runtime_dir"])
        if runtime.exists():
            shutil.rmtree(runtime)
    except OSError as exc:
        record.update(status="cleanup_failed", cleanup_error=str(exc))
        registry.put(record)
        raise RealmError("realm runtime cleanup failed: " + str(exc)) from exc
    record.update(status="stopped")
    record.pop("cleanup_error", None)
    registry.put(record)


class Registry:
    def __init__(self, home):
        from .config import effective_home, private_directory
        self.root = private_directory(effective_home(home) / 'realms')

    @contextmanager
    def lock(self, *, blocking=True):
        fd = os.open(self.root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise OwnershipError('registry lock ownership changed')
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield
        finally:
            os.close(fd)

    def path(self, realm_id):
        if not isinstance(realm_id, str) or not re.fullmatch(
            r"r-[0-9a-f]{24}", realm_id
        ):
            raise ValueError("invalid realm id")
        return self.root / (realm_id + ".json")

    def get(self, realm_id):
        path = self.path(realm_id)
        try:
            if not path.exists() and not path.is_symlink():
                raise FileNotFoundError(path)
            value = private_json(path)
        except FileNotFoundError as exc:
            raise NotFoundError("realm not found: " + realm_id) from exc
        if (
            not isinstance(value, dict)
            or value.get("id") != realm_id
            or value.get("uid") != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
            or value.get("home") != str(self.root.parent)
        ):
            raise OwnershipError("registry ownership mismatch")
        validate_record(value)
        return value

    def put(self, record):
        if record.get('home') != str(self.root.parent):
            raise OwnershipError('registry home ownership mismatch')
        validate_record(record)
        atomic_json(self.path(record["id"]), record)

    def records(self):
        return [self.get(p.stem) for p in sorted(self.root.glob("r-*.json"))]

    def remove(self, realm_id):
        self.path(realm_id).unlink(missing_ok=True)
