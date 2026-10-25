# Adapted from Hermes Realms 0.2.0 (MIT, Copyright (c) 2026 Zeus-Deus)
"""OS containment for the trusted realm driver, not for arbitrary terminal code.

Only the private compositor/buses/runtime and render nodes are exposed. Host
home, session sockets, input devices, PID list and network namespace stay out.
"""

import os
from pathlib import Path
import shutil

from .lifecycle import validate_live, private_json, OwnershipError, SetupRequired


def sandbox_command(record, executable, args=()):
    validate_live(record)
    runtime = Path(record["runtime_dir"])
    binary = Path(executable).resolve(strict=True)
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError("bubblewrap is required for realm driver isolation")
    command = [
        bwrap,
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/etc",
        "/etc",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",  # no-tmp: ok — private tmpfs mounted over the sandbox's own /tmp
        "--dir",
        "/run",
        "--dir",
        "/run/user",
        "--dir",
        str(runtime.parent),
        "--bind",
        str(runtime),
        str(runtime),
        '--bind',
        str(Path(record['workspace_dir']) / 'home'),
        str(Path(record['workspace_dir']) / 'home'),
    ]
    for path in ("/bin", "/sbin", "/lib", "/lib64"):
        target = Path(path)
        if target.is_symlink():
            command += ["--symlink", os.readlink(path), path]
        elif target.exists():
            command += ["--ro-bind", path, path]
    # EGL can render but no DRM card, uinput or physical event device is exposed.
    for node in sorted(Path("/dev/dri").glob("renderD*")):
        command += ["--dev-bind", str(node), str(node)]
    # Driver overlay may use Xwayland; expose only this realm's X socket.
    import re

    env = private_json(runtime / "ready.json")["env"]
    display = env.get("DISPLAY", "")
    if not re.fullmatch(r":[0-9]+", display):
        raise ValueError("Invalid private Xwayland display")
    xsocket = Path("/tmp/.X11-unix") / ("X" + display[1:])  # no-tmp: ok — fixed X11 socket directory
    if xsocket.exists():
        command += ["--ro-bind", str(xsocket), str(xsocket)]
    if not binary.is_relative_to("/usr"):
        command += ["--ro-bind", str(binary), "/opt/realm-driver"]
        binary = Path("/opt/realm-driver")
    # Bind only the exact host-approved bounded manifest, read-only. Its
    # contents remain owned by the caller, never rewritten here.
    args = list(args)
    for index, argument in enumerate(args):
        if argument in ("--capability-manifest", "--session-policy"):
            if index + 1 >= len(args):
                raise ValueError("Missing capability manifest path")
            manifest = Path(args[index + 1]).resolve(strict=True)
            if not manifest.is_file():
                raise ValueError("Capability manifest must be a regular file")
            command += ["--ro-bind", str(manifest), str(manifest)]
            args[index + 1] = str(manifest)
    command += ["--chdir", str(runtime), "--", str(binary), *args]
    return command


def create_driver_launcher(manager, realm_id, executable=None):
    """Return an owned, receipt-verified contained driver entry point."""
    manager.env(realm_id, renew=False)
    record = manager.record(realm_id)
    from .config import driver_path
    from .install_driver import execution_verified
    executable = driver_path(manager.home)
    if not execution_verified(executable):
        raise SetupRequired('Pinned driver installation and execution verification required')
    from .runtime_store import pinned_runtime
    # Use the running generation's payload, even when this request arrived
    # through a newer plugin snapshot with a different runtime version.
    if 'runtime_copy' not in record or 'python_executable' not in record:
        raise OwnershipError('realm has no recorded runtime or interpreter; restart it')
    with pinned_runtime(manager.home, record['runtime_copy']) as payload:
        return _write_driver_launcher(manager, record, executable, payload)


def _write_driver_launcher(manager, record, executable, payload):
    realm_id = record['id']
    binary = str(executable)
    script = Path(record["runtime_dir"]) / "cua-contained"
    payload = str(payload)
    content = (
        f"#!{record['python_executable']} -IB\nimport sys\n"
        f"sys.path.insert(0, {payload!r})\n"
        f"from t3realms.driver import driver_main\n"
        f"driver_main({str(manager.home)!r},{realm_id!r},{binary!r},{record['generation']!r})\n"
    )
    import stat

    with manager.registry.lock():
        current = manager.registry.get(realm_id)
        if any(current.get(key) != record.get(key) for key in
               ('generation', 'runtime_copy', 'python_executable')):
            raise OwnershipError('Driver launcher compute incarnation changed')
        validate_live(current)
        if script.exists() or script.is_symlink():
            info = script.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise OwnershipError("Private driver launcher ownership changed")
            if script.read_text(encoding="utf-8") != content:
                raise OwnershipError("Private driver launcher contents changed")
        else:
            descriptor = os.open(
                script, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
    return str(script)


def driver_main(home, realm_id, binary, generation):
    import sys
    from .manager import Manager

    os.umask(0o077)
    manager = Manager(home, realm_id=realm_id)
    record = manager.record(realm_id)
    if record['generation'] != generation:
        raise OwnershipError('Driver launcher compute incarnation changed')
    from .config import driver_path
    from .install_driver import execution_verified
    target = driver_path(home)
    if str(target) != binary or not execution_verified(target):
        raise OwnershipError('Driver executable identity changed')
    env = manager.env(realm_id, renew=False)
    env['CUA_DRIVER_RS_TELEMETRY_ENABLED'] = '0'
    args = list(sys.argv[1:])
    if args and args[0] in ('mcp', 'serve'):
        if '--embedded' not in args:
            args.append('--embedded')
        if '--socket' not in args:
            args += ['--socket', str(Path(record['runtime_dir']) / 'cua-driver.sock')]
        else:
            index = args.index('--socket')
            if index + 1 == len(args) or Path(args[index + 1]).parent != Path(record['runtime_dir']):
                raise OwnershipError('Driver socket must be private to this realm')
        if '--session-label' not in args:
            args += ['--session-label', realm_id]
        if not manager.config.overlay and '--no-overlay' not in args:
            args.append('--no-overlay')
        if '--cursor-theme' not in args:
            args += ['--cursor-theme', manager.config.cursor_theme]
    command = sandbox_command(record, binary, args)
    if args and args[0] in ('mcp', 'serve'):
        from .driver_lifetime import run_contained
        endpoint = Path(args[args.index('--socket') + 1]) if args[0] == 'serve' else None
        result = run_contained(manager, record, command, env, endpoint=endpoint)
        if result:
            raise SystemExit(result)
        return
    os.execve(command[0], command, env)
