# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Stdlib-only guest half; executed as the desktop user over pinned SSH."""
import json
import os
from pathlib import Path
import shutil
import stat
import base64
import hashlib
import pwd  # windows-footgun: ok — runtime package rejects non-Linux hosts
import re
import runpy
import socket
import struct
import subprocess
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def process_start(pid):
    return Path(f'/proc/{pid}/stat').read_text(encoding="utf-8").rsplit(')', 1)[1].split()[19]


def socket_identity(path):
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():  # windows-footgun: ok — runtime package rejects non-Linux hosts
        raise ValueError('Guest socket owner changed')
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(1)
        client.connect(str(path))
        pid, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid():  # windows-footgun: ok — runtime package rejects non-Linux hosts
        raise ValueError('Foreign guest socket peer')
    return {'device': info.st_dev, 'inode': info.st_ino, 'peer_pid': pid,
            'peer_start': process_start(pid)}


def desktop_identity():
    account = pwd.getpwuid(os.getuid())  # windows-footgun: ok — runtime package rejects non-Linux hosts
    if account.pw_uid == 0:
        raise ValueError('CUA must run as the guest desktop user')
    runtime = private_directory(Path('/run/user') / str(account.pw_uid))
    sockets = [p for p in runtime.glob('wayland-*') if stat.S_ISSOCK(p.lstat().st_mode)]
    if len(sockets) != 1:
        raise ValueError('Guest desktop endpoint is missing or ambiguous')
    path = sockets[0]
    return {'uid': account.pw_uid, 'home': account.pw_dir, 'runtime': str(runtime),
            'wayland': path.name, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text(encoding="utf-8").strip(),
            **socket_identity(path)}


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def read_owned(path, limit=64 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
                or info.st_mode & 0o077 or info.st_size > limit):
            raise ValueError('Guest asset ownership or size changed')
        return stream.read(limit + 1)


def stage(token, expected):
    if not re.fullmatch('[0-9a-f]{16}', token):
        raise ValueError('Invalid CUA stage generation')
    desktop = desktop_identity()
    assets = Path(desktop['runtime']) / ('hcu-' + token)
    assets.mkdir(mode=0o700)
    try:
        header = json.loads(sys.stdin.buffer.readline(8193))
        if set(header) != {'cua-driver', 'vm_driver_lifetime.py'}:
            raise ValueError('Unexpected CUA payload')
        for name, info in header.items():
            size = info['size']
            if not isinstance(size, int) or not 0 < size <= 64 * 1024 * 1024:
                raise ValueError('CUA asset size exceeded')
            data = sys.stdin.buffer.read(size)
            if len(data) != size or digest(data) != info['sha256']:
                raise ValueError('CUA asset checksum mismatch')
            write_new(assets / name, data, 0o700 if name == 'cua-driver' else 0o600)
        if sys.stdin.buffer.read(1) or digest(read_owned(assets / 'cua-driver')) != expected:
            raise ValueError('Pinned guest binary mismatch')
        (assets / 'home').mkdir(mode=0o700)
        info = assets.stat()
        result = {'desktop': desktop, 'token': token, 'device': info.st_dev, 'inode': info.st_ino,
                  'binary_sha256': expected, 'supervisor_sha256': header['vm_driver_lifetime.py']['sha256']}
        print(json.dumps(result), flush=True)
        return 0
    except BaseException:
        shutil.rmtree(assets)
        raise


def attest(guest):
    desktop = desktop_identity()
    if desktop != guest['desktop']:
        raise ValueError('Guest desktop identity changed')
    if not re.fullmatch('[0-9a-f]{16}', guest['token']):
        raise ValueError('Invalid CUA asset generation')
    assets = private_directory(Path(desktop['runtime']) / ('hcu-' + guest['token']))
    info = assets.stat()
    if (info.st_dev, info.st_ino) != (guest['device'], guest['inode']):
        raise ValueError('Guest CUA assets replaced')
    for name, expected in (('cua-driver', guest['binary_sha256']),
                           ('vm_driver_lifetime.py', guest['supervisor_sha256'])):
        if digest(read_owned(assets / name)) != expected:
            raise ValueError('Guest CUA asset checksum mismatch')
    return assets


def driver_env(guest, assets):
    desktop = guest['desktop']
    home = str(assets / 'home')
    return {'PATH': '/usr/bin:/bin', 'HOME': home, 'LANG': 'C.UTF-8',
            'XDG_CONFIG_HOME': home, 'XDG_CACHE_HOME': home,
            'XDG_RUNTIME_DIR': desktop['runtime'], 'WAYLAND_DISPLAY': desktop['wayland'],
            'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + desktop['runtime'] + '/bus',
            'CUA_DRIVER_RS_ENABLE_WAYLAND': '1', 'CUA_DRIVER_RS_TELEMETRY_ENABLED': '0'}


def driver_socket_identity(runtime):
    runtime = private_directory(runtime)
    try:
        live = json.loads(read_owned(runtime / 'live.json'))
        peer = socket_identity(runtime / 'cua.sock')
    except FileNotFoundError as exc:
        # Serve publishes its process before the driver binds; the MCP client retries readiness.
        raise ValueError('no Cua Driver daemon listening on the enrolled guest socket yet') from exc
    if (peer['peer_pid'], peer['peer_start']) != (live['pid'], live['start']):
        raise ValueError('Guest driver socket peer was replaced')
    pin = runtime / 'socket.json'
    try:
        write_new(pin, json.dumps(peer).encode())
    except FileExistsError:
        pass
    if json.loads(read_owned(pin)) != peer:
        raise ValueError('Guest driver socket inode was replaced')
    return peer


def invoke(payload, *, serving=False, inspect_only=False):
    guest = payload['guest']
    assets = attest(guest)
    key = payload['key']
    if not re.fullmatch(r'hc-[0-9a-f]{12}\.sock', key):
        raise ValueError('Invalid CUA socket mapping')
    runtime = assets / ('d-' + key[3:15])
    args = [str(runtime / 'cua.sock') if arg == '@SOCKET@' else
            str(runtime / 'manifest.json') if arg == '@MANIFEST@' else arg for arg in payload['args']]
    driver = str(assets / 'cua-driver')
    env = driver_env(guest, assets)
    if serving:
        if args[0] != 'serve':
            raise ValueError('Invalid supervisor invocation')
        runtime.mkdir(mode=0o700)
        if payload['manifest'] is not None:
            data = base64.b64decode(payload['manifest'], validate=True)
            if digest(data) != payload['manifest_sha256']:
                raise ValueError('Approved capability manifest checksum mismatch')
            write_new(runtime / 'manifest.json', data)
            if digest(read_owned(runtime / 'manifest.json')) != payload['manifest_sha256']:
                raise ValueError('Approved capability manifest changed')
        base = runpy.run_path(str(assets / 'vm_driver_lifetime.py'))['GuestDriverSupervisor']
        class WitnessedSupervisor(base):
            def _monitor(self, selector, control_fd, process):
                write_new(runtime / 'live.json', json.dumps({'pid': process.pid,
                          'start': process_start(process.pid)}).encode())
                return super()._monitor(selector, control_fd, process)
        supervise(driver, str(runtime), args, env, supervisor_class=WitnessedSupervisor)
        return 0
    driver_socket_identity(runtime)
    if inspect_only:
        return 0
    if args[0] not in {'status', 'mcp', 'call'}:
        raise ValueError('Invalid guest driver verb')
    os.execve(driver, [driver, *args], env)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if args[0] == 'stage':
            return stage(args[1], args[2])
        if args[0] == 'attest':
            attest(json.loads(args[1]))
            return 0
        if args[0] not in {'serve', 'invoke', 'inspect'}:
            raise ValueError('Invalid guest CUA operation')
        return invoke(json.loads(args[1]), serving=args[0] == 'serve', inspect_only=args[0] == 'inspect')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('Guest CUA: ' + str(exc), file=sys.stderr)
        return 125


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):  # windows-footgun: ok — runtime package rejects non-Linux hosts
        raise ValueError('Guest CUA runtime ownership changed')
    return path


def supervise(driver, runtime, args, env, *, supervisor_class, timeouts=None):
    """Only publish retirement after the exact Popen was waited and files removed."""
    runtime = private_directory(runtime)
    owner = runtime.stat()
    supervisor = supervisor_class([driver, *args], env=env, cwd=str(runtime),
                                  stop_argv=[driver, 'stop', '--socket', str(runtime / 'cua.sock')],
                                  **(timeouts or {}))
    result = supervisor.run(control_fd=0)
    current = private_directory(runtime).stat()
    if (owner.st_dev, owner.st_ino) != (current.st_dev, current.st_ino):
        raise ValueError('Guest CUA runtime was replaced during retirement')
    shutil.rmtree(runtime)
    result['cleaned'] = not runtime.exists()
    print(json.dumps(result), flush=True)
    return result
