"""Receipt-bound regular driver children and same-generation endpoint reuse."""
from contextlib import contextmanager, nullcontext
import errno
import fcntl
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess

from .lifecycle import (BusyError, OwnershipError, alive, atomic_json, identity,
                        private_json, valid_identity)


def _current(manager, record):
    current = manager.record(record['id'])
    keys = ('id', 'generation', 'runtime_dir', 'session_id', 'home', 'uid',
            'runtime_copy', 'python_executable', 'invocation_id', 'cgroup')
    if (current['status'] != 'running'
            or any(current.get(key) != record.get(key) for key in keys)
            or not alive(current.get('supervisor'))):
        raise OwnershipError('Realm driver compute incarnation stopped or changed')


def _receipt_path(endpoint):
    return endpoint.with_name('.' + endpoint.name + '.owner.json')


def _stop_owner(process, *, cgroup):
    if not isinstance(cgroup, str) or not cgroup.startswith('/') or cgroup == '/':
        raise OwnershipError('Realm driver cgroup receipt is unavailable; retry Stop')
    try:
        fd = os.pidfd_open(process['pid'])
    except ProcessLookupError:
        return
    try:
        current = identity(process['pid'])
        if current is None:
            return
        if current != process:
            raise OwnershipError('Realm driver supervisor identity changed; retry Stop')
        try:
            membership = Path(f"/proc/{process['pid']}/cgroup").read_text(encoding='utf-8').strip()
        except OSError as exc:
            raise OwnershipError('Realm driver cgroup is unavailable; retry Stop') from exc
        if membership != '0::' + cgroup:
            raise OwnershipError('Realm driver supervisor left its owned cgroup; retry Stop')
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        except ProcessLookupError:
            return
        if not select.select([fd], [], [], 5)[0]:
            raise BusyError('Realm driver retirement is unconfirmed; retry Stop')
    finally:
        os.close(fd)


def stop_driver(manager, record):
    """Retire the native receipt's daemon, independent of caller job tracking."""
    endpoint = Path(record['runtime_dir']) / 'cua-driver.sock'
    path = _receipt_path(endpoint)
    if record['status'] == 'stopped' and not Path(record['runtime_dir']).exists():
        return {'retired': True}
    _current(manager, record)
    if path.exists() or path.is_symlink():
        receipt = private_json(path)
        if (not isinstance(receipt, dict) or receipt.get('id') != record['id']
                or receipt.get('generation') != record['generation']
                or not valid_identity(receipt.get('process'))):
            raise OwnershipError('Realm driver ownership receipt changed; retry Stop')
        parent = receipt.get('supervisor')
        if parent is not None:
            if not valid_identity(parent):
                raise OwnershipError('Realm driver supervisor receipt changed; retry Stop')
            _stop_owner(parent, cgroup=record.get('cgroup'))
        if alive(receipt['process']):
            raise OwnershipError('Realm driver retirement is unconfirmed; retry Stop')
    # The same lock excludes startup and validates a dead listener/inode before
    # unlink. Missing receipts or a concurrent replacement never mean retired.
    with serve_guard(manager, record, endpoint):
        return {'retired': True}


def _prepare_endpoint(record, endpoint):
    info = None
    try:
        info = endpoint.lstat()
    except FileNotFoundError:
        pass
    if info is not None and (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()):
        raise OwnershipError('Realm driver endpoint ownership changed; retry Stop')
    path = _receipt_path(endpoint)
    if info is None and not path.exists() and not path.is_symlink():
        return
    receipt = private_json(path)
    if (not isinstance(receipt, dict) or receipt.get('id') != record['id'] or receipt.get('generation') != record['generation']
            or not valid_identity(receipt.get('process')) or alive(receipt['process'])):
        raise OwnershipError('Realm driver retirement is unconfirmed; retry Stop')
    if info is None:
        return
    # The daemon runs in a different network namespace, so the host's
    # /proc/net/unix cannot prove listener absence. Probe the filesystem socket.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(.2)
        try:
            probe.connect(str(endpoint))
        except OSError as exc:
            if exc.errno != errno.ECONNREFUSED:
                raise OwnershipError('Realm driver endpoint retirement is unconfirmed; retry Stop') from exc
        else:
            raise OwnershipError('Realm driver endpoint still has a listener; retry Stop')
    current = endpoint.lstat()
    if (current.st_dev, current.st_ino, current.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_ctime_ns):
        raise OwnershipError('Realm driver endpoint changed during retirement; retry Stop')
    endpoint.unlink()


@contextmanager
def serve_guard(manager, record, endpoint):
    endpoint = Path(endpoint)
    if endpoint.parent != Path(record['runtime_dir']):
        raise OwnershipError('Realm driver endpoint is not private to this generation')
    lock = endpoint.with_name('.' + endpoint.name + '.lock')
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise OwnershipError('Realm driver endpoint lock ownership changed')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BusyError('Realm driver is already serving or retiring') from exc
        with manager.registry.lock():
            current = manager.registry.get(record['id'])
            if current['generation'] != record['generation'] or current['status'] != 'running':
                raise OwnershipError('Realm driver compute incarnation changed')
            _prepare_endpoint(record, endpoint)
        yield
    finally:
        os.close(fd)


def _retire(child, process):
    if child.poll() is not None:
        return
    if (identity(child.pid) != process or os.getpgid(child.pid) != child.pid
            or os.getsid(child.pid) != child.pid):
        raise OwnershipError('Realm driver child process identity changed; retirement unconfirmed')
    try:
        os.killpg(child.pid, signal.SIGTERM)
        child.wait(timeout=3)
    except ProcessLookupError:
        child.wait()
    except subprocess.TimeoutExpired:
        if identity(child.pid) != process:
            raise OwnershipError('Realm driver child identity changed before forced retirement')
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()


class _Stopped(BaseException):
    def __init__(self, number):
        self.number = number


def run_contained(manager, record, command, env, *, endpoint=None):
    """Keep stdio intact while retiring MCP/bwrap when its Realm lease ends.

    The wrapper owns a separate child process group. A terminal-job signal
    reaches this wrapper; forwarding and reaping complete before it exits.
    """
    def stopped(number, _frame):
        raise _Stopped(number)

    previous = {number: signal.signal(number, stopped) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        with serve_guard(manager, record, endpoint) if endpoint is not None else nullcontext():
            child = None
            process = None
            try:
                _current(manager, record)
                child = subprocess.Popen(command, env=env, close_fds=True, start_new_session=True)
                process = identity(child.pid)
                if process is None:
                    return child.wait()
                if endpoint is not None:
                    atomic_json(_receipt_path(Path(endpoint)), {
                        'id': record['id'], 'generation': record['generation'], 'process': process,
                        'supervisor': identity(os.getpid())})
                while True:
                    try:
                        return child.wait(timeout=.5)
                    except subprocess.TimeoutExpired:
                        _current(manager, record)
            finally:
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
                try:
                    if child is not None and process is not None:
                        _retire(child, process)
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    except _Stopped as exc:
        return 128 + exc.number
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
