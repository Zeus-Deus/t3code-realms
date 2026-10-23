"""Private immutable payloads for children that outlive a plugin snapshot."""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from .config import effective_home, private_directory
from .lifecycle import OwnershipError, RealmError, alive


def _directory(info, path):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise OwnershipError('runtime copy directory ownership or mode changed: ' + str(path))


def _contents(package, *, private=False):
    """Read through directory FDs: neither files nor directories may redirect."""
    entries = {}

    def visit(descriptor, prefix):
        for name in sorted(os.listdir(descriptor)):
            relative = prefix / name
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    if private:
                        _directory(os.fstat(child), relative)
                    entries[relative.as_posix()] = None
                    visit(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                with os.fdopen(child, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(opened.st_mode) or private and
                            (opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o600)):
                        raise OwnershipError('runtime copy file ownership or mode changed: ' + str(relative))
                    entries[relative.as_posix()] = stream.read()
            else:
                raise OwnershipError('runtime package contains a symlink or special file: ' + str(relative))

    try:
        package = Path(package)
        for path in (*reversed(package.parents), package):
            if path.is_symlink():
                raise OwnershipError('runtime package path contains a symlink')
        descriptor = os.open(package, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if private:
                _directory(os.fstat(descriptor), package)
            visit(descriptor, Path())
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OwnershipError('runtime package unavailable: ' + str(package)) from exc
    if '__init__.py' not in entries or 'cli.py' not in entries:
        raise OwnershipError('runtime package is incomplete')
    return entries


def _digest(entries):
    digest = hashlib.sha256()
    for name, value in sorted(entries.items()):
        encoded = name.encode('utf-8')
        digest.update(len(encoded).to_bytes(8, 'big'))
        digest.update(encoded)
        digest.update(b'd' if value is None else b'f')
        if value is not None:
            digest.update(len(value).to_bytes(8, 'big'))
            digest.update(value)
    return digest.hexdigest()


def runtime_reference(home, value):
    root = effective_home(home) / 'runtime'
    if (not isinstance(value, str) or Path(value).parent != root
            or not re.fullmatch('[0-9a-f]{64}', Path(value).name)
            or str(Path(value)) != value):
        raise OwnershipError('invalid stable runtime copy reference')
    return Path(value)


class RuntimeStore:
    def __init__(self, home):
        self.home = effective_home(home)
        self.root = private_directory(self.home / 'runtime')

    @contextmanager
    def lock(self, *, blocking=True):
        # Always outermost: publication of a reference and pruning are atomic
        # with respect to each other, including concurrent plugin invocations.
        descriptor = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise OwnershipError('runtime store lock ownership changed')
            fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield
        finally:
            os.close(descriptor)

    def reference(self, value):
        return runtime_reference(self.home, value)

    def verify(self, value):
        path = self.reference(value)
        try:
            _directory(path.lstat(), path)
            if sorted(os.listdir(path)) != ['t3realms']:
                raise OwnershipError('runtime copy has unexpected contents')
            if _digest(_contents(path / 't3realms', private=True)) != path.name:
                raise OwnershipError('runtime copy contents hash changed')
        except OSError as exc:
            raise OwnershipError('runtime copy unavailable: ' + str(path)) from exc
        return path

    def materialize(self):
        entries = _contents(Path(__file__).absolute().parent)
        target = self.root / _digest(entries)
        if target.exists() or target.is_symlink():
            return self.verify(str(target))
        temporary = Path(tempfile.mkdtemp(prefix='.prepare-', dir=self.root))
        try:
            package = private_directory(temporary / 't3realms')
            for name, value in entries.items():
                path = package / name
                if value is None:
                    private_directory(path)
                else:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(descriptor, 'wb') as stream:
                        stream.write(value)
                        stream.flush()
                        os.fsync(stream.fileno())
            os.rename(temporary, target)
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return self.verify(str(target))

    def prune(self):
        from .lifecycle import Registry, scope_info
        from .jobs import Jobs, TERMINAL

        protected = {Path(__file__).absolute().parents[1]}
        if (self.home / 'realms').exists():
            registry = Registry(self.home)
            with registry.lock(blocking=False):
                for record in registry.records():
                    value = record.get('runtime_copy')
                    if value is None:
                        continue
                    path = self.reference(value)
                    keep = record['status'] not in ('stopped', 'deleted') or alive(record.get('supervisor'))
                    if not keep:
                        # ExecStopPost may still be pending after the scope and
                        # supervisor exit. A failed query must retain its code.
                        try:
                            keep = scope_info(record['guardian_unit'])['ActiveState'] not in ('inactive', 'failed')
                        except RealmError:
                            keep = True
                    if keep:
                        protected.add(path)
        if (self.home / 'jobs').exists():
            jobs = Jobs(self.home)
            with jobs.lock(blocking=False):
                for file in jobs.root.glob('*.json'):
                    record = jobs.get(file.stem)
                    value = record.get('runtime_copy')
                    if value is not None and (record['state'] not in TERMINAL or alive(record.get('process'))):
                        protected.add(self.reference(value))
        removed = []
        for path in self.root.iterdir():
            if not re.fullmatch('[0-9a-f]{64}', path.name) or path in protected:
                continue
            # Refuse redirected, injected, or tampered trees instead of trying
            # to repair them or recursively removing unverified contents.
            self.verify(str(path))
            shutil.rmtree(path)
            removed.append(str(path))
        return removed


@contextmanager
def pinned_runtime(home, existing=None):
    store = RuntimeStore(home)
    with store.lock():
        yield store.verify(existing) if existing is not None else store.materialize()


def prune_runtime(home):
    if not (Path(home) / 'runtime').exists():
        return []
    store = RuntimeStore(home)
    try:
        # Startup can hold the registry lock while waiting for a desktop.
        # GC is opportunistic and must not delay detached-job admission.
        with store.lock(blocking=False):
            return store.prune()
    except BlockingIOError:
        return []
