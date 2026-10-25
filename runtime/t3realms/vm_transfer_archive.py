# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Stdlib-only, literal-path archive protocol shared by host and VM.

Symlinks are never followed while packing. Extraction is staged and constrained;
selected copies add missing entries, never overwrite different bytes or types.
"""
import io
import errno
import json
import os
from collections import deque
from pathlib import Path, PurePosixPath

import stat
import sys
import tarfile
import tempfile
import uuid

MAX_BYTES = 8 * 1024**3
MAX_ENTRIES = 100_000
CONFLICT_MESSAGE = "Transfer conflict: destination differs or changed during copy; select a new destination."


class TransferConflict(ValueError):
    """A selected copy cannot publish without replacing existing work."""


class LimitedWriter(io.RawIOBase):
    def __init__(self, stream, limit=MAX_BYTES):
        self.stream, self.limit, self.count = stream, limit, 0

    def write(self, data):
        if self.count + len(data) > self.limit:
            raise ValueError("transfer exceeds the 8 GiB archive limit")
        written = self.stream.write(data)
        self.count += written
        return written


def _relative_link(target):
    if target.startswith('/'):
        raise ValueError("absolute symbolic link is not a workspace-relative link")


def _info(name, info):
    member = tarfile.TarInfo(name)
    member.mode = stat.S_IMODE(info.st_mode) & 0o777
    member.mtime = info.st_mtime
    return member


def pack(source, stream):
    source = Path(source).expanduser()
    if source.is_symlink():
        raise ValueError("top-level symbolic link requires selecting its target explicitly")
    source = source.parent.resolve(strict=True)/source.name
    if not source.name:
        raise ValueError("select a named file or directory, not the filesystem root")
    with tarfile.open(fileobj=LimitedWriter(stream), mode='w|', dereference=False) as archive:
        count = 0
        emitted = []
        def add(name, descriptor, entry=None):
            nonlocal count
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError("transfer has too many entries")
            info = os.fstat(descriptor) if entry is None else os.stat(entry,dir_fd=descriptor,follow_symlinks=False)
            member = _info(name,info)
            if stat.S_ISLNK(info.st_mode):
                if entry is None:
                    raise ValueError("symbolic link cannot be the archive root")
                member.type = tarfile.SYMTYPE
                member.linkname = os.readlink(entry,dir_fd=descriptor)
                _relative_link(member.linkname)
                archive.addfile(member)
                emitted.append(member)
            elif stat.S_ISDIR(info.st_mode):
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
                emitted.append(member)
            elif stat.S_ISREG(info.st_mode):
                fd = os.dup(descriptor) if entry is None else os.open(entry,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=descriptor)
                with os.fdopen(fd,'rb') as data:
                    before = os.fstat(data.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError("transfer source changed type")
                    member = _info(name,before)
                    member.size = before.st_size
                    archive.addfile(member,data)
                    emitted.append(member)
                    after = os.fstat(data.fileno())
                    if (before.st_size,before.st_mtime_ns) != (after.st_size,after.st_mtime_ns):
                        raise ValueError("transfer source changed while being copied")
            else:
                raise ValueError("transfer refuses special files")
        parent_fd = os.open(source.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fd = os.open(source.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        try:
            add(source.name,fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                def fail(error):
                    raise error
                for directory, dirs, files, directory_fd in os.fwalk('.',dir_fd=fd,follow_symlinks=False,onerror=fail):
                    prefix = str(PurePosixPath(source.name)/PurePosixPath(directory))
                    if directory != '.':
                        add(prefix,directory_fd)
                    for name in dirs:
                        if stat.S_ISLNK(os.stat(name,dir_fd=directory_fd,follow_symlinks=False).st_mode):
                            add(prefix+'/'+name,directory_fd,name)
                    for name in files:
                        add(prefix+'/'+name,directory_fd,name)
        finally:
            os.close(fd)
        _link_order(emitted)


def _members(archive):
    members, seen, root, size = [], set(), None, 0
    for member in archive:
        name = member.name
        parts = PurePosixPath(name).parts
        if not parts or name.startswith('/') or any(p in ('','.','..') for p in name.split('/')):
            raise ValueError("invalid archive path")
        if root is None:
            root = name
            if len(parts) != 1 or not (member.isdir() or member.isfile()):
                raise ValueError("invalid archive root")
        if name != root and not name.startswith(root+'/'):
            raise ValueError("archive path escapes its root")
        if name in seen or len(members) >= MAX_ENTRIES:
            raise ValueError("duplicate or excessive archive entries")
        if not (member.isfile() or member.isdir() or member.issym()):
            raise ValueError("archive contains a special file or hard link")
        if member.issym():
            _relative_link(member.linkname)
        size += member.size
        if member.size < 0 or size > MAX_BYTES:
            raise ValueError("archive payload exceeds transfer limit")
        seen.add(name)
        members.append(member)
    if not members:
        raise ValueError("empty transfer archive")
    by_name = {member.name: member for member in members}
    for member in members:
        for parent in PurePosixPath(member.name).parents:
            ancestor = by_name.get(str(parent))
            if ancestor is not None and not ancestor.isdir():
                raise ValueError("archive entry traverses a non-directory member")
    return members


def _link_order(members, destination=None):
    """Resolve original link components, including retained destination links."""
    incoming = {PurePosixPath(member.name).parts[1:]: member for member in members}
    links = {key: member for key, member in incoming.items() if member.issym()}
    dependencies = {}
    for key, member in links.items():
        pending = deque((*key[:-1], *member.linkname.split('/')))
        resolved, followed, used = [], 0, set()
        while pending:
            part = pending.popleft()
            if part in ('', '.'):
                continue
            if part == '..':
                if not resolved:
                    raise ValueError("symbolic link escapes the transfer root")
                resolved.pop()
                continue
            candidate = (*resolved, part)
            entry = incoming.get(candidate)
            target = None
            if entry is not None:
                if entry.issym():
                    target = entry.linkname
                    used.add(candidate)
            elif destination is not None:
                path = destination.joinpath(*candidate)
                try:
                    if stat.S_ISLNK(path.lstat().st_mode):
                        target = os.readlink(path)
                except (FileNotFoundError, NotADirectoryError):
                    pass
            if target is None:
                resolved.append(part)
                continue
            followed += 1
            if followed > 40:
                raise ValueError("symbolic link cycle or excessive chain")
            if target.startswith('/'):
                parts = PurePosixPath(target).parts
                anchor = destination.parts if destination is not None else ()
                if not anchor or parts[:len(anchor)] != anchor:
                    raise ValueError("symbolic link escapes through the merged destination")
                resolved.clear()
                pending.extendleft(reversed(parts[len(anchor):]))
            else:
                pending.extendleft(reversed(target.split('/')))
        dependencies[key] = used
    ordered, complete, visiting = [], set(), set()
    def visit(key):
        if key in complete:
            return
        if key in visiting:
            raise ValueError("symbolic link cycle")
        visiting.add(key)
        for dependency in sorted(dependencies[key]):
            visit(dependency)
        visiting.remove(key)
        complete.add(key)
        ordered.append(links[key])
    for key in links:
        visit(key)
    return ordered



def _directory(path, *, create=True):
    """Open/create the canonical directory chain without following links."""
    path = Path(path).absolute()
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            if name in ('.','..'):
                raise ValueError("invalid destination directory")
            if create:
                try:
                    os.mkdir(name,mode=0o755,dir_fd=fd)
                except FileExistsError:
                    pass
            new = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


def _link_new(source, parent_fd, name, *, source_fd=None):
    info = os.stat(source,dir_fd=source_fd,follow_symlinks=False)
    try:
        os.link(source,name,src_dir_fd=source_fd,dst_dir_fd=parent_fd,follow_symlinks=False)
    except FileExistsError as error:
        raise TransferConflict(f"transfer conflict at {name!r}: destination appeared during copy") from error
    return (info.st_dev,info.st_ino)


def _publish(source, parent_fd, name):
    try:
        return _link_new(source,parent_fd,name)
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
    # Existing destination directories can be separate mounts. Stage the leaf
    # through its already-open parent, never fall back to truncating the target.
    temporary = '.t3realms-transfer-'+uuid.uuid4().hex
    created = False
    try:
        if source.is_symlink():
            os.symlink(os.readlink(source),temporary,dir_fd=parent_fd)
            created = True
        else:
            fd = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent_fd)
            created = True
            with os.fdopen(fd,'wb') as output:
                source_fd = os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
                with os.fdopen(source_fd,'rb') as input_file:
                    info = os.fstat(input_file.fileno())
                    writer = LimitedWriter(output)
                    while data := input_file.read(65536):
                        writer.write(data)
                    os.fchmod(output.fileno(),stat.S_IMODE(info.st_mode)&0o777)
        return _link_new(temporary,parent_fd,name,source_fd=parent_fd)
    finally:
        if created:
            try:
                os.unlink(temporary,dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def _compatible(source, parent_fd, name, *, recursive=False):
    """Preflight the whole selection before publishing any of it."""
    try:
        existing = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
    except FileNotFoundError:
        return False
    incoming = source.lstat()
    conflict = TransferConflict(f"transfer conflict at {name!r}: destination differs; select a new destination")
    if stat.S_IFMT(existing.st_mode) != stat.S_IFMT(incoming.st_mode):
        raise conflict
    if stat.S_ISLNK(incoming.st_mode):
        if os.readlink(name,dir_fd=parent_fd) != os.readlink(source):
            raise conflict
    elif stat.S_ISREG(incoming.st_mode):
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        with os.fdopen(fd,'rb') as current, source.open('rb') as selected:
            before = os.fstat(current.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != incoming.st_size:
                raise conflict
            while data := selected.read(65536):
                if current.read(len(data)) != data:
                    raise conflict
            after = os.fstat(current.fileno())
            if (before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise conflict
    elif stat.S_ISDIR(incoming.st_mode):
        if recursive:
            fd = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
            try:
                for child in source.iterdir():
                    _compatible(child,fd,child.name,recursive=True)
            finally:
                os.close(fd)
    else:
        raise conflict
    return True


def _merge(source, parent_fd, name, *, created_dirs, created, skip_links=False, relative=()):
    relative = (*relative,name)
    existing = _compatible(source,parent_fd,name)
    if source.is_symlink() and skip_links:
        return
    if source.is_symlink() or source.is_file():
        if not existing:
            identity = _publish(source,parent_fd,name)
            created.append((relative,identity,False))
        return
    try:
        os.mkdir(name,mode=0o700,dir_fd=parent_fd)
    except FileExistsError:
        _compatible(source,parent_fd,name)
    else:
        # Journal before opening: descriptor/permission failures must unwind
        # the mkdir too, not strand an apparently successful empty copy.
        info = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        created_dirs.append((source,(info.st_dev,info.st_ino)))
        created.append((relative,(info.st_dev,info.st_ino),True))
    fd = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
    try:
        for child in source.iterdir():
            _merge(child,fd,child.name,skip_links=skip_links,created_dirs=created_dirs,
                   created=created,relative=relative)
    finally:
        os.close(fd)


def _rollback(created, root_fd, error):
    """Remove only this invocation's additions, never a raced replacement."""
    for parts, identity, directory in reversed(created):
        fd = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
            if (info.st_dev,info.st_ino) != identity:
                raise ValueError('destination addition was replaced; left untouched')
            if directory:
                os.rmdir(parts[-1],dir_fd=fd)
            else:
                os.unlink(parts[-1],dir_fd=fd)
        except FileNotFoundError:
            pass
        except (OSError,ValueError) as cleanup_error:
            error.add_note(f"transfer cleanup incomplete at {'/'.join(parts)!r}: {cleanup_error}")
        finally:
            os.close(fd)


def _install(source, target, members, scratch):
    links = _link_order(members,target)
    created_dirs, created = [], []
    fd = _directory(target.parent)
    try:
        _compatible(source,fd,target.name,recursive=True)
        _merge(source,fd,target.name,skip_links=True,created_dirs=created_dirs,created=created)
        # Validated link dependencies are installed before their consumers.
        for member in links:
            relative = PurePosixPath(member.name).parts[1:]
            path = target.joinpath(*relative)
            link_fd = _directory(path.parent,create=False)
            try:
                _merge(scratch/member.name,link_fd,path.name,created=created,created_dirs=created_dirs,
                       relative=(target.name,*relative[:-1]))
            finally:
                os.close(link_fd)
        modes = {scratch/member.name: (member.mode & 0o755)|0o700 for member in members if member.isdir()}
        for directory, identity in reversed(created_dirs):
            path = target/directory.relative_to(source)
            mode_fd = _directory(path,create=False)
            try:
                info = os.fstat(mode_fd)
                if (info.st_dev,info.st_ino) != identity:
                    raise ValueError("new destination directory was replaced")
                os.fchmod(mode_fd,modes.get(directory,0o700))
            finally:
                os.close(mode_fd)
    except BaseException as error:
        _rollback(created,fd,error)
        raise
    finally:
        os.close(fd)


def unpack(stream, destination, *, directory_exact=False):
    destination = Path(destination).expanduser().absolute()
    if destination.is_symlink():
        raise ValueError("destination is a symbolic link")
    # Resolve an explicitly selected parent once, then use no-follow dirfds.
    destination = destination.parent.resolve()/destination.name
    staging_parent = destination if destination.is_dir() else destination.parent
    parent_fd = _directory(staging_parent)
    try:
        with tempfile.TemporaryDirectory(prefix='.t3realms-transfer-',dir=staging_parent) as scratch:
            scratch = Path(scratch)
            with tempfile.TemporaryFile(dir=scratch) as spool:
                writer = LimitedWriter(spool)
                while data := stream.read(65536):
                    writer.write(data)
                spool.seek(0)
                with tarfile.open(fileobj=spool,mode='r:') as archive:
                    members = _members(archive)
                    staged_links = _link_order(members)
                    # Keep data filtering for all payloads. Its lexical symlink
                    # normalization disagrees with real pivot/../../ traversal;
                    # create graph-validated links only after payload extraction.
                    archive.extractall(scratch, members=[m for m in members if not m.issym()], filter='data')
                    for member in staged_links:
                        path = scratch/member.name
                        path.parent.mkdir(parents=True,exist_ok=True)
                        path.symlink_to(member.linkname)
            source = scratch/members[0].name
            target = destination
            if destination.is_dir() and not (source.is_dir() and directory_exact):
                target = destination/source.name
            if target.is_symlink():
                raise ValueError("destination is a symbolic link")
            # Validate existing destination links before publishing any entry.
            for directory, dirs, files in os.walk(source,followlinks=False):
                relative = Path(directory).relative_to(source)
                for name in [*dirs,*files]:
                    candidate = target/relative/name
                    if candidate.is_symlink() and not (Path(directory)/name).is_symlink():
                        raise ValueError("destination contains a symbolic link")
            _install(source,target,members,scratch)
            return str(target)
    finally:
        os.close(parent_fd)


if __name__ == '__main__':
    operation, path = sys.argv[1:3]
    try:
        if operation == 'pack':
            pack(path,sys.stdout.buffer)
        elif operation == 'unpack':
            result = unpack(sys.stdin.buffer,path,directory_exact=True)
            print(json.dumps({'destination':result}))
        else:
            raise SystemExit(2)
    except TransferConflict as error:
        # Incomplete rollback is not an ordinary clean conflict refusal.
        if getattr(error, '__notes__', None):
            raise
        print(json.dumps({'t3realms_transfer_error':'conflict'}),file=sys.stderr)
        raise SystemExit(1)
