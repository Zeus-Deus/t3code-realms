# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Durable VM data receipts, independent of ephemeral compute ownership.

These detect accidental replacement, not a hostile same-UID administrator.
Mutable overlay/firmware are inode-bound; immutable spec/base metadata and the
SSH pin are sealed. Incomplete legacy work is retained, never auto-recreated.

Receipts never record ``st_dev``: the kernel numbers btrfs subvolumes, device
mapper and NVMe devices at mount/probe time, so it changes across reboots for
the same file. Each object is instead required to live on the same filesystem
as its directory (no mount point standing in for it), and is bound by inode.
Older receipts that recorded a device number are compared without it.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

from .config import Config
from .lifecycle import OwnershipError


def _file(path, *, mutable=False, large=False):
    if path.resolve() != path:
        raise OwnershipError("VM workspace path redirects through a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not info.st_size:  # windows-footgun: ok — runtime package rejects non-Linux hosts
            raise OwnershipError("VM workspace file is missing, empty or foreign")
        if info.st_dev != os.lstat(path.parent).st_dev:
            raise OwnershipError("VM workspace file is a mount point, not part of its directory")
        result: dict[str, int | str] = {"inode": info.st_ino}
        if not mutable:
            result.update(size=info.st_size, mtime_ns=info.st_mtime_ns)
            if not large:
                if info.st_size > 2 * 1024 * 1024:
                    raise OwnershipError("VM workspace metadata is too large")
                result["sha256"] = hashlib.sha256(os.read(fd, info.st_size + 1)).hexdigest()
        return result
    finally:
        os.close(fd)


def _identity(receipt):
    """A stored receipt without the boot-unstable device number of older versions."""
    if not isinstance(receipt, dict):
        return receipt
    return {key: value for key, value in receipt.items() if key != "device"}


def _same(current, receipt):
    return _identity(current) == _identity(receipt)


def _same_base(base, receipt):
    if not isinstance(receipt, dict) or set(receipt) != {"disk", "metadata"}:
        return False
    return (_same(_file(base, large=True), receipt["disk"])
            and _same(_file(base.parent / "base.json"), receipt["metadata"]))


def _binding(record):
    from .vm_manager import validate_vm_record
    validate_vm_record(record)
    from .vm_base import dependency
    dependency(Path(record["home"]), record.get("base_disk", ""))
    session = Path(record["session_dir"])
    info = session.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:  # windows-footgun: ok — runtime package rejects non-Linux hosts
        raise OwnershipError("VM workspace directory ownership changed")
    if info.st_dev != session.parent.lstat().st_dev:
        raise OwnershipError("VM workspace directory is a mount point")
    return {key: record[key] for key in ("id", "generation", "uid", "home", "session_id", "session_dir", "base_disk")}


def create(record):
    binding = _binding(record)
    session = Path(record["session_dir"])
    base = Path(record["base_disk"])
    record["workspace"] = {
        "version": 1, "binding": binding,
        "files": {name: _file(session / name, mutable=name != "spec.json")
                  for name in ("disk.qcow2", "OVMF_VARS.4m.fd", "spec.json")},
        "base": {"disk": _file(base, large=True), "metadata": _file(base.parent / "base.json")},
    }


def retain_pin(record):
    from .vm_ssh import require_host_key
    source = require_host_key(record)
    pin = _file(source)
    destination = Path(record["session_dir"]) / "ssh_known_hosts"
    # Exclusive creation: never overwrite a previous enrolled identity.
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if _file(destination)["sha256"] != pin["sha256"]:
            raise OwnershipError("VM retained SSH pin differs from the enrolled key")
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(source.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
    directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if isinstance(record.get("workspace"), dict):
        record["workspace"]["pin"] = _file(destination)


def validate(record, *, allow_unlaunched=False):
    try:
        binding = _binding(record)
        receipt = record.get("workspace")
        if not isinstance(receipt, dict) or receipt.get("version") != 1 or receipt.get("binding") != binding:
            raise OwnershipError("VM workspace has no complete bound recovery receipt")
        session = Path(record["session_dir"])
        for name in ("disk.qcow2", "OVMF_VARS.4m.fd", "spec.json"):
            if not _same(_file(session / name, mutable=name != "spec.json"), receipt["files"][name]):
                raise OwnershipError("VM retained workspace file changed: " + name)
        if not _same_base(Path(record["base_disk"]), receipt["base"]):
            raise OwnershipError("VM retained base dependency changed")
        if not allow_unlaunched:
            if not _same(_file(session / "ssh_known_hosts"), receipt.get("pin")):
                raise OwnershipError("VM retained SSH pin changed or was never enrolled")
            if stat.S_IMODE((session / "ssh_known_hosts").stat().st_mode) != 0o600:
                raise OwnershipError("VM retained SSH pin permissions changed")
        elif record.get("ssh_host_key_pinned") or receipt.get("pin"):
            raise OwnershipError("A previously enrolled VM cannot be treated as unlaunched")
        config = Config(**json.loads((session / "spec.json").read_text(encoding="utf-8")))
        if (config.vm.memory, config.vm.network) != (record["memory"], record["network"]):
            raise OwnershipError("VM retained resource receipt differs from frozen spec")
        return config
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise OwnershipError("VM workspace metadata is incomplete; recovery required") from exc


def _directory(path):
    if path.resolve() != path:
        raise OwnershipError("VM deletion directory redirects through a symlink")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:  # windows-footgun: ok — runtime package rejects non-Linux hosts
        raise OwnershipError("VM deletion directory ownership changed")
    if info.st_dev != os.lstat(path.parent).st_dev:
        raise OwnershipError("VM deletion directory is a mount point")
    return {"inode": info.st_ino}


def begin_deletion(record):
    validate(record)
    record["deletion"] = {
        "version": 1,
        "workspace_sha256": hashlib.sha256(json.dumps(record["workspace"], sort_keys=True).encode()).hexdigest(),
        "directories": {key: _directory(Path(record[key])) for key in ("runtime_dir", "session_dir")},
    }


def validate_deletion(record):
    """Only already-authorized missing files are tolerated, never replacements."""
    from .vm_manager import validate_vm_record
    validate_vm_record(record)
    try:
        intent, receipt = record["deletion"], record["workspace"]
        if (intent["version"] != 1
                or intent["workspace_sha256"] != hashlib.sha256(json.dumps(receipt, sort_keys=True).encode()).hexdigest()
                or receipt["binding"] != {key: record[key] for key in receipt["binding"]}):
            raise OwnershipError("VM deletion receipt binding changed")
        for key in ("runtime_dir", "session_dir"):
            current = _directory(_present(Path(record[key])))
            if current is not None and not _same(current, intent["directories"][key]):
                raise OwnershipError("VM deletion directory was replaced")
        session = _present(Path(record["session_dir"]))
        for name, expected in {**receipt["files"], "ssh_known_hosts": receipt["pin"]}.items():
            if name not in {"disk.qcow2", "OVMF_VARS.4m.fd", "spec.json", "ssh_known_hosts"}:
                raise OwnershipError("VM deletion file receipt changed")
            try:
                current = _file(session / name, mutable=name in {"disk.qcow2", "OVMF_VARS.4m.fd"})
            except FileNotFoundError:
                continue
            if not _same(current, expected):
                raise OwnershipError("VM deletion file was replaced: " + name)
            if name == "ssh_known_hosts" and stat.S_IMODE((session / name).stat().st_mode) != 0o600:
                raise OwnershipError("VM retained SSH pin permissions changed")
        if not _same_base(Path(record["base_disk"]), receipt["base"]):
            raise OwnershipError("VM retained base dependency changed")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise OwnershipError("VM deletion receipt is incomplete; explicit recovery required") from exc


def _contents(session):
    """Top-level entries of a workspace being discarded, without following links."""
    entries = []
    with os.scandir(session) as scan:
        for entry in scan:
            info = entry.stat(follow_symlinks=False)
            kind = ("d" if stat.S_ISDIR(info.st_mode) else "f" if stat.S_ISREG(info.st_mode)
                    else "l" if stat.S_ISLNK(info.st_mode) else "o")
            entries.append([entry.name, kind, info.st_ino, info.st_size, info.st_mtime_ns])
    return sorted(entries)


def begin_discard(record):
    """Bind an owner-confirmed discard of a workspace whose receipt cannot verify.

    There is no trustworthy file receipt to check, so the confirmation binds the
    exact directories and every top-level entry seen at review instead. Any
    change before the deletion runs revokes it.
    """
    from .vm_manager import validate_vm_record
    validate_vm_record(record)
    directories = {key: _directory(Path(record[key])) for key in ("runtime_dir", "session_dir")}
    # A workspace already removed by other means leaves only its record; the
    # discard then removes just that record, under the same compute checks.
    contents = [] if directories["session_dir"] is None else _contents(Path(record["session_dir"]))
    # A VM workspace holds only regular files. A directory, link or device in
    # it is not something this tool created; inspect it by hand instead.
    for name, kind, *_ in contents:
        if kind != "f":
            raise OwnershipError("VM workspace holds an unexpected non-file entry: " + name)
    record["deletion"] = {"version": 1, "discard": True, "directories": directories,
                          "contents": contents}


def validate_discard(record):
    """An interrupted discard may only have removed entries, never gained or changed one."""
    from .vm_manager import validate_vm_record
    validate_vm_record(record)
    try:
        intent = record["deletion"]
        if intent["version"] != 1 or intent.get("discard") is not True:
            raise OwnershipError("VM deletion is not an owner-confirmed discard")
        for key in ("runtime_dir", "session_dir"):
            current = _directory(_present(Path(record[key])))
            if current is not None and not _same(current, intent["directories"][key]):
                raise OwnershipError("VM deletion directory was replaced")
        session = _present(Path(record["session_dir"]))
        if _directory(session) is not None:
            recorded = {entry[0]: entry for entry in intent["contents"]}
            for entry in _contents(session):
                if recorded.get(entry[0]) != entry:
                    raise OwnershipError("VM discarded workspace gained or changed an entry: " + entry[0])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise OwnershipError("VM discard receipt is incomplete; explicit recovery required") from exc


def remove_directory(path, bound):
    """Remove a verified deletion directory with no gap between check and removal.

    The directory is renamed to a tombstone beside it and the tombstone is
    checked against the inode bound at review, so what was checked is exactly
    what is removed. A directory swapped in after verification is renamed back
    and kept. A tombstone left by an interrupted removal is finished on retry
    under the same check.
    """
    tombstone = _tombstone(path)
    if os.path.lexists(path):
        if bound is None or os.path.lexists(tombstone):
            raise OwnershipError("VM deletion directory was replaced")
        os.rename(path, tombstone)
        try:
            _bound_tombstone(tombstone, bound)
        except OwnershipError:
            os.rename(tombstone, path)
            raise
    elif os.path.lexists(tombstone):
        _bound_tombstone(tombstone, bound)
    else:
        return
    shutil.rmtree(tombstone)


def _tombstone(path):
    return path.with_name("." + path.name + ".deleting")


def _present(path):
    """The directory a deletion still has to remove: itself, or its tombstone."""
    tombstone = _tombstone(path)
    return tombstone if not os.path.lexists(path) and os.path.lexists(tombstone) else path


def _bound_tombstone(tombstone, bound):
    if bound is None or not _same(_directory(tombstone), bound):
        raise OwnershipError("VM deletion directory was replaced")


def restore_pin(record):
    validate(record)
    source = Path(record["session_dir"]) / "ssh_known_hosts"
    destination = Path(record["runtime_dir"]) / "ssh_known_hosts"
    with destination.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(source.read_bytes())
        stream.flush()
        os.fsync(stream.fileno())
