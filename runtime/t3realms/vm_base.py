# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Physical immutable VM bases and the profile's atomic allocation selection.

Legacy bases stay in place. Selection never moves/rebases a workspace dependency.
Publication is serialized by the manager's existing registry lock.
"""
import json
import os
from pathlib import Path
import re
import stat

from .config import vm_data_path
from .lifecycle import OwnershipError


def validate_release(release):
    if not isinstance(release, str) or not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", release
    ):
        raise ValueError("invalid Omarchy release; expected a literal stable version such as 4.0.3")
    return release


def read_json(path):
    from .vm_workspace import _file
    _file(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 2 * 1024 * 1024:  # windows-footgun: ok — runtime package rejects non-Linux hosts
            raise OwnershipError("Invalid VM base metadata")
        value = json.loads(os.read(fd, 2 * 1024 * 1024 + 1))
        if not isinstance(value, dict):
            raise OwnershipError("Invalid VM base metadata")
        return value
    finally:
        os.close(fd)


def dependency(home, disk):
    """Accept literal legacy paths or generation-bound physical directories only."""
    from .setup_plan import confined
    if str(Path(disk)) != str(disk):
        raise OwnershipError("VM base dependency must use its literal physical path")
    data, disk = vm_data_path(home), Path(disk)
    legacy = data / "base" / "disk.qcow2"
    if str(disk) != str(legacy):
        generation = disk.parent.name
        if (not re.fullmatch(r"[0-9a-f]{32}", generation)
                or disk != data / "bases" / generation / "disk.qcow2"):
            raise OwnershipError("VM base dependency is outside this profile")
        if read_json(disk.parent / "base.json").get("generation") != generation:
            raise OwnershipError("VM base generation metadata changed")
    try:
        return confined(home, disk)
    except (ValueError, OSError) as exc:
        raise OwnershipError("VM base dependency ownership changed") from exc


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_assets(base):
    from .vm_workspace import _file
    for name in ("disk.qcow2", "OVMF_VARS.4m.fd", "credentials", "cidata.img"):
        path = base / name
        if name in {"credentials", "cidata.img"} and not path.exists():
            continue
        _file(path, large=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def selection_receipt(home):
    """Compare-and-select token; also fences replacement at the legacy path."""
    from .vm_workspace import _file
    base = selected(home)
    receipts = {}
    for path in (vm_data_path(home) / "current-base.json", base / "base.json"):
        try:
            receipts[str(path)] = _file(path)
        except FileNotFoundError:
            receipts[str(path)] = None
    return str(base), receipts


def selected(home):
    from .setup_plan import confined
    data = vm_data_path(home)
    pointer = confined(home, data / "current-base.json")
    try:
        value = read_json(pointer)
    except FileNotFoundError:
        return confined(home, data / "base")
    generation = value.get("generation")
    if (value.get("version") != 1 or value.get("home") != str(home)
            or value.get("uid") != os.getuid() or not isinstance(generation, str)  # windows-footgun: ok — runtime package rejects non-Linux hosts
            or not re.fullmatch(r"[0-9a-f]{32}", generation)):
        raise OwnershipError("VM current base selection ownership changed")
    return dependency(home, data / "bases" / generation / "disk.qcow2").parent
