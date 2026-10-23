# Adapted from Hermes Realms 0.2.0 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Durable private HOME binding; registry records remain the lifecycle authority."""
import json
import os
from pathlib import Path
import stat

from .lifecycle import OwnershipError, atomic_json


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:  # windows-footgun: ok — runtime package rejects non-Linux hosts
        raise OwnershipError("workspace directory ownership or permissions changed")


def binding(record):
    return {key: record[key] for key in ("id", "session_id", "uid", "home")}


def location(record):
    return Path(record["home"]) / "realms" / "workspaces" / record["id"]


def validate(record):
    root = location(record)
    if record.get("workspace_dir") != str(root):
        raise OwnershipError("workspace path ownership mismatch")
    if record.get("status") == "deleting":
        return validate_deletion(record)
    try:
        for path in (root.parent, root, root / "home"):
            directory(path)
        receipt = root / "owner.json"
        info = receipt.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:  # windows-footgun: ok — runtime package rejects non-Linux hosts
            raise OwnershipError("workspace receipt ownership changed")
        if json.loads(receipt.read_text(encoding="utf-8")) != binding(record):
            raise OwnershipError("workspace owner binding changed")
    except (OSError, ValueError) as exc:
        raise OwnershipError("workspace unavailable; retain data for recovery") from exc
    return root


def deletion_binding(record):
    return dict(binding(record), generation=record["generation"])


def begin_deletion(record):
    root = validate(record)
    # The registry is the durable authority once these exact objects disappear.
    objects = {}
    for name in (".", "home", "owner.json"):
        info = (root / name).lstat()
        objects[name] = [info.st_dev, info.st_ino]
    return dict(record, status="deleting", deletion={
        "binding": deletion_binding(record), "objects": objects,
    })


def validate_deletion(record):
    root = location(record)
    authorization = record.get("deletion", {})
    objects = authorization.get("objects", {})
    if (authorization.get("binding") != deletion_binding(record)
            or set(objects) != {".", "home", "owner.json"}
            or any(not isinstance(value, list) or len(value) != 2
                   or any(type(n) is not int or n < 0 for n in value)
                   for value in objects.values())):
        raise OwnershipError("workspace deletion authorization changed")
    try:
        directory(root.parent)
        for name in (".", "home", "owner.json"):
            path = root / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if [info.st_dev, info.st_ino] != objects[name]:
                raise OwnershipError("workspace deletion object identity changed")
            if name == "owner.json":
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or json.loads(path.read_text(encoding="utf-8")) != binding(record)):
                    raise OwnershipError("workspace owner binding changed")
            else:
                directory(path)
    except (OSError, ValueError) as exc:
        raise OwnershipError("workspace deletion unavailable; retain authorization") from exc
    return root


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def finish_deletion(record):
    import shutil

    root = validate(record)
    if root.exists():
        if (root / "home").exists():
            shutil.rmtree(root / "home")
        (root / "owner.json").unlink(missing_ok=True)
        sync_directory(root)
        # Unknown siblings are not authorized for recursive deletion.
        root.rmdir()
    sync_directory(root.parent)


def create(record):
    root = location(record)
    root.parent.mkdir(mode=0o700, exist_ok=True)
    directory(root.parent)
    root.mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    atomic_json(root / "owner.json", binding(record))
    record["workspace_dir"] = str(root)
    return validate(record)
