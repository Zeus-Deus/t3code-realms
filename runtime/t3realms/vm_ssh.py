# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Generation-local SSH host-key trust; never borrow a global known-hosts file."""
import os
from pathlib import Path
import stat
import subprocess
import time

from .lifecycle import OwnershipError, scope_info


def ssh_options(record, *, enroll=False):
    return [
        "-F", "/dev/null", "-i", str(Path.home() / ".ssh" / "id_ed25519"),
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=" + ("accept-new" if enroll else "yes"),
        "-o", "UserKnownHostsFile=" + str(Path(record["runtime_dir"]) / "ssh_known_hosts"),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "HostKeyAlias=t3code-omarchy-guest",
        "-o", "UpdateHostKeys=no",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ForwardX11Trusted=no",
        "-o", "IdentitiesOnly=yes",
    ]


def require_host_key(record):
    path = Path(record["runtime_dir"]) / "ssh_known_hosts"
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise OwnershipError("VM SSH host-key pin is missing; refusing to trust a replacement endpoint") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
            or info.st_mode & 0o777 != 0o600 or info.st_size == 0):
        raise OwnershipError("VM SSH host-key pin has invalid ownership, permissions or contents")
    return path


def _owned_unit_running(record):
    from .vm_manager import validate_vm_record

    validate_vm_record(record)
    info = scope_info(record["unit"])
    if info.get("ActiveState") in ("inactive", "failed"):
        return False
    if not record.get("invocation_id") or info.get("InvocationID") != record["invocation_id"]:
        raise OwnershipError("VM shutdown refused: live invocation is not the owned guest")
    return True


def shutdown_guest(record, argv):
    """Never reuse the installer's pre-enrollment SSH policy for shutdown."""
    if not _owned_unit_running(record):
        return
    result = None
    try:
        require_host_key(record)
        result = subprocess.run([*argv, "--", "poweroff"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=15)
    except (OwnershipError, OSError, subprocess.SubprocessError):
        # Missing pins or failed authentication do not authorize another peer.
        # The caller can still retire the validated owned systemd invocation.
        pass
    if result is not None and result.returncode == 0:
        deadline = time.monotonic() + 30
        while _owned_unit_running(record) and time.monotonic() < deadline:
            time.sleep(0.2)
    # A replacement/unknown invocation must retain its record and files, even
    # if the preceding SSH attempt was unsuccessful.
    _owned_unit_running(record)


def enroll_host_key(record):
    """TOFU only during owned launch/legacy adoption, never ordinary tool calls.

    This pins the endpoint reached during that lifecycle transaction. It is not
    an out-of-band identity proof or protection against a hostile same-UID host.
    """
    from .vm_manager import validate_vm_record

    validate_vm_record(record)
    info = scope_info(record["unit"])
    if info.get("ActiveState") != "active" or (
            record.get("invocation_id") and info.get("InvocationID") != record["invocation_id"]):
        raise OwnershipError("Cannot enroll an SSH key for an unowned VM invocation")
    path = Path(record["runtime_dir"]) / "ssh_known_hosts"
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        require_host_key(record)
    try:
        subprocess.run(
            ["ssh", "-p", str(record["ssh_port"]), "-T", *ssh_options(record, enroll=fd is not None),
             "root@127.0.0.1", "--", "true"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        require_host_key(record)
    except (OwnershipError, OSError, subprocess.SubprocessError) as exc:
        if fd is not None:
            # Keep the created inode open until cleanup so it cannot be recycled
            # for a replacement. Never erase a key learned before auth failed.
            original = os.fstat(fd)
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino, current.st_size) == (original.st_dev, original.st_ino, 0):
                    path.unlink()
            except FileNotFoundError:
                pass
        raise OwnershipError("Could not enroll or verify the owned VM SSH host key") from exc
    finally:
        if fd is not None:
            os.close(fd)
