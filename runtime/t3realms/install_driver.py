# Adapted from Hermes Realms 0.2.0 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Explicit pinned driver install; never changes the user's global cua-driver."""

import hashlib
from pathlib import Path
import os
import platform
import stat
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = "0.23.2"
ARCHIVE_SHA256 = "478e010d2b0426de9d8a07eb839802daa92137b33cb8affb93b991e91d76ce7e"
BINARY_SHA256 = "2aaad67b996d41cd909e4b7ac2ddd705653e8c7f9958010ac051838b02f64eeb"
URL = f"https://github.com/trycua/cua/releases/download/cua-driver-rs-v{VERSION}/cua-driver-rs-{VERSION}-linux-x86_64.tar.gz"
# The prior native run retained no archive; bound the pinned release to 64 MiB.
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MEMBER = f"cua-driver-rs-{VERSION}-linux-x86_64/cua-driver"


def installed(target):
    target = Path(target)
    try:
        info = target.lstat()
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
            and os.access(target, os.X_OK)
            and hashlib.sha256(target.read_bytes()).hexdigest() == BINARY_SHA256
        )
    except OSError:
        return False


def _execution_identity(target):
    info = Path(target).stat()
    return [BINARY_SHA256, info.st_dev, info.st_ino, info.st_size, info.st_mode,
            info.st_uid, info.st_mtime_ns, info.st_ctime_ns]


def write_receipt(path, data):
    from .lifecycle import atomic_json
    atomic_json(path, data)


def present(target):
    """A which-style presence probe; never reads or executes the binary."""
    target = Path(target).absolute()
    try:
        info = target.lstat()
        return (target.parent.resolve() == target.parent and stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid() and os.access(target, os.X_OK))
    except OSError:
        return False


def receipt_verified(target):
    """For diagnostics, the receipt's inode/ctime binding needs only stat."""
    try:
        target = Path(target).absolute()
        from .lifecycle import private_json
        return present(target) and private_json(target.with_name('.cua-driver-verified.json')) == _execution_identity(target)
    except (OSError, ValueError, RuntimeError):
        return False


def execution_verified(target):
    return installed(target) and receipt_verified(target)


def verify_execution(target):
    target = Path(target).absolute()
    if not installed(target):
        raise ValueError('Pinned Cua driver binary identity is not verified')
    before = _execution_identity(target)
    receipt = target.with_name(".cua-driver-verified.json")
    receipt.unlink(missing_ok=True)
    try:
        result = subprocess.run(
            [str(target), "--version"], capture_output=True, text=True, timeout=20,
            # A setup diagnostic is not consent to vendor product telemetry.
            env={**os.environ, "CUA_DRIVER_RS_TELEMETRY_ENABLED": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Pinned Cua driver cannot run; check runtime libraries and executable filesystem permissions") from exc
    if result.returncode or VERSION not in result.stdout:
        raise ValueError("Pinned Cua driver cannot run; check runtime libraries and executable filesystem permissions")
    if not installed(target) or _execution_identity(target) != before:
        raise ValueError('Pinned Cua driver changed during execution verification')
    write_receipt(receipt, before)


def profile_target(home):
    from .config import driver_path, effective_home

    target = driver_path(home)
    for parent in (target.parent, *target.parent.parents):
        if parent.is_symlink():
            raise ValueError("Realms driver directory must stay within this profile, without symlink redirects")
        if parent.exists():
            info = parent.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():  # windows-footgun: ok — runtime package rejects non-Linux hosts
                raise ValueError("Realms driver directory has unsafe profile ownership")
        if parent == effective_home(home):
            break
    return target


def install_archive(archive, target, *, progress=None):
    archive, target = Path(archive), Path(target).absolute()
    if progress is not None:
        progress("verifying")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Downloaded cua-driver release checksum mismatch")
    if installed(target):
        verify_execution(target)
        return str(target)
    with tarfile.open(archive, "r:gz") as package:
        member = package.getmember(MEMBER)
        if not member.isfile():
            raise ValueError("Driver archive member is not a regular file")
        stream = package.extractfile(member)
        if stream is None:
            raise ValueError("Missing driver archive payload")
        with stream:
            data = stream.read()
    if hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError("Driver binary checksum mismatch")
    if progress is not None:
        progress("preparing")
    from .config import private_directory
    private_directory(target.parent)
    fd, temporary = tempfile.mkstemp(prefix=".driver-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o700)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    if not os.access(target, os.X_OK):
        raise PermissionError(
            "Installed driver is not executable on the target filesystem"
        )
    verify_execution(target)
    return str(target)


def install(*, home, archive=None, progress=None):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise ValueError("This verified binary release is Linux x86_64 only")
    from .config import private_directory
    target = profile_target(home)
    private_directory(target.parent)
    target = Path(target).absolute()
    if archive is not None:
        return install_archive(archive, target, progress=progress)
    if installed(target):
        if progress is not None:
            progress("verifying")
        verify_execution(target)
        return str(target)
    with tempfile.TemporaryDirectory(prefix="t3realms-driver-download-") as directory:
        archive = Path(directory) / "release.tar.gz"
        if progress is not None:
            progress("downloading")
        with (
            urllib.request.urlopen(URL, timeout=60) as response,
            archive.open("wb") as stream,
        ):
            digest = hashlib.sha256()
            total = 0
            while chunk := response.read(min(1024 * 1024, MAX_ARCHIVE_BYTES - total + 1)):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError('Downloaded cua-driver release exceeds size limit')
                digest.update(chunk)
                stream.write(chunk)
            if digest.hexdigest() != ARCHIVE_SHA256:
                raise ValueError('Downloaded cua-driver release checksum mismatch')
        return install_archive(archive, target, progress=progress)
