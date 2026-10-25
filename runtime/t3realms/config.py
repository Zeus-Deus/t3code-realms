# Adapted from Hermes Realms 0.2.0 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Caller-supplied configuration and an explicit, private state home."""

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import stat


def finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def effective_home(home):
    from .lifecycle import OwnershipError

    if not isinstance(home, (str, os.PathLike)) or not str(home):
        raise ValueError('home is required')
    path = Path(home)
    if not path.is_absolute():
        raise ValueError('home must be absolute')
    # Resolve redirects above the final component (e.g. /home -> /var/home),
    # but never follow a redirect of the private state directory itself.
    if path.name == '..':
        raise ValueError('home must name a private directory')
    try:
        path = path.parent.resolve(strict=True) / path.name
    except FileNotFoundError as exc:
        raise ValueError('home must already exist') from exc
    except OSError as exc:
        raise OwnershipError('home parent cannot be resolved safely') from exc
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError('home must already exist') from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise OwnershipError('home must be owned by this uid with mode 0700')
    return path


def private_directory(path):
    from .lifecycle import OwnershipError

    path = Path(path)
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise OwnershipError('private directory ownership or mode changed: ' + str(path))
    except FileExistsError as exc:
        raise OwnershipError('private directory was redirected: ' + str(path)) from exc
    return path


def driver_path(home):
    return effective_home(home) / 'bin' / 'cua-driver'


@dataclass(frozen=True)
class Config:
    kind: str = 'realm'
    vm: 'VmConfig' = field(default_factory=lambda: VmConfig())
    size: str = '1920x1080'
    idle_ttl: float = 1800
    renderer: str = 'gles2'
    overlay: bool = True
    cursor_theme: str = 'cua.default'

    def __post_init__(self):
        if self.kind not in ("realm", "omarchy-vm"):
            raise ValueError("kind must be realm or omarchy-vm")
        if isinstance(self.vm, dict):
            try:
                object.__setattr__(self, "vm", VmConfig(**self.vm))
            except TypeError as exc:
                raise ValueError("unknown VM configuration field") from exc
        if not isinstance(self.vm, VmConfig):
            raise ValueError("vm must be an object")
        parse_size(self.size)
        if self.renderer not in ('gles2', 'pixman'):
            raise ValueError('renderer must be gles2 or pixman')
        if not finite_number(self.idle_ttl) or self.idle_ttl <= 0:
            raise ValueError('idle_ttl must be a positive finite number of seconds')
        if not isinstance(self.overlay, bool):
            raise ValueError('overlay must be a JSON boolean')
        if (not isinstance(self.cursor_theme, str) or not self.cursor_theme
                or '\0' in self.cursor_theme):
            raise ValueError('cursor_theme must be a nonempty NUL-free string')

    @classmethod
    def from_object(cls, value):
        if not isinstance(value, dict):
            raise ValueError('config must be a JSON object')
        try:
            return cls(**value)
        except TypeError as exc:
            raise ValueError('unknown configuration field') from exc


def parse_size(size):
    if not isinstance(size, str) or not re.fullmatch(r'[1-9][0-9]{1,4}x[1-9][0-9]{1,4}', size):
        raise ValueError('size must be WIDTHxHEIGHT')
    width, height = map(int, size.split('x'))
    if not (64 <= width <= 8192 and 64 <= height <= 8192):
        raise ValueError('size dimensions must be between 64 and 8192')
    return width, height


def validate_owner(owner):
    if not isinstance(owner, str) or not 1 <= len(owner) <= 256 or '\0' in owner:
        raise ValueError('owner must contain 1 to 256 NUL-free characters')
    return owner


KINDS = ('realm', 'omarchy-vm')


def vm_data_path(home):
    return effective_home(home) / 'vm'


@dataclass(frozen=True)
class VmConfig:
    release: str = '4.0.4'
    memory: int = 3072
    cpus: int = 2
    disk_size: str = '40G'
    network: bool = True
    boot_timeout: int = 180
    workspace_retention_days: int = 14

    def __post_init__(self):
        if not isinstance(self.release, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', self.release):
            raise ValueError('vm.release must be a literal stable version such as 4.0.4')
        for name, low, high in (('memory', 1024, 131072), ('cpus', 1, 64), ('boot_timeout', 10, 900), ('workspace_retention_days', 0, 36500)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'vm.{name} must be an integer from {low} to {high}')
        if not isinstance(self.network, bool):
            raise ValueError('vm.network must be a JSON boolean')
        if (not isinstance(self.disk_size, str) or not re.fullmatch(r'[1-9][0-9]{0,3}G', self.disk_size)
                or not 16 <= int(self.disk_size[:-1]) <= 2048):
            raise ValueError('vm.disk_size must be 16G to 2048G')
