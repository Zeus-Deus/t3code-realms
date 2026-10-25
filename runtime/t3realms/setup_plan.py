"""Read-only setup proposals, exact package commands and explicit-home path checks."""
from dataclasses import asdict
import os
import platform
import shlex
import shutil
import sys
from pathlib import Path
from .config import effective_home
from .lifecycle import OwnershipError


def confined(home, path):
    home, path = effective_home(home), Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(home):
        raise OwnershipError('VM path must stay in this plugin home')
    cursor = home
    for part in path.relative_to(home).parts:
        cursor /= part
        if cursor.is_symlink(): raise OwnershipError('VM path redirects through a symlink')
        if cursor.exists() and cursor.stat().st_uid != os.getuid(): raise OwnershipError('VM path has a foreign owner')
    return path


def base_present(home, *, base=None):
    from .vm_base import selected, read_json
    base = selected(home) if base is None else confined(home, base)
    try:
        metadata = read_json(base / 'base.json')
        disk = confined(home, base / 'disk.qcow2')
        firmware = confined(home, base / 'OVMF_VARS.4m.fd')
        return disk.is_file() and disk.stat().st_size > 0 and firmware.is_file() and isinstance(metadata.get('built_at'), (int, float))
    except (OSError, ValueError, OwnershipError): return False

# Only these fixed package names can enter an administrator-authorized transaction.
PACKAGES = {
    'labwc': 'labwc', 'Xwayland': 'xorg-xwayland', 'wayvnc': 'wayvnc',
    'dbus-daemon': 'dbus', 'gdbus': 'glib2', 'grim': 'grim', 'wlr-randr': 'wlr-randr',
    'bwrap': 'bubblewrap', 'at-spi-bus-launcher': 'at-spi2-core', 'at-spi2-registryd': 'at-spi2-core',
    'systemd-run': 'systemd', 'systemd-inhibit': 'systemd', 'systemctl': 'systemd',
    'qemu-system-x86_64': 'qemu-full', 'qemu-img': 'qemu-full', 'ssh': 'openssh', 'scp': 'openssh',
    'socat': 'socat', 'jq': 'jq', 'mcopy': 'mtools', 'mformat': 'mtools', 'openssl': 'openssl',
    'curl': 'curl', 'gpg': 'gnupg', 'qemu-full': 'qemu-full', 'edk2-ovmf': 'edk2-ovmf', 'mtools': 'mtools',
    '/usr/share/edk2/x64/OVMF_CODE.4m.fd': 'edk2-ovmf', '/usr/share/edk2/x64/OVMF_VARS.4m.fd': 'edk2-ovmf',
}
PACKAGE_PREFIX = ['/usr/bin/pkexec', '/usr/bin/timeout', '--signal=TERM', '--kill-after=10s',
                  '1800s', '/usr/bin/pacman', '-S', '--needed', '--noconfirm', '--']


def distribution():
    try: return 'arch' if platform.freedesktop_os_release().get('ID') == 'arch' else 'unsupported'
    except OSError: return 'unsupported'


def package_plan(missing):
    instructions = {
        'systemd_user': 'A working systemd user manager is required; repair your login session before retrying',
        '/dev/kvm read/write access (no permissions are changed)': 'KVM access is required; enable virtualization and ask your administrator to grant your user access, then log in again. Setup never changes /dev/kvm permissions',
        'existing ~/.ssh/id_ed25519 key pair (never created or replaced)': 'Prepare an SSH id_ed25519 key pair yourself before retrying; setup never creates, replaces or modifies host keys',
        'Omarchy signing keyring /etc/pacman.d/gnupg': 'Initialize and verify the Omarchy signing keyring at /etc/pacman.d/gnupg through your administrator before retrying',
    }
    blockers = [instructions.get(name, name) for name in dict.fromkeys(missing) if name not in PACKAGES]
    packages = sorted({PACKAGES[name] for name in missing if name in PACKAGES})
    if packages and (sys.platform != 'linux' or distribution() != 'arch' or not shutil.which('pacman')):
        blockers.append('Automatic package setup requires Arch Linux with pacman; install missing prerequisites with your package manager: ' + ', '.join(packages))
        packages = []
    if packages and not shutil.which('pkexec'):
        blockers.append('Polkit pkexec is required for native administrator package authorization; install prerequisites manually first')
    if packages and not shutil.which('timeout'):
        blockers.append('GNU timeout is required to bound administrator package installation')
    argv = [*PACKAGE_PREFIX, *packages] if packages else None
    return {'packages': packages, 'argv': argv, 'command': shlex.join(argv) if argv else None, 'blockers': blockers}


def bind_review(value):
    from .manager import Manager
    return dict(value, reviewId=Manager._delete_token(value))


def plan(home, config):
    if config.kind == 'omarchy-vm':
        from .vm_setup import plan as vm_plan
        return vm_plan(home, config)
    from .diagnostics import doctor
    from .install_driver import VERSION, URL, ARCHIVE_SHA256, BINARY_SHA256
    report = doctor(home)
    missing = [name for name in report['missing'] if name != 'verified cua-driver']
    if report['platform'] != 'linux' or report['arch'] not in ('x86_64', 'AMD64'):
        missing.append('Linux x86-64')
    return bind_review({'kind': 'realm', 'home': str(effective_home(home)), 'config': asdict(config),
        'platform': report['platform'], 'arch': report['arch'], 'systemdUser': report['systemd_user'],
        'ready': report['ready'] and not missing, 'missing': missing, **package_plan(missing),
        'driver': {'version': VERSION, 'url': URL, 'archiveSha256': ARCHIVE_SHA256, 'binarySha256': BINARY_SHA256,
                   'destination': report['driver']['path'], 'installed': report['driver']['verified']},
        'message': report['message']})
