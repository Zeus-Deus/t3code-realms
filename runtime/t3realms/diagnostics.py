"""Read-only prerequisite probes; never execute the driver or start a unit."""
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from .config import driver_path
from .install_driver import VERSION, present, receipt_verified

TOOLS = ('labwc', 'wayvnc', 'wlr-randr', 'grim', 'dbus-daemon', 'gdbus',
         'Xwayland', 'systemd-run', 'systemd-inhibit', 'bwrap', 'systemctl',
         'at-spi-bus-launcher', 'at-spi2-registryd')


def driver_status(home):
    target = driver_path(home)
    verified = receipt_verified(target)
    return {'installed': present(target), 'verified': verified,
            'version': VERSION if verified else None, 'path': str(target)}


def doctor(home):
    tools = {name: shutil.which(name) for name in TOOLS}
    for name in ('at-spi-bus-launcher', 'at-spi2-registryd'):
        candidate = Path('/usr/lib') / name
        if tools[name] is None and os.access(candidate, os.X_OK):
            tools[name] = str(candidate)
    user_manager = False
    if tools['systemctl']:
        from .lifecycle import host_control_env
        try:
            probe = subprocess.run([tools['systemctl'], '--user', 'show', 'basic.target',
                                    '--property=ActiveState'], env=host_control_env(),
                                   capture_output=True, text=True, timeout=5)
            user_manager = probe.returncode == 0 and 'ActiveState=active' in probe.stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            pass
    driver = driver_status(home)
    missing = [name for name, path in tools.items() if path is None]
    if sys.platform != 'linux':
        missing.append('Linux')
    if not user_manager:
        missing.append('systemd_user')
    if not driver['verified']:
        missing.append('verified cua-driver')
    return {'tools': tools, 'systemd_user': user_manager, 'platform': sys.platform,
            'arch': platform.machine(), 'driver': driver, 'ready': not missing,
            'missing': missing, 'message': 'Realms prerequisites available.' if not missing
            else 'Realms setup required: ' + ', '.join(missing)}
