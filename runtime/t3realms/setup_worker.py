"""Setup bound to an exact read-only proposal before any effect.

An agent's unattended job covers only plugin-local downloads: it can never reach pkexec.
"""
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from .config import Config, effective_home
from .lifecycle import OwnershipError, BusyError, SetupRequired, host_control_env
from .setup_plan import plan, PACKAGES, PACKAGE_PREFIX


def validate_setup_input(payload):
    if (set(payload) - {'unattended'} != {'config', 'review_id'} or not isinstance(payload['review_id'], str)
            or payload.get('unattended', True) is not True):
        raise ValueError('Setup requires its reviewed plan')


def run_command(argv, env, lock_fd):
    # A separate process retains the package lock even if this job runner dies.
    payload = json.dumps({'argv': argv, 'env': env})
    process = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).with_name('package_process.py')), payload],
        env=env, stdin=subprocess.DEVNULL, start_new_session=True, pass_fds=(lock_fd,))
    from .jobs import Cancelled
    try:
        process.wait()
    except Cancelled:
        # Never interrupt an elevated package transaction or release its exclusion early.
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        process.wait()
        raise
    if process.returncode:
        raise SetupRequired('Package installation failed or administrator authorization was denied; inspect setup before retrying')


def install_packages(home, reviewed, progress):
    packages = reviewed['packages']
    if (packages != sorted(set(packages)) or any(package not in set(PACKAGES.values()) for package in packages)
            or reviewed['argv'] != ([*PACKAGE_PREFIX, *packages] if packages else None)):
        raise OwnershipError('Package command differs from the supported reviewed transaction')
    home = effective_home(home)
    fd = os.open(home / 'setup-packages.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise OwnershipError('Package setup lock ownership changed')
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc: raise BusyError('A prior package transaction is still draining; retry when it finishes') from exc
        if not packages: return
        progress({'stage': 'packages', 'packages': packages, 'command': reviewed['command'],
                  'message': 'Waiting for native Polkit authorization or package installation. Cancellation waits for the transaction to finish safely.'})
        env = dict(host_control_env(), HOME=str(Path.home()), LANG='C.UTF-8')
        run_command(reviewed['argv'], env, fd)
    finally:
        # close only: LOCK_UN would also unlock the independent supervisor's inherited description.
        os.close(fd)


def run(home, job, progress):
    payload = job['input']
    config = Config.from_object(payload['config'])
    reviewed = plan(home, config)
    if payload['review_id'] != reviewed['reviewId']:
        raise OwnershipError('Setup plan changed; review it again')
    if reviewed['blockers']: raise SetupRequired('; '.join(reviewed['blockers']))
    by = 'agent' if payload.get('unattended') else 'person'
    if by == 'agent' and reviewed['packages']:
        raise SetupRequired('Installing system packages needs a person')
    install_packages(home, reviewed, progress)
    from .components import remember
    if reviewed['packages']: remember(home, packages=reviewed['packages'])
    # Consent cannot expand to new packages discovered after installation.
    current = plan(home, config)
    if current['blockers'] or current['packages']:
        raise SetupRequired('Prerequisites remain after package setup; review setup again: ' + ', '.join(current['missing']))
    from .install_driver import install
    if not current['driver']['installed']:
        install(home=home, progress=progress)
        remember(home, driver={'by': by})
    if config.kind == 'omarchy-vm':
        from .vm_manager import VmManager
        vm = VmManager(home, config=payload['config'])
        if not current['base']['present']:
            vm.install_base(progress=progress, job_id=job['job_id'])
            remember(home, vm={'by': by})
        result = vm.doctor()
    else:
        from .diagnostics import doctor
        result = doctor(home)
    if not result['ready']: raise SetupRequired('Setup did not verify ready; inspect prerequisites before retrying')
    return result
