"""A persistent T3 guardian owns each VM, independently of plugin invocations."""
import os
from pathlib import Path
import subprocess
import sys
from .config import private_directory
from .lifecycle import OwnershipError, host_control_env, scope_info, private_json, alive

TERMINAL = {'inactive', 'failed'}


def owner_unit(record):
    from .vm_manager import validate_vm_record
    validate_vm_record(record)
    return record['unit'].removesuffix('.service') + '-lifetime.service'


def dropin_directory(record):
    return Path(f'/run/user/{os.getuid()}/systemd/user/{record["unit"]}.d')


def policy(record):
    return f'[Unit]\nBindsTo={owner_unit(record)}\nAfter={owner_unit(record)}\n[Service]\nTimeoutStopSec=5\nKillMode=control-group\n'


def install(record):
    from .runtime_store import RuntimeStore
    root = RuntimeStore(record['home']).verify(record['runtime_copy'])
    for unit in (record['unit'], owner_unit(record), record['guardian_unit']):
        info = scope_info(unit)
        if info['ActiveState'] not in TERMINAL or info.get('LoadState') != 'not-found':
            raise OwnershipError('VM startup unit already exists: ' + unit)
    directory = dropin_directory(record)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    with (directory / '50-owner-lifetime.conf').open('x') as stream: stream.write(policy(record))
    subprocess.run(['systemctl', '--user', 'daemon-reload'], env=host_control_env(), capture_output=True, check=True, timeout=5)
    command = ['systemd-run', '--user', '--quiet', '--collect', '--service-type=notify',
               '--unit=' + owner_unit(record), '--description=T3 Code VM guardian ' + record['compute_generation'],
               '--property=NotifyAccess=main', '--property=TimeoutStartSec=15', '--property=TimeoutStopSec=3',
               '--property=KillMode=control-group', '--setenv=PYTHONDONTWRITEBYTECODE=1',
               sys.executable, '-I', '-B', str(root / 't3realms' / 'vm_supervisor.py'),
               record['home'], record['id'], record['compute_generation']]
    subprocess.run(command, env=host_control_env(), capture_output=True, check=True, timeout=20)
    info = scope_info(owner_unit(record))
    if info['ActiveState'] != 'active' or not info.get('InvocationID'):
        raise OwnershipError('VM guardian did not acknowledge startup')
    record['owner_invocation_id'] = info['InvocationID']
    record['supervisor'] = private_json(Path(record['runtime_dir']) / 'supervisor.json')


def validate_owner(record):
    info = scope_info(owner_unit(record))
    if (info['ActiveState'] != 'active' or info.get('InvocationID') != record.get('owner_invocation_id')
            or info.get('Description') != 'T3 Code VM guardian ' + record['compute_generation']
            or not alive(private_json(Path(record['runtime_dir']) / 'supervisor.json'))):
        raise OwnershipError('VM guardian is not the owned live incarnation')


def stop_invocation(unit, invocation, *, description=None):
    info = scope_info(unit)
    if info['ActiveState'] in TERMINAL: return
    if (invocation is not None and info.get('InvocationID') != invocation
            or invocation is None and description is None
            or description is not None and info.get('Description') != description):
        raise OwnershipError('VM unit invocation changed: ' + unit)
    subprocess.run(['systemctl', '--user', 'stop', unit], env=host_control_env(), capture_output=True, check=True, timeout=12)
    if scope_info(unit)['ActiveState'] not in TERMINAL: raise OwnershipError('VM unit has not stopped: ' + unit)


def retire(record):
    # Check the guest before stopping any dependency, which could otherwise
    # retire a substituted invocation through BindsTo.
    guest = scope_info(record['unit'])
    expected = 'T3 Code VM ' + record.get('compute_generation', '')
    if guest['ActiveState'] not in TERMINAL and (
            record.get('invocation_id') and guest.get('InvocationID') != record['invocation_id']
            or guest.get('Description') != expected):
        raise OwnershipError('VM guest invocation is unknown or replaced; retirement deferred')
    stop_invocation(record['unit'], record.get('invocation_id'), description=expected)
    stop_invocation(owner_unit(record), record.get('owner_invocation_id'),
                    description='T3 Code VM guardian ' + record['compute_generation'])
    stop_invocation(record['guardian_unit'], record.get('guardian_invocation_id'))


def remove_dropin(record):
    for unit in (record['unit'], owner_unit(record), record['guardian_unit']):
        if scope_info(unit)['ActiveState'] not in TERMINAL: raise OwnershipError('VM compute is still active')
    directory = dropin_directory(record)
    if not directory.exists() and not directory.is_symlink(): return
    if directory.is_symlink() or directory.stat().st_uid != os.getuid(): raise OwnershipError('VM unit policy redirected')
    path = directory / '50-owner-lifetime.conf'
    if path.is_symlink() or path.read_text() != policy(record): raise OwnershipError('VM unit policy changed')
    path.unlink(); directory.rmdir()
    subprocess.run(['systemctl', '--user', 'daemon-reload'], env=host_control_env(), capture_output=True, check=True, timeout=5)


def startup_abandoned(record):
    return record['status'] == 'starting' and not alive(record.get('startup_process'))
