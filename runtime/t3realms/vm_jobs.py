"""VM job admission and execution share the same generation/owner checks."""
from pathlib import Path
from .config import Config, validate_owner
from .lifecycle import OwnershipError


def validate_input(home, kind, owner, payload):
    if kind == 'vm_setup':
        from .setup_worker import validate_setup_input
        validate_setup_input(payload)
        if Config.from_object(payload['config']).kind != 'omarchy-vm': raise ValueError('VM setup requires kind omarchy-vm')
        return
    validate_owner(owner)
    fields = {'id', 'incarnation'} if kind == 'vm_driver' else {'id', 'incarnation', 'direction', 'source', 'destination'}
    if set(payload) - fields or not {'id', 'incarnation'} <= set(payload): raise ValueError('unknown or missing VM job input')
    from .vm_manager import VmManager
    vm = VmManager(home)
    record = vm.record(payload['id'], owner=owner)
    if payload['incarnation'] != record.get('compute_generation'): raise OwnershipError('VM job incarnation changed')
    vm.validate(record['id'])
    if kind == 'transfer':
        if payload.get('direction') not in ('push', 'pull'): raise ValueError('transfer direction must be push or pull')
        for key in ('source', 'destination'):
            value = payload.get(key)
            if key == 'destination' and payload['direction'] == 'push' and value is None: continue
            if not isinstance(value, str) or not Path(value).is_absolute() or '\0' in value or len(value) > 4096:
                raise ValueError(key + ' must be an explicit absolute path (destination required for pull)')


def run(home, job, progress):
    payload, kind = job['input'], job['kind']
    validate_input(home, kind, job['owner'], payload)
    from .vm_manager import VmManager
    if kind == 'vm_setup':
        from .setup_worker import run as setup
        return setup(home, job, progress)
    vm = VmManager(home, vm_id=payload['id'])
    if kind == 'vm_driver':
        from .vm_cua import create_vm_driver_launcher
        from .config import driver_path
        progress({'stage': 'staging guest driver'})
        return {'path': create_vm_driver_launcher(vm, payload['id'], driver_path(home))}
    progress({'stage': 'copying', 'direction': payload['direction']})
    vm.touch(payload['id'])
    result = getattr(vm, payload['direction'])(payload['id'], payload['source'], payload.get('destination'))
    vm.touch(payload['id'])
    return result
