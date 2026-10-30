"""What Realms put on this machine, and removing it when a person asks."""
import os
from pathlib import Path
import shlex
import shutil
import time

from .config import effective_home, driver_path, vm_data_path
from .lifecycle import BusyError, OwnershipError, Registry, RealmError, atomic_json, private_json

STATE = 'components.json'
WALK_LIMIT = 200_000
ISO_ESTIMATE_BYTES = 5 * 1024**3
ACTIVE = ('running', 'starting', 'stopping')


def read_state(home):
    try:
        value = private_json(effective_home(home) / STATE)
    except (OSError, ValueError, OwnershipError):
        return {}
    return value if isinstance(value, dict) else {}


def remember(home, **items):
    """A receipt for the Installed list; losing it never affects what is installed."""
    from .jobs import Jobs
    # The job lock is what note_setup runs under, so neither overwrites the other's update.
    with Jobs(home).lock():
        state = read_state(home)
        for name, value in items.items():
            if name == 'packages':
                state['packages'] = sorted({*state.get('packages', []), *value})
            else:
                state[name] = dict(value, at=time.time())
        atomic_json(effective_home(home) / STATE, state)


def halted(home, kind):
    """A failed or cancelled install. Job history expires, and this must not: only a person clears it."""
    value = read_state(home).get('halts', {}).get(kind)
    return value if isinstance(value, dict) else None


def note_setup(home, record):
    """Called with the job lock held, for every published setup job state."""
    kind = 'omarchy-vm' if record['kind'] == 'vm_setup' else 'realm'
    state = read_state(home)
    halts = dict(state.get('halts') or {})
    if record['state'] in ('failed', 'cancelled'):
        halts[kind] = {'state': record['state'], 'error': record.get('error'), 'job_id': record['job_id']}
    elif record['state'] == 'succeeded' or (record['state'] == 'queued' and not record['input'].get('unattended')):
        halts.pop(kind, None)
    else:
        return
    if halts != state.get('halts', {}):
        atomic_json(effective_home(home) / STATE, dict(state, halts=halts))


def disk_use(*paths):
    """Allocated bytes, so sparse VM disks report what they really cost."""
    total, seen = 0, 0
    for root in paths:
        if not os.path.lexists(root):
            continue
        if not Path(root).is_dir() or Path(root).is_symlink():
            total += os.lstat(root).st_blocks * 512
            continue
        for directory, names, files in os.walk(root):
            for name in names + files:
                seen += 1
                if seen > WALK_LIMIT:
                    return total
                try:
                    info = os.lstat(os.path.join(directory, name))
                except OSError:
                    continue
                if name in files:
                    total += info.st_blocks * 512
    return total


def registries(home):
    from .vm_manager import VmRegistry
    return Registry(home), VmRegistry(home)


def summary(home):
    from .diagnostics import driver_status
    from .install_driver import VERSION
    from .setup_plan import base_present
    from .vm_base import read_json, selected
    home = effective_home(home)
    state = read_state(home)
    data = vm_data_path(home)
    driver = driver_status(home)
    target = driver_path(home)
    # An interrupted removal may leave a dangling base; the page must still offer to finish it.
    try:
        base = selected(home)
        present = base_present(home)
    except (OSError, ValueError, OwnershipError):
        base, present = None, False
    release = None
    if present:
        try:
            release = str(read_json(base / 'base.json').get('iso', '')).removeprefix('omarchy-').removesuffix('.iso') or None
        except (OSError, ValueError, OwnershipError):
            pass
    desktop, vm = registries(home)
    records = desktop.records() + vm.records()
    packages = [name for name in state.get('packages', []) if isinstance(name, str)]
    components = {
        'driver': {'present': driver['installed'], 'verified': driver['verified'], 'version': VERSION,
                   'bytes': disk_use(target), **receipt(state, 'driver')},
        'vm': {'present': present, 'release': release, 'bytes': disk_use(data / 'base', data / 'bases', data / 'iso'),
               **receipt(state, 'vm')},
        'workspaces': {'count': sum(1 for record in records if not record.get('setup_base')),
                       'bytes': disk_use(desktop.root / 'workspaces', vm.root / 'vm')},
        'packages': {'names': packages,
                     'removeCommand': shlex.join(['sudo', 'pacman', '-Rns', *packages]) if packages else None},
    }
    return dict(components, totalBytes=sum(components[key]['bytes'] for key in ('driver', 'vm', 'workspaces')))


def receipt(state, name):
    value = state.get(name)
    if not isinstance(value, dict):
        return {'installedBy': None, 'installedAt': None}
    return {'installedBy': value.get('by'), 'installedAt': value.get('at')}


def download_progress(home):
    """The ISO's size on disk; the vendored installer owns the download itself."""
    data = vm_data_path(home) / 'iso'
    total = 0
    try:
        for entry in os.scandir(data):
            if entry.name.endswith(('.iso', '.iso.part')) and entry.is_file(follow_symlinks=False):
                total += entry.stat(follow_symlinks=False).st_size
    except OSError:
        pass
    return {'bytes': total, 'estimatedBytes': ISO_ESTIMATE_BYTES}


def remove(home, name, *, job_id=None):
    """job_id is the teardown calling this: every other active job blocks removal."""
    from .jobs import Jobs, TERMINAL
    from .setup_plan import confined
    if name not in ('driver', 'vm'):
        raise ValueError('component must be driver or vm')
    home = effective_home(home)
    jobs = Jobs(home)
    desktop, vm = registries(home)
    # Registry before jobs, the order job progress takes them. Held throughout, so no job can
    # start between this check and the removal. Both registries share this lock.
    with desktop.lock(), jobs.lock():
        if any(record['state'] not in TERMINAL and record['job_id'] != job_id for record in jobs.records()):
            raise BusyError('Realm work is still running; try again when it finishes')
        records = desktop.records() + vm.records()
        if name == 'driver':
            if any(record.get('status') in ACTIVE for record in records):
                raise RealmError('Stop running Realms before removing the GUI driver')
            target = confined(home, driver_path(home))
            target.unlink(missing_ok=True)
            confined(home, target.with_name('.cua-driver-verified.json')).unlink(missing_ok=True)
        else:
            # Unregistered directories count too: their overlays may still need this base.
            sessions = vm.root / 'vm'
            if vm.records() or (sessions.is_dir() and any(sessions.iterdir())):
                raise RealmError('Delete this machine\'s Omarchy VM workspaces before removing the Omarchy VM')
            data = vm_data_path(home)
            # The pointer goes first: it must never name a base that is already gone.
            confined(home, data / 'current-base.json').unlink(missing_ok=True)
            for part in ('base', 'bases', 'iso', 'identity'):
                path = confined(home, data / part)
                if path.exists():
                    shutil.rmtree(path)
        state = read_state(home)
        if state.pop(name, None) is not None:
            atomic_json(home / STATE, state)
    return None if job_id else summary(home)


def teardown(home, config, job_id, progress):
    """Remove Everything. A detached job, because a large machine outlasts any host call.

    Workspaces go first: VM disks depend on the shared base. What fails is reported and stays,
    and running this again resumes interrupted deletions.
    """
    from .manager import Manager
    from .vm_manager import VmManager
    manager, vm = Manager(home, config=config), VmManager(home, config=config)
    records = manager.list() + vm.list()
    if any(record.get('status') in ACTIVE for record in records):
        raise BusyError('Stop running Realms first')
    failed = []
    for index, record in enumerate(records):
        progress({'stage': 'workspaces', 'done': index, 'total': len(records)})
        target = vm if record['id'].startswith('v-') else manager
        options = {'discard': True} if target is vm and record.get('status') != 'stopped' else {}
        try:
            snapshot = target.delete_snapshot(record['id'], session_id=record['session_id'], **options)
            target.delete(record['id'], session_id=record['session_id'], token=snapshot['token'], **options)
        except Exception as exc:
            failed.append({'name': record['id'], 'error': str(exc)[:500]})
    for name in ('vm', 'driver'):
        progress({'stage': name})
        try:
            remove(home, name, job_id=job_id)
        except Exception as exc:
            failed.append({'name': name, 'error': str(exc)[:500]})
    return {'failed': failed}
