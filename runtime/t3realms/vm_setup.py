"""Reviewed VM setup; never touches host keys, and only a person can approve packages."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import uuid
from .config import Config, effective_home, vm_data_path, private_directory
from .lifecycle import OwnershipError, SetupRequired, atomic_json, host_control_env, scope_info, identity
from .setup_plan import confined, base_present

MIB = 1024**2
GIB = 1024**3
TOOLS = ('qemu-system-x86_64', 'qemu-img', 'ssh', 'ssh-keygen', 'socat', 'jq', 'mcopy', 'mformat',
         'openssl', 'systemd-run', 'systemd-inhibit', 'systemctl', 'curl', 'gpg', 'pacman')
FIRMWARE = ('/usr/share/edk2/x64/OVMF_CODE.4m.fd', '/usr/share/edk2/x64/OVMF_VARS.4m.fd')
SIGNER = '40DFB630FF42BCFFB047046CF0134EE680CAC571'


def resources(config, path, *, install=False):
    path = Path(path)
    while not path.exists(): path = path.parent
    required_disk = int(config.vm.disk_size[:-1]) * GIB + 6 * GIB if install else 2 * GIB
    memory = None
    try:
        values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        memory = int(values['MemAvailable'].split()[0]) * 1024
        disk = shutil.disk_usage(path).free
    except (OSError, KeyError, ValueError):
        return {'blockers': ['Cannot inspect available RAM or disk space; allocation refused']}
    blockers = []
    if memory < (config.vm.memory + 512) * MIB: blockers.append('Insufficient host RAM including 512 MiB host headroom')
    if disk < required_disk: blockers.append('Insufficient free storage for VM allocation')
    return {'blockers': blockers, 'availableMemoryBytes': memory, 'requiredMemoryBytes': (config.vm.memory + 512) * MIB,
            'availableDiskBytes': disk, 'requiredDiskBytes': required_disk}


def require_resources(config, path, *, install=False):
    blockers = resources(config, path, install=install)['blockers']
    if blockers: raise SetupRequired('; '.join(blockers) + '. No other guests were reclaimed.')


def doctor(home, config):
    from .diagnostics import driver_status
    home = effective_home(home)
    tools = {name: shutil.which(name) for name in TOOLS}
    missing = [name for name, found in tools.items() if not found]
    missing += [name for name in FIRMWARE if not os.access(name, os.R_OK)]
    # The vendored installer checks these Arch packages itself before effects.
    for package in ('qemu-full', 'edk2-ovmf', 'mtools'):
        if not any(Path('/var/lib/pacman/local').glob(package + '-[0-9]*')): missing.append(package)
    if sys.platform != 'linux' or platform.machine() not in ('x86_64', 'AMD64'): missing.append('Linux x86-64')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK): missing.append('/dev/kvm read/write access (no permissions are changed)')
    user_manager = False
    if tools['systemctl']:
        try:
            probe = subprocess.run([tools['systemctl'], '--user', 'show', 'basic.target', '--property=ActiveState'],
                                   env=host_control_env(), capture_output=True, text=True, timeout=5)
            user_manager = probe.returncode == 0 and 'ActiveState=active' in probe.stdout.splitlines()
        except (OSError, subprocess.SubprocessError): pass
    if not user_manager: missing.append('systemd_user')
    if not Path('/etc/pacman.d/gnupg').is_dir(): missing.append('Omarchy signing keyring /etc/pacman.d/gnupg')
    base = base_present(home)
    driver = driver_status(home)
    blockers = list(dict.fromkeys(missing))
    if not base: missing.append('Omarchy base image')
    if not driver['verified']: missing.append('verified cua-driver')
    return {'kind': 'omarchy-vm', 'platform': sys.platform, 'arch': platform.machine(), 'tools': tools,
            'systemd_user': user_manager, 'driver': driver, 'base_image': {'present': base, 'path': str(vm_data_path(home) / 'base/disk.qcow2')},
            'blockers': blockers, 'missing': missing, 'ready': not missing,
            'message': 'Omarchy VM ready.' if not missing else 'Omarchy VM setup required: ' + ', '.join(missing)}


def plan(home, config):
    from .vm_manager import VENDORED_SHA256
    from .install_driver import VERSION, URL, ARCHIVE_SHA256, BINARY_SHA256
    report = doctor(home, config)
    home = effective_home(home)
    base = report['base_image']
    iso = f'https://iso.omarchy.org/omarchy-{config.vm.release}.iso'
    # Available resources fluctuate; the reviewed requirements bind consent,
    # while availability is checked again at execution without changing the id.
    value = {'kind': 'omarchy-vm', 'home': str(home), 'config': asdict(config),
             'missing': report['blockers'], 'blockers': report['blockers'], 'ready': report['ready'],
             'platform': report['platform'], 'arch': report['arch'], 'systemdUser': report['systemd_user'],
             'installerSha256': VENDORED_SHA256,
             'driver': {'version': VERSION, 'url': URL, 'archiveSha256': ARCHIVE_SHA256, 'binarySha256': BINARY_SHA256,
                        'destination': report['driver']['path'], 'installed': report['driver']['verified']},
             'base': base, 'release': config.vm.release,
             'downloads': [] if base['present'] else [{'url': iso, 'signatureUrl': iso + '.sig', 'signer': SIGNER,
                                                      'estimatedBytes': 5 * GIB, 'destination': str(vm_data_path(home) / 'iso')}],
             'storage': {'baseDirectory': str(vm_data_path(home) / 'base'), 'isoDirectory': str(vm_data_path(home) / 'iso'),
                         'virtualDisk': config.vm.disk_size, 'requiredFreeBytes': int(config.vm.disk_size[:-1]) * GIB + 6 * GIB,
                         'memoryMiB': config.vm.memory, 'cpus': config.vm.cpus, 'network': config.vm.network},
             'message': report['message']}
    if not value['driver']['installed']:
        value['downloads'].append({'url': URL, 'archiveSha256': ARCHIVE_SHA256, 'estimatedBytes': 64 * MIB,
                                   'destination': value['driver']['destination']})
    from .setup_plan import package_plan, bind_review
    value.update(package_plan(value['missing']))
    return dict(bind_review(value), resources={'blockers': [] if base['present'] else resources(config, vm_data_path(home), install=True)['blockers']})


def install_base(vm, *, progress=None, job_id=None):
    from .vm_manager import _generation_paths
    from .vm_lifetime import install, retire, remove_dropin
    from .vm_ssh import enroll_host_key, shutdown_guest
    from .runtime_store import pinned_runtime
    from .vm_base import sync_assets
    require_resources(vm.config, vm.home, install=True)
    private_directory(vm.data); private_directory(vm.data / 'iso')
    from .vm_ssh import ensure_identity
    ensure_identity(vm.home)
    with pinned_runtime(vm.home) as runtime_copy, vm.registry.lock():
        if vm.base_status()['present']: return vm.base_status()
        base = confined(vm.home, vm.data / 'base')
        if base.exists(): raise OwnershipError('Incomplete base directory exists; inspect it explicitly before retrying')
        port = vm._free_port(vm._reserved_ports())
        generation = uuid.uuid4().hex
        private_directory(vm.registry.root / 'vm')
        session = vm.registry.root / 'vm' / generation; session.mkdir(mode=0o700)
        runtime = _generation_paths(os.getuid(), generation); runtime.mkdir(mode=0o700)
        record = {'id': 'v-' + generation[:24], 'session_id': 'setup:base:' + generation, 'kind': 'omarchy-vm',
                  'generation': generation, 'compute_generation': uuid.uuid4().hex, 'uid': os.getuid(),
                  'home': str(vm.home), 'runtime_dir': str(runtime), 'session_dir': str(session),
                  'unit': f't3code-vm-{generation}.service', 'guardian_unit': f't3code-vm-{generation}-guard.service',
                  'runtime_copy': str(runtime_copy), 'python_executable': sys.executable,
                  'status': 'starting', 'created_at': time.time(), 'startup_at': time.time(), 'last_activity': time.time(),
                  'idle_ttl': 7200, 'startup_process': identity(os.getpid()), 'setup_base': True, 'ssh_port': port,
                  'memory': vm.config.vm.memory, 'network': vm.config.vm.network, 'base_disk': str(base / 'disk.qcow2')}
        atomic_json(session / 'spec.json', asdict(vm.config)); atomic_json(runtime / 'vm.json', record); vm.registry.put(record)
    vm.operation = record; vm.setup_job = job_id
    published = False
    try:
        install(record)
        with vm.registry.lock(): vm.registry.put(record)
        if progress: progress({'stage': 'installing', 'realm_id': record['id'], 'estimatedMinutes': '15–30'})
        # Installer output is a private bounded-by-duration job log, not a plugin result.
        vm._run_script(['install', '--version', vm.config.vm.release], vm_home=session,
                       ssh_port=record['ssh_port'], unit=record['unit'], runtime=runtime, timeout=5400,
                       stdout=sys.stdout, identity=True)
        with vm.registry.lock(): record = vm._starting(record)
        enroll_host_key(record)
        shutdown_guest(record, vm.ssh_argv(record))
        with vm.registry.lock():
            retire(record); remove_dropin(record)
            if not vm._compute_stopped(record): raise OwnershipError('Base installer compute is still active')
            sync_assets(session)
            atomic_json(session / 'base.json', {'built_at': time.time(), 'generation': generation,
                                               'iso': f'omarchy-{vm.config.vm.release}.iso', 'home': str(vm.home),
                                               'uid': os.getuid(), 'ssh_identity': 'plugin'})
            if base.exists(): raise OwnershipError('Base appeared during installation; refusing replacement')
            session.rename(base); published = True
            vm.registry.remove(record['id'])
        shutil.rmtree(runtime)
        return vm.base_status()
    finally:
        if not published:
            with vm.registry.lock():
                current = vm.registry.get(record['id'])
                try: retire(current); remove_dropin(current)
                except BaseException:
                    vm._retirement_failed(current); raise
                current.update(status='recovery-required', cleanup_required=False, stopped_at=time.time(),
                               recovery_reason='Interrupted base install retained; explicitly review Discard')
                vm.registry.put(current)
        vm.operation = None; vm.setup_job = None
