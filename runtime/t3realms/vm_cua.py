# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Host Cua CLI proxy for one enrolled VM generation, never a host input driver."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import base64
import fcntl  # windows-footgun: ok — runtime package rejects non-Linux hosts
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from .install_driver import BINARY_SHA256
from .vm_ssh import require_host_key


_IDENTITY_KEYS = ('id', 'generation', 'home', 'runtime_dir', 'uid', 'session_id', 'session_dir', 'owner',
                  'owner_session_id', 'owner_start_ticks', 'owner_pid', 'owner_protocol',
                  'invocation_id', 'unit', 'guardian_unit', 'ssh_port', 'compute_generation', 'runtime_copy')


def _record_identity(record):
    return {key: record.get(key) for key in _IDENTITY_KEYS}


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def _host_env():
    # SSH uses the explicitly pinned key, never an ambient agent or GUI handle.
    return {'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C.UTF-8',
            'CUA_DRIVER_RS_TELEMETRY_ENABLED': '0'}


def _guest_command(vm, record, user, operation, *args):
    source = Path(__file__).with_name('vm_cua_guest.py').read_text(encoding='utf-8')
    remote = ['runuser', '-u', user, '--', '/usr/bin/python3', '-I', '-S', '-c',
              source + '\nraise SystemExit(main())\n', operation, *args]
    return [*vm.ssh_argv(record, tty=False), '--', shlex.join(remote)]


def _remote(vm, record, user, operation, *args, data=None, timeout=20):
    try:
        return subprocess.run(_guest_command(vm, record, user, operation, *args),
                              input=data, stdin=subprocess.DEVNULL if data is None else None,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=_host_env(), timeout=timeout, check=True).stdout
    except subprocess.CalledProcessError as exc:
        # The SSH argv embeds the guest program; retain its failure cause instead.
        stderr = exc.stderr.decode('utf-8', errors='replace') if isinstance(exc.stderr, bytes) else str(exc.stderr or '')
        detail = next((line.strip() for line in reversed(stderr.splitlines()) if line.strip()), 'No guest diagnostic was returned')
        raise RuntimeError(f'Guest GUI-driver {operation} failed (exit {exc.returncode}): {detail[:800]}') from exc


def _binary_bytes(executable):
    path = Path(executable).absolute()
    if path.resolve() != path:
        raise ValueError('Pinned driver must not use symlink redirects')
    with open(path, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not info.st_mode & 0o100:  # windows-footgun: ok — runtime package rejects non-Linux hosts
            raise ValueError('Pinned driver ownership changed')
        data = stream.read(64 * 1024 * 1024)
    if _digest(data) != BINARY_SHA256:
        raise ValueError('Pinned driver checksum mismatch')
    return data


def create_vm_driver_launcher(vm, realm_id, driver_executable):
    record = vm.validate(realm_id)
    runtime = _private_directory(record['runtime_dir'])
    fd = os.open(runtime / 'cua-prepare.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        spec_path = runtime / 'cua-proxy.json'
        binary = _binary_bytes(driver_executable)
        if spec_path.exists():
            proxy = VmDriverProxy(vm, json.loads(_read_private(spec_path)))
            proxy.check()
            if proxy.spec['binary_sha256'] != _digest(binary):
                raise ValueError('Pinned driver changed')
            return str(runtime / 'cua-vm')
        pin = require_host_key(record)
        user = vm.guest_user(realm_id)
        token = uuid.uuid4().hex[:16]
        files = {'cua-driver': binary,
                 'vm_driver_lifetime.py': Path(__file__).with_name('vm_driver_lifetime.py').read_bytes()}
        header = {name: {'size': len(data), 'sha256': _digest(data)} for name, data in files.items()}
        packet = json.dumps(header).encode() + b'\n' + b''.join(files.values())
        guest = json.loads(_remote(vm, record, user, 'stage', token, BINARY_SHA256,
                                  data=packet, timeout=60))
        if guest['binary_sha256'] != BINARY_SHA256:
            raise ValueError('Guest driver checksum mismatch')
        with tempfile.TemporaryDirectory(prefix='cua-metadata-', dir=runtime) as home:
            env = {'PATH': '/usr/bin:/bin', 'HOME': home, 'XDG_CONFIG_HOME': home,
                   'XDG_CACHE_HOME': home, 'CUA_DRIVER_RS_TELEMETRY_ENABLED': '0'}
            manifest = subprocess.run([str(driver_executable), 'manifest'], env=env,
                                      stdin=subprocess.DEVNULL, capture_output=True,
                                      check=True, timeout=20).stdout
        json.loads(manifest)
        spec = {'record': _record_identity(record), 'user': user, 'guest': guest,
                'host_key_sha256': _digest(_read_private(pin)), 'binary_sha256': BINARY_SHA256,
                'manifest': base64.b64encode(manifest).decode()}
        _write_new(spec_path, json.dumps(spec).encode())
        from .runtime_store import RuntimeStore
        binding = str(RuntimeStore(vm.home).verify(record['runtime_copy']) / 't3realms' / '_binding.py')
        launcher = (f'#!{record["python_executable"]} -IB\nimport runpy, sys\n'
                    f"runpy.run_path({binding!r})['load_runtime']('vm_cua').driver_main("
                    f"{str(vm.home)!r}, {realm_id!r}, {str(spec_path)!r})\n")
        _write_new(runtime / 'cua-vm', launcher.encode(), 0o700)
        return str(runtime / 'cua-vm')


def vm_desktop_attestor(vm, realm_id):
    record = vm.validate(realm_id)
    runtime = _private_directory(record['runtime_dir'])
    proxy = VmDriverProxy(vm, json.loads(_read_private(runtime / 'cua-proxy.json')))
    identity = ('omarchy-vm-cua', json.dumps(proxy.spec, sort_keys=True))
    def attest():
        record = proxy.check()
        _remote(vm, record, proxy.spec['user'], 'attest', json.dumps(proxy.spec['guest']))
        return identity
    return attest


def _strip_guest_paths(value):
    if isinstance(value, dict):
        return {key: _strip_guest_paths(child) for key, child in value.items()
                if key not in {'screenshot_file_path', 'screenshot_out_file'}}
    if isinstance(value, list):
        return [_strip_guest_paths(child) for child in value]
    if isinstance(value, str) and value.lstrip().startswith(('{', '[')):
        try:
            return json.dumps(_strip_guest_paths(json.loads(value)))
        except ValueError:
            pass
    return value


class VmDriverProxy:
    def __init__(self, vm, spec):
        self.vm = vm
        self.spec = json.loads(json.dumps(spec))
        self.runtime = _private_directory(spec['record']['runtime_dir'])

    def check(self):
        record = self.vm.validate(self.spec['record']['id'])
        if _record_identity(record) != self.spec['record']:
            raise ValueError('VM CUA generation or owner changed')
        _private_directory(self.runtime)
        if _digest(_read_private(require_host_key(record))) != self.spec['host_key_sha256']:
            raise ValueError('VM CUA enrolled host key changed')
        return record

    def run(self, argv):
        request = parse_invocation(argv, self.runtime)
        record = self.check()
        verb = request['args'][0]
        if verb == 'manifest':
            sys.stdout.buffer.write(base64.b64decode(self.spec['manifest'], validate=True))
            sys.stdout.buffer.flush()
            return 0
        key = request['socket']
        if verb == 'serve':
            return self._serve(record, request)
        mapping = json.loads(_read_private(self.runtime / (key + '.json')))
        if mapping['guest'] != self.spec['guest']:
            raise ValueError('Foreign CUA socket mapping')
        if verb == 'stop':
            return self._stop(key)
        payload = {'guest': self.spec['guest'], 'key': key, 'args': request['args']}
        command = _guest_command(self.vm, record, self.spec['user'], 'invoke', json.dumps(payload))
        if verb == 'mcp':
            def endpoint_check():
                current = self.check()
                _remote(self.vm, current, self.spec['user'], 'inspect', json.dumps(payload), timeout=5)
            return self._mcp(command, endpoint_check)
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                env=_host_env(), timeout=1.7 if verb == 'status' else 30)
        if verb == 'call' and result.returncode == 0:
            output = json.dumps(_strip_guest_paths(json.loads(result.stdout))).encode() + b'\n'
        else:
            output = result.stdout
        if result.returncode == 0:
            self.check()
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(result.stderr)
        return result.returncode

    def _serve(self, record, request):
        key = request['socket']
        mapping = self.runtime / (key + '.json')
        retired = self.runtime / (key + '.retired')
        if mapping.exists() and retired.exists():
            receipt = json.loads(_read_private(retired))
            if receipt.get('cleaned') is not True or receipt.get('driver_returncode') is None:
                raise RuntimeError('Prior guest CUA retirement is unconfirmed')
            if json.loads(_read_private(mapping)) != {'guest': self.spec['guest']}:
                raise ValueError('Foreign CUA socket mapping')
            mapping.unlink(); retired.unlink()
        control = self.runtime / (key + '.ctl')
        payload = {'guest': self.spec['guest'], 'key': key, 'args': request['args'],
                   'manifest': base64.b64encode(request['manifest']).decode() if request['manifest'] is not None else None,
                   'manifest_sha256': _digest(request['manifest']) if request['manifest'] is not None else None}
        _write_new(self.runtime / (key + '.json'), json.dumps({'guest': self.spec['guest']}).encode())
        stop = threading.Event()
        old = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}  # windows-footgun: ok — runtime package rejects non-Linux hosts
        process = None
        try:
            with socket.socket(socket.AF_UNIX) as listener, selectors.DefaultSelector() as selector:
                listener.bind(str(control))
                os.chmod(control, 0o600)
                listener.listen(4)
                selector.register(listener, selectors.EVENT_READ)
                process = subprocess.Popen(_guest_command(self.vm, record, self.spec['user'], 'serve', json.dumps(payload)),
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, env=_host_env(),
                                           start_new_session=True)
                while process.poll() is None and not stop.is_set():
                    process.stdin.write(b'HEARTBEAT\n')
                    process.stdin.flush()
                    for _, _ in selector.select(.5):
                        with listener.accept()[0] as client:
                            client.settimeout(1)
                            if client.recv(16) == b'STOP\n':
                                stop.set()
                if process.poll() is None:
                    process.stdin.write(b'STOP\n')
                    process.stdin.flush()
                output, _ = process.communicate(timeout=16)
                if process.returncode != 0:
                    raise RuntimeError('Guest CUA retirement unconfirmed')
                receipt = json.loads(output)
                if receipt.get('driver_returncode') is None or receipt.get('cleaned') is not True:
                    raise RuntimeError('Guest CUA retirement unconfirmed')
                _write_new(self.runtime / (key + '.retired'), output)
                return 0
        finally:
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                    process.stdin = None
                if process.poll() is None:
                    try:
                        process.communicate(timeout=16)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            process.communicate(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate(timeout=2)
                if process.stdout is not None:
                    process.stdout.close()
            control.unlink(missing_ok=True)
            for sig, handler in old.items():
                signal.signal(sig, handler)

    def _stop(self, key):
        receipt = self.runtime / (key + '.retired')
        if not receipt.exists():
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(str(self.runtime / (key + '.ctl')))
                client.sendall(b'STOP\n')
        deadline = time.monotonic() + 16
        while not receipt.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        data = json.loads(_read_private(receipt))
        if data.get('driver_returncode') is None or data.get('cleaned') is not True:
            raise RuntimeError('Guest CUA retirement unconfirmed')
        return 0

    def _mcp(self, command, endpoint_check=None):
        # A selector, not a daemon stdin thread: guest EOF must retire the host
        # proxy even while the core still holds its stdin writer open.
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=None, env=_host_env())
        assert process.stdin is not None and process.stdout is not None
        pending = {'input': b'', 'output': b''}
        limit = 32 * 1024 * 1024
        try:
            with selectors.SelectSelector() as selector:
                selector.register(sys.stdin.fileno(), selectors.EVENT_READ, 'input')
                selector.register(process.stdout.fileno(), selectors.EVENT_READ, 'output')
                output_open = True
                while output_open:
                    for event, _ in selector.select(1):
                        kind = event.data
                        data = os.read(event.fd, 65536)
                        if not data:
                            selector.unregister(event.fd)
                            if pending[kind]:
                                raise ValueError('Incomplete MCP frame')
                            if kind == 'input':
                                process.stdin.close()
                            else:
                                output_open = False
                            continue
                        pending[kind] += data
                        while b'\n' in pending[kind]:
                            line, pending[kind] = pending[kind].split(b'\n', 1)
                            if len(line) > limit:
                                raise ValueError('MCP frame too large')
                            message = json.loads(line)
                            self.check()
                            if kind == 'input':
                                _inline_only(message)
                                if endpoint_check is not None and message.get('method') == 'tools/call':
                                    endpoint_check()
                                process.stdin.write(line + b'\n')
                                process.stdin.flush()
                            else:
                                message = _strip_guest_paths(message)
                                sys.stdout.buffer.write(json.dumps(message).encode() + b'\n')
                                sys.stdout.buffer.flush()
                        if len(pending[kind]) > limit:
                            raise ValueError('MCP frame too large')
            return process.wait(timeout=3)
        finally:
            if not process.stdin.closed:
                process.stdin.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            process.stdout.close()


def driver_main(home, realm_id, spec_path):
    from .vm_manager import VmManager
    try:
        vm = VmManager(home, vm_id=realm_id)
        spec = json.loads(_read_private(spec_path))
        code = VmDriverProxy(vm, spec).run(default_invocation(
            sys.argv[1:], Path(spec_path).parent, spec['record']['compute_generation']))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('VM CUA: ' + str(exc), file=sys.stderr)
        code = 125
    raise SystemExit(code)


def default_invocation(argv, runtime, incarnation):
    if argv not in (['mcp'], ['serve']):
        return argv
    args = [*argv, '--embedded', '--socket', str(runtime / ('hc-' + incarnation[:12] + '.sock'))]
    # The pinned driver's MCP client rejects daemon authorization/overlay flags.
    return args + ['--no-permissions-gate', '--no-overlay'] if argv == ['serve'] else args


def _private_directory(path):
    path = Path(path)
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):  # windows-footgun: ok — runtime package rejects non-Linux hosts
        raise ValueError('CUA runtime ownership changed')
    return path


def _read_private(path, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
            raise ValueError('CUA private file ownership or size changed')
        return stream.read(limit + 1)


def _inline_only(value):
    if isinstance(value, dict):
        if any(key in value for key in ('screenshot_out_file', 'screenshot_file_path')):
            raise ValueError('VM computer-use supports inline pixels only')
        for child in value.values():
            _inline_only(child)
    elif isinstance(value, list):
        for child in value:
            _inline_only(child)


def parse_invocation(argv, runtime):
    runtime = _private_directory(runtime)
    args = list(argv)
    if args == ['manifest']:
        return {'args': args, 'socket': None, 'manifest': None}
    if not args or args[0] not in {'serve', 'status', 'mcp', 'call', 'stop'}:
        raise ValueError('Unsupported VM driver verb')
    if (args.count('--socket') != 1 or args[-1] == '--socket'
            or (args[0] in {'serve', 'mcp'} and '--embedded' not in args)):
        raise ValueError('VM driver requires an explicit embedded private socket')
    index = args.index('--socket') + 1
    path = Path(args[index])
    if path.parent != runtime or not re.fullmatch(r'hc-[0-9a-f]{12}\.sock', path.name):
        raise ValueError('Foreign VM driver socket')
    args[index] = '@SOCKET@'
    manifest = None
    flags = {'--embedded', '--no-permissions-gate', '--dangerously-bypass-approvals',
             '--approve-capability-manifest', '--no-overlay'}
    values = {'--socket', '--permission-mode', '--capability-manifest', '--cursor-theme', '--session-label'}
    offset = 1
    if args[0] == 'call':
        if len(args) < 5 or not re.fullmatch(r'[a-z_]+', args[1]):
            raise ValueError('Invalid VM driver call')
        _inline_only(json.loads(args[2]))
        offset = 3
    while offset < len(args):
        flag = args[offset]
        if flag in flags:
            offset += 1
            continue
        if flag not in values or offset + 1 >= len(args):
            raise ValueError('Unsupported VM driver argument')
        if flag == '--capability-manifest':
            policy = Path(args[offset + 1])
            if manifest is not None or policy.parent != runtime or not re.fullmatch(r'hc-manifest-[\w-]+\.json', policy.name):
                raise ValueError('Foreign capability manifest')
            manifest = _read_private(policy)
            args[offset + 1] = '@MANIFEST@'
        offset += 2
    return {'args': args, 'socket': path.name, 'manifest': manifest}
