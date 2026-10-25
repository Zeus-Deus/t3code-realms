"""Persistent VM guardian and bounded command capture, in one systemd service."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid
if __package__ in (None, ''):
    import runpy
    __package__ = runpy.run_path(str(Path(__file__).with_name('_binding.py')))['load_runtime']().__name__
from .lifecycle import atomic_json, private_json, identity, OwnershipError, host_control_env
from .bootstrap import admit_job, reap_jobs, JOB_RETENTION_SECONDS
from .lifecycle import OUTPUT_LIMIT_BYTES


def command_argv(vm, record, command, cwd):
    launcher = Path(record['runtime_dir']) / 'cua-vm'
    if command == [str(launcher), 'serve']:
        # Only this generated, generation-bound proxy is host executable.
        from .vm_cua import _read_private, VmDriverProxy
        VmDriverProxy(vm, json.loads(_read_private(launcher.parent / 'cua-proxy.json'))).check()
        return command, False
    from .vm_launch import guest_script
    code = Path(__file__).with_name('vm_terminal_guest.py').read_text()
    script = guest_script(command, cwd or '~')
    import shlex
    return [*vm.ssh_argv(record), '--', shlex.join(['python3', '-I', '-S', '-c', code, script])], True


def run(home, vm_id, incarnation):
    from .vm_manager import VmManager
    from .runtime_store import RuntimeStore
    vm = VmManager(home)
    record = vm.record(vm_id)
    if record['compute_generation'] != incarnation or record['status'] != 'starting':
        raise OwnershipError('VM guardian startup cancelled')
    RuntimeStore(home).verify(record['runtime_copy'])
    runtime = Path(record['runtime_dir'])
    atomic_json(runtime / 'supervisor.json', identity(os.getpid()))
    with socket.socket(socket.AF_UNIX) as control:
        control.bind(str(runtime / 'control')); os.chmod(runtime / 'control', 0o600); control.listen(16)
        address = os.environ['NOTIFY_SOCKET']; address = '\0' + address[1:] if address.startswith('@') else address
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
            notifier.connect(address); notifier.sendall(b'READY=1')
        inhibitor = subprocess.Popen(['systemd-inhibit', '--what=sleep', '--mode=block', '--who=T3 Code Realms',
                                     '--why=Omarchy VM realm', 'sleep', 'infinity'],
                                    env=host_control_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        jobs, finished = {}, {}
        try:
            while True:
                record = vm.record(vm_id)
                if record['compute_generation'] != incarnation or record['status'] not in {'starting', 'running'}: return
                if record['status'] == 'running' and time.time() - record['last_activity'] >= record['idle_ttl']:
                    with vm.registry.lock():
                        current = vm.registry.get(vm_id)
                        if current['compute_generation'] == incarnation and time.time() - current['last_activity'] >= current['idle_ttl']:
                            current['status'] = 'stopping'; vm.registry.put(current); return
                    continue
                from .vm_lifetime import startup_abandoned
                if startup_abandoned(record): return
                if record['status'] == 'starting' and time.time() - record['startup_at'] > (6000 if record.get('setup_base') else 1000): return
                if record['status'] == 'running': vm.validate(vm_id)
                reap_jobs(jobs, finished)
                for process, metadata in jobs.values():
                    if metadata.get('guest_control') and process.poll() is None:
                        try: process.stdin.write(b'HEARTBEAT\n'); process.stdin.flush()
                        except (OSError, BrokenPipeError): pass
                readers = [pipe for process, _ in jobs.values() for pipe in (process.stdout, process.stderr) if pipe and not pipe.closed]
                readable, _, _ = select.select([control, *readers], [], [], 0.2)
                if control not in readable: continue
                with control.accept()[0] as connection:
                    connection.settimeout(5)
                    try:
                        pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if uid != os.getuid(): raise OwnershipError('Foreign VM RPC peer')
                        with connection.makefile('rb') as stream: line = stream.readline(1024 * 1024)
                        if not line.endswith(b'\n'): raise ValueError('Incomplete or excessive VM RPC frame')
                        request = json.loads(line)
                        if request.get('client_process') != identity(pid): raise OwnershipError('VM RPC peer identity changed')
                        record = vm.validate(vm_id)
                        admit_job(jobs, request)
                        if request['op'] == 'exec':
                            argv, guest_control = command_argv(vm, record, request['command'], request.get('cwd'))
                            job_id = uuid.uuid4().hex
                            paths = {key + '_path': str(runtime / (job_id + '.' + key)) for key in ('stdout', 'stderr')}
                            for path in paths.values():
                                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600); os.close(fd)
                            process = subprocess.Popen(argv, env=host_control_env(), cwd=runtime, stdin=subprocess.PIPE if guest_control else subprocess.DEVNULL,
                                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                            os.set_blocking(process.stdout.fileno(), False); os.set_blocking(process.stderr.fileno(), False)
                            metadata = dict(paths, job_id=job_id, pid=process.pid, start_time=(identity(process.pid) or {}).get('start_time'),
                                            guest_control=guest_control, output_complete=False, stdout_truncated=False, stderr_truncated=False,
                                            result_retention_seconds=JOB_RETENTION_SECONDS, output_limit_bytes=OUTPUT_LIMIT_BYTES)
                            jobs[job_id] = process, metadata; result = metadata
                        elif request['op'] == 'job':
                            process, metadata = jobs[request['job_id']]
                            result = dict(metadata, returncode=process.poll())
                            if result['returncode'] is not None:
                                for key in ('stdout', 'stderr'): result[key] = Path(metadata[key + '_path']).read_bytes()[:OUTPUT_LIMIT_BYTES].decode('utf-8', 'replace')
                        elif request['op'] == 'signal':
                            from .errors import signal_number
                            process, metadata = jobs[request['job_id']]
                            number = signal_number(request['signal'])
                            if process.poll() is None:
                                if identity(process.pid) != {'pid': metadata['pid'], 'start_time': metadata['start_time']}:
                                    raise OwnershipError('VM command PID was replaced')
                                if metadata['guest_control']:
                                    process.stdin.write(f'SIGNAL:{number}\n'.encode()); process.stdin.flush()
                                else: os.killpg(process.pid, number)
                            result = True
                        else: raise ValueError('Unsupported VM RPC operation')
                        response = {'result': result}
                    except Exception as exc:
                        from .errors import error_code
                        response = {'error': str(exc), 'code': error_code(exc)}
                    try: connection.sendall(json.dumps(response).encode() + b'\n')
                    except BrokenPipeError: pass
        finally:
            for process, _ in jobs.values():
                if process.stdin is not None: process.stdin.close()
            inhibitor.terminate()
            inhibitor.wait(timeout=2)

if __name__ == '__main__': run(*sys.argv[1:4])
