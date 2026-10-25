# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Bounded archive transport over the generation-pinned SSH route."""
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import tempfile
import time

from .lifecycle import host_control_env
from .setup_plan import confined
from . import vm_transfer_archive as archive


def run_stream(argv, *, input_file=None, output_file=None, timeout=600):
    output, errors = bytearray(), bytearray()
    writer = archive.LimitedWriter(output_file) if output_file is not None else None
    with subprocess.Popen(argv, env=host_control_env(), stdin=input_file or subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        deadline = time.monotonic()+timeout
        try:
            assert process.stdout is not None and process.stderr is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ,'stdout')
                selector.register(process.stderr,selectors.EVENT_READ,'stderr')
                while selector.get_map():
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv,timeout)
                    for key,_ in selector.select(min(remaining,.2)):
                        data = os.read(key.fd,65536)
                        if not data:
                            selector.unregister(key.fileobj)
                        elif key.data == 'stderr':
                            errors.extend(data[:max(0,65536-len(errors))])
                        elif writer is not None:
                            writer.write(data)
                        else:
                            if len(output)+len(data)>65536:
                                raise ValueError('transfer response exceeds protocol limit')
                            output.extend(data)
            process.wait(timeout=max(.1,deadline-time.monotonic()))
            if process.returncode:
                try:
                    diagnostic = json.loads(errors)
                except ValueError:
                    diagnostic = None
                if diagnostic == {'t3realms_transfer_error':'conflict'}:
                    raise ValueError(archive.CONFLICT_MESSAGE)
                raise subprocess.CalledProcessError(process.returncode,argv,
                    output=bytes(output).decode('utf-8','replace'),stderr=bytes(errors).decode('utf-8','replace'))
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def _scratch(home):
    path = confined(home,Path(home)/'cache'/'realms-transfers')
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(path,0o700)
    return path


def _command(manager, record, operation, path, *, user):
    code = Path(archive.__file__).read_text(encoding='utf-8')
    return [*manager.ssh_argv(record,user=user),'--',
            shlex.join(['python3','-I','-S','-c',code,operation,str(path)])]


def push(manager, vm_id, source, destination):
    record = manager.validate(vm_id)
    local = Path(source).expanduser().absolute()
    with tempfile.TemporaryFile(dir=_scratch(manager.home)) as stream:
        # Seal and validate the entire selected tree before any upload. SCP -r
        # follows links; no path on the live source tree reaches SSH here.
        archive.pack(local,stream)
        stream.seek(0)
        remote = str(destination) if destination is not None else str(Path(manager.guest_home(vm_id))/local.name)
        user = manager.guest_user(vm_id)
        prepared = manager.guest_run(vm_id,['mkdir','-p','--',str(Path(remote).parent)],user=user)
        if prepared['returncode']:
            from .vm_manager import VmError
            raise VmError('guest workspace destination is not writable by the desktop user')
        record = manager.validate(vm_id)
        response = run_stream(_command(manager,record,'unpack',remote,user=user),input_file=stream)
        actual = json.loads(response)['destination']
    return {'source':str(local),'destination':actual}


def pull(manager, vm_id, source, destination):
    record = manager.validate(vm_id)
    with tempfile.TemporaryFile(dir=_scratch(manager.home)) as stream:
        run_stream(_command(manager,record,'pack',source,user='root'),output_file=stream)
        stream.seek(0)
        manager.validate(vm_id)
        actual = archive.unpack(stream,destination)
    return {'source':str(source),'destination':actual}
