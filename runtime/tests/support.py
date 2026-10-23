import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os
import select
import subprocess
import time
import uuid
from t3realms.lifecycle import Registry
from t3realms.workspace import create

RUNTIME = Path(__file__).resolve().parents[1]
CLI = RUNTIME / 't3realms_cli.py'


def cli(home, command, data=None, *, env=None, entry=CLI):
    process = subprocess.run([sys.executable, '-I', '-B', str(entry), '--home', str(home),
                              command, '--input', json.dumps({} if data is None else data)],
                             capture_output=True, text=True, env=env, timeout=35 if command == 'start' else 15)
    if process.returncode or len(process.stdout.splitlines()) != 1:
        raise AssertionError((process.returncode, process.stdout, process.stderr))
    response = json.loads(process.stdout)
    if response.get('ok') is True and set(response) != {'ok', 'result'}:
        raise AssertionError(response)
    if response.get('ok') is False and set(response) != {'ok', 'code', 'error'}:
        raise AssertionError(response)
    return response


def stopped_record(home, owner='thread:test'):
    registry = Registry(home)
    generation = uuid.uuid4().hex
    record = {'id': 'r-' + generation[:24], 'session_id': owner, 'generation': generation,
              'uid': os.getuid(), 'home': str(home),
              'runtime_dir': f'/run/user/{os.getuid()}/t3r-{generation[:16]}',
              'scope': f't3code-realm-{generation}.scope',
              'guardian_unit': f't3code-realm-{generation}-guard.service',
              'status': 'stopped', 'size': '1920x1080', 'renderer': 'gles2',
              'overlay': True, 'cursor_theme': 'cua.default', 'idle_ttl': 1800,
              'created_at': time.time(), 'last_activity': time.time()}
    create(record)
    registry.put(record)
    return record


def await_process(process, *, timeout=12):
    if process is None:
        return
    try:
        descriptor = os.pidfd_open(process['pid'])
    except ProcessLookupError:
        return
    try:
        if not select.select([descriptor], [], [], timeout)[0]:
            raise AssertionError('owned test process did not exit')
    finally:
        os.close(descriptor)
