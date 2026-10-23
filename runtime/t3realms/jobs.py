"""Detached, durable operations with process-incarnation ownership receipts."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

from .config import Config, effective_home, private_directory, validate_owner, finite_number
from .errors import error_code
from .lifecycle import (BusyError, NotFoundError, OwnershipError, RealmError,
                        alive, atomic_json, identity, private_json)

TERMINAL = {'succeeded', 'failed', 'cancelled'}
RETENTION_SECONDS = 86400
RECORD_LIMIT = 200


class Cancelled(BaseException):
    pass


class Jobs:
    def __init__(self, home):
        self.home = effective_home(home)
        self.root = private_directory(self.home / 'jobs')

    @contextmanager
    def lock(self, *, blocking=True):
        # Delivery after releasing the lock keeps cancellation from interrupting
        # the runner's terminal publication or stranding a critical section.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        descriptor = None
        try:
            descriptor = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise OwnershipError('job lock ownership changed')
            fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield
        finally:
            if descriptor is not None:
                os.close(descriptor)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def path(self, job_id):
        if not isinstance(job_id, str) or not re.fullmatch('[0-9a-f]{32}', job_id):
            raise ValueError('invalid job id')
        return self.root / (job_id + '.json')

    def get(self, job_id):
        path = self.path(job_id)
        if not path.exists() and not path.is_symlink():
            raise NotFoundError('job not found: ' + job_id)
        record = private_json(path)
        if (not isinstance(record, dict) or record.get('job_id') != job_id
                or record.get('kind') not in ('start', 'driver_install', 'selftest')
                or record.get('state') not in TERMINAL | {'queued', 'running'}):
            raise OwnershipError('job ownership receipt changed')
        process = record.get('process')
        if 'runtime_copy' in record:
            from .runtime_store import runtime_reference
            runtime_reference(self.home, record['runtime_copy'])
        if process is not None and (not isinstance(process, dict) or set(process) != {'pid', 'start_time'}
                or any(type(process[key]) is not int or process[key] <= 0 for key in process)):
            raise OwnershipError('invalid job process receipt')
        for key in ('created_at', 'updated_at'):
            value = record.get(key)
            if not finite_number(value):
                raise OwnershipError('invalid job timestamp')
        return record

    def put(self, record):
        atomic_json(self.path(record['job_id']), record)

    def reconcile(self, record):
        if record['state'] not in TERMINAL and not alive(record.get('process')):
            record.update(state='failed', code='interrupted',
                          error='Owned job process exited before recording a result', updated_at=time.time())
            self.put(record)
        return record

    def records(self):
        return [self.reconcile(self.get(path.stem)) for path in self.root.glob('*.json')]

    def prune(self, records, *, reserve=0):
        now = time.time()
        ordered = sorted(records, key=lambda record: (record['created_at'], record['job_id']), reverse=True)
        retained = []
        for record in ordered:
            if record['state'] in TERMINAL and now - record['updated_at'] > RETENTION_SECONDS:
                self.remove(record)
            else:
                retained.append(record)
        excess = max(0, len(retained) + reserve - RECORD_LIMIT)
        for record in reversed(retained.copy()):
            if not excess:
                break
            if record['state'] in TERMINAL:
                self.remove(record)
                retained.remove(record)
                excess -= 1
        return retained

    def remove(self, record):
        self.path(record['job_id']).unlink()
        (self.root / (record['job_id'] + '.log')).unlink(missing_ok=True)

    def list(self, owner=None):
        if owner is not None:
            validate_owner(owner)
        with self.lock():
            return [record for record in self.prune(self.records())
                    if owner is None or record.get('owner') == owner]

    def status(self, job_id):
        with self.lock():
            return self.reconcile(self.get(job_id))

    def start(self, kind, *, owner=None, input=None):
        if kind not in ('start', 'driver_install', 'selftest'):
            raise ValueError('kind must be start, driver_install, or selftest')
        payload = {} if input is None else input
        if not isinstance(payload, dict):
            raise ValueError('job input must be an object')
        if owner is not None:
            validate_owner(owner)
        if kind == 'start':
            validate_owner(owner)
            if set(payload) - {'config'}:
                raise ValueError('unknown start job input field')
            Config.from_object(payload.get('config', {}))
        elif kind == 'driver_install':
            if set(payload) - {'archive'}:
                raise ValueError('unknown driver_install input field')
            if 'archive' in payload and (not isinstance(payload['archive'], str)
                    or not Path(payload['archive']).is_absolute() or '\0' in payload['archive']):
                raise ValueError('archive must be an absolute NUL-free path')
        else:
            seconds = payload.get('seconds', 0)
            if (not finite_number(seconds) or not 0 <= seconds <= 3600
                    or not isinstance(payload.get('fail', False), bool)
                    or set(payload) - {'seconds', 'fail'}):
                raise ValueError('invalid selftest input')
        from .runtime_store import pinned_runtime
        with pinned_runtime(self.home) as runtime_copy, self.lock():
            records = self.prune(self.records(), reserve=1)
            for record in records:
                if record['state'] in TERMINAL:
                    continue
                if (kind == 'driver_install' and record['kind'] == kind
                        or kind == 'start' and record['kind'] == kind and record['owner'] == owner):
                    raise BusyError('an operation of this kind is already active for this owner')
            if len(records) >= RECORD_LIMIT:
                raise BusyError('job capacity reached')
            job_id = uuid.uuid4().hex
            now = time.time()
            record = {'job_id': job_id, 'kind': kind, 'owner': owner, 'state': 'queued',
                      'created_at': now, 'updated_at': now, 'process': None, 'input': payload,
                      'runtime_copy': str(runtime_copy)}
            self.put(record)
            log_path = self.root / (job_id + '.log')
            descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            env = dict(os.environ, PYTHONPATH=str(runtime_copy), PYTHONDONTWRITEBYTECODE='1')
            try:
                # lock() blocks SIGTERM. The child inherits that mask until its
                # runner installs the cancellation handler, closing the spawn race.
                with os.fdopen(descriptor, 'wb') as log:
                    process = subprocess.Popen(
                        [sys.executable, '-B', '-P', '-m', 't3realms.cli', '--home', str(self.home),
                         'job_run', '--input', json.dumps({'job_id': job_id})],
                        env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                        start_new_session=True, close_fds=True)
                process_identity = identity(process.pid)
                if process_identity is None:
                    raise RealmError('job runner exited during spawn')
                record['process'] = process_identity
                self.put(record)
            except Exception as exc:
                record.update(state='failed', code=error_code(exc), error=str(exc), updated_at=time.time())
                self.put(record)
                raise
            return {'job_id': job_id}

    def cancel(self, job_id):
        with self.lock():
            record = self.reconcile(self.get(job_id))
            if record['state'] in TERMINAL:
                return record
            process = record['process']
            try:
                if (not alive(process) or os.getpgid(process['pid']) != process['pid']
                        or os.getsid(process['pid']) != process['pid']):
                    raise OwnershipError('job process group ownership changed')
                # The second identity check is immediately adjacent to signaling.
                if not alive(process):
                    raise OwnershipError('job PID identity changed')
                os.killpg(process['pid'], signal.SIGTERM)
            except ProcessLookupError:
                return self.reconcile(record)
            return record

    def run(self, job_id):
        manager = None
        operation = None

        def cancelled(_number, _frame):
            raise Cancelled()

        def progress(value):
            with self.lock():
                current = self.get(job_id)
                current.update(progress=value, updated_at=time.time())
                self.put(current)

        def before_start(*, prepared=None):
            nonlocal operation
            if prepared is not None:
                operation = prepared
                progress({'realm_id': prepared['id'], 'generation': prepared['generation']})

        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        previous = signal.signal(signal.SIGTERM, cancelled)
        try:
            try:
                # The parent publishes the runner PID before releasing this lock.
                with self.lock():
                    record = self.get(job_id)
                    if record['process'] != identity(os.getpid()) or record['state'] not in ('queued', 'running'):
                        raise OwnershipError('job runner identity does not own this operation')
                    record.update(state='running', updated_at=time.time())
                    self.put(record)
                signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
                payload = record['input']
                if record['kind'] == 'selftest':
                    time.sleep(payload.get('seconds', 0))
                    # Exercise a deferred package import as well as process
                    # survival when qualifying plugin-update behavior.
                    from .diagnostics import driver_status
                    driver_status(self.home)
                    if payload.get('fail'):
                        raise RealmError('selftest requested failure')
                    result = {'completed': True}
                elif record['kind'] == 'driver_install':
                    from .install_driver import install
                    from .diagnostics import driver_status
                    install(home=self.home, archive=payload.get('archive'), progress=progress)
                    result = driver_status(self.home)
                else:
                    from .manager import Manager
                    manager = Manager(self.home, config=payload.get('config', {}))
                    result = dict(manager.start(record['owner'], before_start=before_start), owner=record['owner'])
                terminal = {'state': 'succeeded', 'result': result}
            except Cancelled:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
                terminal = {'state': 'cancelled', 'code': 'cancelled', 'error': 'Operation cancelled'}
                if operation is not None and manager is not None:
                    try:
                        current = manager.record(operation['id'])
                        if current['generation'] != operation['generation']:
                            raise OwnershipError('cancelled startup incarnation changed')
                        manager.stop(current['id'])
                    except Exception as exc:
                        terminal['error'] += '; startup cleanup failed: ' + str(exc)
            except Exception as exc:
                terminal = {'state': 'failed', 'code': error_code(exc), 'error': str(exc)}
            # A second cancellation cannot interrupt a terminal publication.
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
            with self.lock():
                current = self.get(job_id)
                if current['process'] != identity(os.getpid()):
                    raise OwnershipError('job runner receipt changed')
                current.update(**terminal, updated_at=time.time())
                self.put(current)
            return current
        finally:
            signal.signal(signal.SIGTERM, previous)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
