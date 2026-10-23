"""One request, one JSON response. Native operations are explicit commands."""
import argparse
import json
import os
import select
import time
import sys
from .config import effective_home, validate_owner
from .errors import error_code

COMMAND_FIELDS = {
    'doctor': set(), 'list': {'owner'}, 'start': {'owner', 'config'},
    'stop': {'id', 'owner'}, 'stop_owner': {'owner'},
    'exec': {'id', 'owner', 'argv', 'cwd'}, 'job': {'id', 'owner', 'job_id'},
    'signal': {'id', 'owner', 'job_id', 'signal'},
    'shot': {'id', 'owner', 'format', 'quality', 'scale'},
    'resize': {'id', 'owner', 'size'}, 'outputs': {'id', 'owner'},
    'windows': {'id', 'owner'}, 'touch': {'id', 'owner'}, 'vnc_endpoint': {'id', 'owner'},
    'driver_status': set(), 'driver_launcher': {'id', 'owner'},
    'delete_snapshot': {'id', 'owner'}, 'delete': {'id', 'owner', 'token'},
    'job_start': {'kind', 'owner', 'input'}, 'job_status': {'job_id'},
    'job_cancel': {'job_id'}, 'job_list': {'owner'}, 'job_run': {'job_id'},
}


def public_record(record):
    return dict(record, owner=record['session_id'])


def dispatch(home, command, data):
    home = effective_home(home)
    if not isinstance(data, dict) or set(data) - COMMAND_FIELDS[command]:
        raise ValueError('input must be an object containing only fields for this command')
    if 'owner' in data:
        validate_owner(data['owner'])
    if command == 'doctor':
        from .diagnostics import doctor
        return doctor(home)
    if command == 'driver_status':
        from .diagnostics import driver_status
        return driver_status(home)
    if command.startswith('job_'):
        from .jobs import Jobs
        jobs = Jobs(home)
        if command == 'job_start':
            return jobs.start(data['kind'], owner=data.get('owner'), input=data.get('input', {}))
        if command == 'job_status':
            return jobs.status(data['job_id'])
        if command == 'job_cancel':
            return jobs.cancel(data['job_id'])
        if command == 'job_list':
            return jobs.list(owner=data.get('owner'))
        return jobs.run(data['job_id'])
    from .manager import Manager
    manager = Manager(home, config=data.get('config', {}))
    if command == 'list':
        return manager.list(data.get('owner'))
    if command == 'start':
        return blocking_start(home, data['owner'], data.get('config', {}))
    if command == 'stop_owner':
        return manager.stop_owner(data['owner'])
    realm_id = data['id']
    # Every realm operation, including idempotent Stop, resolves the same
    # durable ownership receipt before it can touch compute or workspace data.
    manager.record(realm_id, owner=data.get('owner'))
    if command == 'stop':
        return manager.stop(realm_id)
    if command == 'exec':
        return manager.exec(realm_id, data['argv'], cwd=data.get('cwd'))
    if command == 'job':
        return manager.job(realm_id, data['job_id'])
    if command == 'signal':
        return manager.signal(realm_id, data['job_id'], data['signal'])
    if command == 'shot':
        return manager.shot(realm_id, format=data.get('format', 'png'),
                            quality=data.get('quality'), scale=data.get('scale', 1))
    if command == 'resize':
        return public_record(manager.resize(realm_id, data['size']))
    if command == 'outputs':
        return manager.outputs(realm_id)
    if command == 'windows':
        return manager.windows(realm_id)
    if command == 'touch':
        return public_record(manager.touch(realm_id))
    if command == 'vnc_endpoint':
        return manager.vnc_endpoint(realm_id, owner=data.get('owner'))
    if command == 'driver_launcher':
        from .driver import create_driver_launcher
        return {'path': create_driver_launcher(manager, realm_id)}
    if command == 'delete_snapshot':
        return manager.delete_snapshot(realm_id, session_id=data['owner'])
    if command == 'delete':
        return manager.delete(realm_id, session_id=data['owner'], token=data.get('token'))
    raise ValueError('unknown command')



def blocking_start(home, owner, config):
    from .jobs import Jobs
    from .errors import coded_error
    # A bounded caller wait leaves cleanup with an independently owned runner.
    # SIGTERM after the deadline asks that runner to retire its partial startup.
    deadline = time.monotonic() + 29
    jobs = Jobs(home)
    job_id = jobs.start('start', owner=owner, input={'config': config})['job_id']
    record = jobs.status(job_id)
    if record['state'] not in {'succeeded', 'failed', 'cancelled'}:
        try:
            descriptor = os.pidfd_open(record['process']['pid'])
        except ProcessLookupError:
            descriptor = None
        if descriptor is not None:
            try:
                exited = select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0]
            finally:
                os.close(descriptor)
            if not exited:
                jobs.cancel(job_id)
                raise TimeoutError('realm startup timed out; cleanup requested for job ' + job_id)
        record = jobs.status(job_id)
    if record['state'] != 'succeeded':
        raise coded_error(record.get('code', 'failed'), record.get('error', 'realm startup failed'))
    return record['result']

def reject_constant(value):
    raise ValueError('nonfinite JSON number: ' + value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', required=True)
    parser.add_argument('command', choices=COMMAND_FIELDS)
    parser.add_argument('--input', default='{}')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if len(args.input.encode('utf-8')) > 1024 * 1024:
            raise ValueError('input exceeds 1 MiB')
        data = json.loads(args.input, parse_constant=reject_constant)
        result = dispatch(args.home, args.command, data)
        if args.command in {'start', 'job_start', 'driver_launcher', 'stop', 'stop_owner',
                            'delete', 'list', 'job_list', 'job_status', 'job_cancel'}:
            from .runtime_store import prune_runtime
            from .lifecycle import OwnershipError
            try:
                prune_runtime(args.home)
            except (OwnershipError, OSError) as exc:
                # GC must not turn a committed spawn/stop into an apparent
                # failure. Unverified trees stay in place for inspection.
                print('runtime copy pruning deferred: ' + str(exc), file=sys.stderr)
        response = {'ok': True, 'result': result}
        line = json.dumps(response, ensure_ascii=True, allow_nan=False)
    except Exception as exc:
        line = json.dumps({'ok': False, 'code': error_code(exc), 'error': str(exc)}, ensure_ascii=True)
    print(line, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
