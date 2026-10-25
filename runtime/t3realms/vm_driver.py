"""Cold guest driver staging is a detached job, never a 30-second host call."""
from pathlib import Path
from .jobs import Jobs
from .errors import coded_error


def launcher(vm, vm_id):
    record = vm.validate(vm_id)
    path = Path(record['runtime_dir']) / 'cua-vm'
    if path.exists():
        from .vm_cua import VmDriverProxy, _read_private
        import json
        VmDriverProxy(vm, json.loads(_read_private(path.parent / 'cua-proxy.json'))).check()
        return {'path': str(path)}
    jobs = Jobs(vm.home)
    relevant = [job for job in jobs.list(owner=record['session_id']) if job['kind'] == 'vm_driver'
                and job.get('input', {}).get('id') == vm_id
                and job['input'].get('incarnation') == record['compute_generation']]
    latest = max(relevant, key=lambda job: (job['created_at'], job['job_id']), default=None)
    if latest is not None:
        if latest['state'] in ('queued', 'running'):
            return {'starting': {'job_id': latest['job_id'], 'state': latest['state'],
                                 'progress': latest.get('progress'), 'poll_after_ms': 2000}}
        raise coded_error(latest.get('code', 'failed'),
                          f"Guest GUI-driver preparation job {latest['job_id']} {latest['state']}: "
                          + latest.get('error', 'The prepared guest launcher is missing')
                          + '. No requested GUI input was sent. Inspect this cause before one explicit Repair; '
                          'Realm terminal and shot remain available.')
    job = jobs.start('vm_driver', owner=record['session_id'], input={'id': vm_id, 'incarnation': record['compute_generation']})
    return {'starting': job}
