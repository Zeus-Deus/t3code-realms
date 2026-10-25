"""Synchronous vendor lifecycle hooks, never inferred from installation logs."""
import json
import os
from pathlib import Path
import sys
if __package__ in (None, ''):
    import runpy
    __package__ = runpy.run_path(str(Path(__file__).with_name('_binding.py')))['load_runtime']().__name__
from .vm_manager import VmManager
from .lifecycle import OwnershipError, scope_info


def report(home, vm_id, incarnation, job_id, stage):
    vm = VmManager(home)
    with vm.registry.lock():
        record = vm.registry.get(vm_id)
        if record['compute_generation'] != incarnation or record['status'] != 'starting':
            raise OwnershipError('VM setup/start was cancelled or replaced')
        if stage == 'launched':
            info = scope_info(record['unit'])
            if info['ActiveState'] != 'active' or info.get('Description') != 'T3 Code VM ' + incarnation:
                raise OwnershipError('VM launch hook observed a foreign unit')
            record.update(invocation_id=info['InvocationID'], cgroup=info['ControlGroup'])
            record.pop('launch_pending', None)
            vm.registry.put(record)
    if job_id is not None:
        from .jobs import Jobs
        jobs = Jobs(home)
        with jobs.lock():
            job = jobs.get(job_id)
            job.update(progress={'stage': stage, 'realm_id': vm_id}, updated_at=__import__('time').time())
            jobs.put(job)

if __name__ == '__main__':
    args = json.loads(sys.argv[1]); report(*args[1:], sys.argv[2])
