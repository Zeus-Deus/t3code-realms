import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import signal
import tempfile
import time
import unittest
from unittest.mock import patch
from support import cli, await_process
from t3realms.jobs import Jobs, RECORD_LIMIT
from t3realms.lifecycle import identity, OwnershipError


class JobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='t3r-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.jobs = Jobs(self.home)
        self.active = []
        self.addCleanup(self.stop_test_jobs)

    def stop_test_jobs(self):
        for job_id in self.active:
            try:
                record = self.jobs.cancel(job_id)
                await_process(record.get('process'))
            except (FileNotFoundError, ProcessLookupError):
                pass

    def start(self, payload=None):
        result = cli(self.home, 'job_start', {'kind': 'selftest', 'owner': 'thread:jobs', 'input': payload or {}})
        self.assertTrue(result['ok'], result)
        job_id = result['result']['job_id']
        self.active.append(job_id)
        return job_id

    def complete(self, job_id):
        record = self.jobs.status(job_id)
        await_process(record['process'])
        response = cli(self.home, 'job_status', {'job_id': job_id})
        self.assertTrue(response['ok'], response)
        return response['result']

    def test_selftest_success_persistence_and_log_permissions(self):
        job_id = self.start()
        result = self.complete(job_id)
        self.assertEqual(result['state'], 'succeeded')
        self.assertEqual(result['result'], {'completed': True})
        self.assertEqual(result['owner'], 'thread:jobs')
        self.assertEqual(self.jobs.path(job_id).stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.home / 'jobs' / (job_id + '.log')).stat().st_mode & 0o777, 0o600)
        self.assertEqual(cli(self.home, 'job_list', {'owner': 'thread:jobs'})['result'][0], result)
        self.assertEqual(cli(self.home, 'job_list', {'owner': 'else'})['result'], [])

    def test_selftest_failure(self):
        result = self.complete(self.start({'fail': True}))
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['code'], 'failed')
        self.assertIn('selftest', result['error'])

    def test_active_jobs_reuse_one_verified_runtime_copy(self):
        first = self.jobs.status(self.start({'seconds': 30}))
        payload = Path(first['runtime_copy'])
        inode = payload.stat().st_ino
        second = self.jobs.status(self.start({'seconds': 30}))
        self.assertEqual(second['runtime_copy'], str(payload))
        self.assertEqual(payload.stat().st_ino, inode)
        self.assertEqual([path for path in (self.home / 'runtime').iterdir() if path.is_dir()], [payload])

    def test_cancel_owned_process_group(self):
        job_id = self.start({'seconds': 30})
        record = self.jobs.status(job_id)
        self.assertEqual(os.getsid(record['process']['pid']), record['process']['pid'])
        self.assertEqual(os.getpgid(record['process']['pid']), record['process']['pid'])
        response = cli(self.home, 'job_cancel', {'job_id': job_id})
        self.assertTrue(response['ok'], response)
        result = self.complete(job_id)
        self.assertEqual(result['state'], 'cancelled', result)
        self.assertEqual(result['code'], 'cancelled')

    def test_sigkill_is_visible_interrupted_failure(self):
        job_id = self.start({'seconds': 30})
        record = self.jobs.status(job_id)
        # This PID came directly from our spawn receipt, never a pattern search.
        self.assertEqual(identity(record['process']['pid']), record['process'])
        os.kill(record['process']['pid'], signal.SIGKILL)
        result = self.complete(job_id)
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['code'], 'interrupted')

    def test_pid_reuse_receipt_is_never_signalled(self):
        job_id = self.start({'seconds': 30})
        record = self.jobs.status(job_id)
        original = dict(record['process'])
        record['process'] = dict(original, start_time=original['start_time'] + 1)
        with self.jobs.lock():
            self.jobs.put(record)
        with patch('t3realms.jobs.os.killpg') as kill:
            result = self.jobs.cancel(job_id)
            self.assertEqual(result['code'], 'interrupted')
            kill.assert_not_called()
        # Restore only this fixture's captured receipt so cleanup can cancel it.
        record.update(process=original, state='running')
        with self.jobs.lock():
            self.jobs.put(record)

    def test_busy_admission_for_owner_start_and_global_install(self):
        job_id = self.start({'seconds': 30})
        original = self.jobs.status(job_id)
        for kind in ('start', 'driver_install'):
            record = dict(original, kind=kind)
            with self.jobs.lock():
                self.jobs.put(record)
            response = cli(self.home, 'job_start', {'kind': kind, 'owner': 'thread:jobs', 'input': {}})
            self.assertEqual(response['code'], 'busy', response)
            if kind == 'driver_install':
                response = cli(self.home, 'job_start', {'kind': kind, 'owner': 'other', 'input': {}})
                self.assertEqual(response['code'], 'busy')
        with self.jobs.lock():
            self.jobs.put(original)

    def test_job_pruning_age_bound_and_order(self):
        now = time.time()
        for index in range(RECORD_LIMIT + 5):
            job_id = f'{index + 1:032x}'
            self.jobs.put({'job_id': job_id, 'kind': 'selftest', 'owner': 'x',
                           'state': 'succeeded', 'created_at': now + index,
                           'updated_at': now, 'process': None})
        stale_id = 'f' * 32
        self.jobs.put({'job_id': stale_id, 'kind': 'selftest', 'owner': 'x',
                       'state': 'failed', 'created_at': now - 90000,
                       'updated_at': now - 90000, 'process': None})
        result = cli(self.home, 'job_list')['result']
        self.assertEqual(len(result), RECORD_LIMIT)
        self.assertEqual(result[0]['job_id'], f'{RECORD_LIMIT + 5:032x}')
        self.assertEqual(result[-1]['job_id'], f'{6:032x}')
        self.assertFalse(self.jobs.path(stale_id).exists())

    def test_job_inputs_fail_before_spawn(self):
        for data in ({'kind': 'start', 'input': {}}, {'kind': 'selftest', 'input': {'seconds': -1}},
                     {'kind': 'selftest', 'input': {'seconds': True}},
                     {'kind': 'driver_install', 'input': {'archive': 'relative'}}):
            self.assertEqual(cli(self.home, 'job_start', data)['code'], 'invalid_input')
        self.assertEqual(self.jobs.list(), [])

    def test_symlink_record_is_refused(self):
        target = self.home / 'else.json'
        target.write_text('{}')
        self.jobs.path('a' * 32).symlink_to(target)
        with self.assertRaises(OwnershipError):
            self.jobs.status('a' * 32)

    def test_cancelled_start_runner_stops_its_prepared_incarnation(self):
        from unittest.mock import MagicMock
        from t3realms.jobs import Cancelled
        now = time.time()
        job_id = 'e' * 32
        prepared = {'id': 'r-' + 'a' * 24, 'generation': 'b' * 32}
        manager = MagicMock()
        manager.record.return_value = prepared
        def start(owner, before_start):
            before_start(prepared=prepared)
            raise Cancelled()
        manager.start.side_effect = start
        self.jobs.put({'job_id': job_id, 'kind': 'start', 'owner': 'x', 'input': {'config': {}},
                       'state': 'queued', 'created_at': now, 'updated_at': now,
                       'process': identity(os.getpid())})
        with patch('t3realms.manager.Manager', return_value=manager):
            result = self.jobs.run(job_id)
        self.assertEqual(result['state'], 'cancelled')
        manager.stop.assert_called_once_with(prepared['id'])
        self.assertEqual(result['progress']['generation'], prepared['generation'])
