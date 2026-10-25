"""Interrupted VM lifecycle and detached failure regressions, with fake compute."""
import copy
import os
from pathlib import Path
import sys
import subprocess
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_vm
from t3realms import vm_workspace
from t3realms.errors import CodedError
from t3realms.jobs import Cancelled, Jobs
from t3realms.lifecycle import OwnershipError, identity


class VmRuntimeRegression(unittest.TestCase):
    def setUp(self):
        fixture = test_vm.VmLifecycle('test_stop_resume_keeps_disk_and_rotates_compute_identity')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.vm, self.home, self.active = fixture.vm, fixture.home, fixture.active

    def test_interruption_after_durable_pin_preserves_resumable_workspace(self):
        original = vm_workspace.retain_pin
        saved = {}
        def interrupted(record):
            original(record)
            saved.update(copy.deepcopy(record))
            raise OSError('interrupted after durable pin')
        with patch.object(vm_workspace, 'retain_pin', side_effect=interrupted):
            with self.assertRaisesRegex(OSError, 'after durable pin'):
                self.vm.start('thread:owner')
        stopped = self.vm.list()[0]
        self.assertEqual(stopped['status'], 'stopped', stopped)
        self.assertFalse(self.active)
        self.assertEqual(stopped['workspace'], saved['workspace'])
        pin = Path(stopped['session_dir']) / 'ssh_known_hosts'
        before = (pin.stat().st_ino, pin.read_bytes())
        resumed = self.vm.start('thread:owner')
        self.assertEqual(resumed['id'], stopped['id'])
        self.assertNotEqual(resumed['compute_generation'], stopped['compute_generation'])
        self.assertEqual(resumed['workspace'], stopped['workspace'])
        self.assertEqual((pin.stat().st_ino, pin.read_bytes()), before)
        self.assertTrue(resumed['vnc_socket'])

    def test_pin_receipt_is_published_before_desktop_readiness(self):
        def readiness(record, config):
            current = self.vm.record(record['id'])
            self.assertEqual(current['workspace']['pin'], record['workspace']['pin'])
            self.assertTrue(current['ssh_host_key_pinned'])
            self.assertNotIn('launch_pending', current)
        self.vm._wait_for_desktop = readiness
        self.vm.start('thread:owner')

    def interrupted_pin_publication(self):
        original = vm_workspace.retain_pin
        def interrupted(record):
            original(record)
            raise OSError('pin publication interrupted')
        with patch.object(vm_workspace, 'retain_pin', side_effect=interrupted), patch.object(
                self.vm, '_remove_locked', side_effect=SystemExit('startup process died')), patch.object(
                self.vm, '_retirement_failed'):
            with self.assertRaisesRegex(SystemExit, 'startup process died'):
                self.vm.start('thread:owner')
        record = self.vm.registry.records()[0]
        record['startup_process'] = {'pid': 2147483647, 'start_time': 1}
        self.vm.registry.put(record)
        return record

    def test_abandoned_start_recovers_only_its_durable_pin(self):
        record = self.interrupted_pin_publication()
        pin = Path(record['session_dir']) / 'ssh_known_hosts'
        before = (pin.stat().st_ino, pin.read_bytes())
        stopped = self.vm.list()[0]
        self.assertEqual(stopped['status'], 'stopped', stopped)
        self.assertFalse(self.active)
        self.assertEqual((pin.stat().st_ino, pin.read_bytes()), before)
        self.assertEqual(self.vm.start('thread:owner')['status'], 'running')

    def test_abandoned_pin_enrollment_rejects_replaced_pin_even_with_identical_bytes(self):
        record = self.interrupted_pin_publication()
        pin = Path(record['session_dir']) / 'ssh_known_hosts'
        replacement = pin.with_name('replacement')
        replacement.write_bytes(pin.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, pin)
        self.assertEqual(self.vm.list()[0]['status'], 'recovery-required')
        with self.assertRaisesRegex(RuntimeError, 'recovery'):
            self.vm.start('thread:owner')

    def test_abandoned_pin_enrollment_rejects_changed_bytes(self):
        record = self.interrupted_pin_publication()
        pin = Path(record['session_dir']) / 'ssh_known_hosts'
        pin.write_bytes(b'replacement guest key\n')
        self.assertEqual(self.vm.list()[0]['status'], 'recovery-required')
        self.assertEqual(pin.read_bytes(), b'replacement guest key\n')

    def test_resume_does_not_reenroll_a_substituted_retained_pin(self):
        record = self.vm.start('thread:owner')
        self.vm.stop(record['id'])
        pin = Path(record['session_dir']) / 'ssh_known_hosts'
        original_receipt = record['workspace']['pin']
        launch = self.vm._run_script
        def substituted(*args, **kwargs):
            launch(*args, **kwargs)
            replacement = pin.with_name('replacement')
            replacement.write_bytes(pin.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, pin)
        self.vm._run_script = substituted
        with self.assertRaisesRegex(OwnershipError, 'pin'):
            self.vm.start('thread:owner')
        current = self.vm.list()[0]
        self.assertEqual(current['status'], 'recovery-required')
        self.assertEqual(current['workspace']['pin'], original_receipt)

    def test_obsolete_failed_start_does_not_retire_resumed_compute(self):
        record = self.vm.start('thread:owner')
        self.vm.stop(record['id'])
        saved = {}
        def readiness(old, config):
            self.vm.stop(old['id'])
            self.vm._wait_for_desktop = lambda *args: None
            saved.update(self.vm.start('thread:owner'))
            raise OSError('obsolete startup failed')
        self.vm._wait_for_desktop = readiness
        with self.assertRaisesRegex(OSError, 'obsolete startup failed'):
            self.vm.start('thread:owner')
        current = self.vm.validate(record['id'])
        self.assertEqual(current['compute_generation'], saved['compute_generation'])
        self.assertIn(current['unit'], self.active)
        self.assertEqual(current['workspace'], saved['workspace'])

    def test_known_deletion_tombstone_does_not_block_peer(self):
        record = self.vm.start('thread:owner')
        self.vm.stop(record['id'])
        review = self.vm.delete_snapshot(record['id'], session_id='thread:owner')
        session = Path(record['session_dir'])
        tombstone = session.with_name('.' + session.name + '.deleting')
        original = vm_workspace.shutil.rmtree
        def interrupted(path, *args, **kwargs):
            if Path(path) == tombstone:
                raise OSError('interrupted deletion')
            return original(path, *args, **kwargs)
        with patch.object(vm_workspace.shutil, 'rmtree', side_effect=interrupted):
            with self.assertRaisesRegex(OSError, 'interrupted deletion'):
                self.vm.delete(record['id'], session_id='thread:owner', token=review['token'])
        inode = tombstone.stat().st_ino
        peer = self.vm.start('thread:peer')
        self.assertEqual(peer['status'], 'running')
        self.assertEqual(tombstone.stat().st_ino, inode)
        review = self.vm.delete_snapshot(record['id'], session_id='thread:owner')
        self.vm.delete(record['id'], session_id='thread:owner', token=review['token'])
        self.assertFalse(tombstone.exists())
        self.assertEqual(self.vm.validate(peer['id'])['status'], 'running')

    def test_unregistered_hidden_directory_still_blocks_fresh_allocation(self):
        orphan = self.vm.registry.root / 'vm' / ('.' + 'f' * 32 + '.deleting')
        orphan.mkdir(parents=True, mode=0o700)
        with self.assertRaisesRegex(OwnershipError, 'Unregistered VM workspace'):
            self.vm.start('thread:peer')
        self.assertTrue(orphan.is_dir())
        self.assertFalse(self.active)

    def test_tombstone_without_bound_deletion_intent_still_blocks_peer(self):
        record = self.vm.start('thread:owner')
        self.vm.stop(record['id'])
        session = Path(record['session_dir'])
        tombstone = session.with_name('.' + session.name + '.deleting')
        tombstone.mkdir(mode=0o700)
        with self.assertRaisesRegex(OwnershipError, 'Unregistered VM workspace'):
            self.vm.start('thread:peer')
        self.assertTrue(tombstone.exists())

    def put_job(self, kind, payload, *, state='running', error=None):
        jobs = Jobs(self.home)
        job_id = ('e' if kind == 'start' else 'd') * 32
        now = time.time()
        record = {'job_id': job_id, 'kind': kind, 'owner': 'thread:owner',
                  'input': payload, 'state': state, 'created_at': now, 'updated_at': now,
                  'process': identity(os.getpid())}
        if error:
            record.update(code='failed', error=error)
        jobs.put(record)
        return jobs, job_id

    def test_guest_stage_failure_keeps_the_remote_cause_without_inline_source(self):
        from t3realms.vm_cua import _remote
        failure = subprocess.CalledProcessError(
            1, ['ssh', '--', 'inline guest source should not enter the diagnostic'],
            stderr=b'Traceback (most recent call last):\nValueError: CUA asset checksum mismatch\n')
        with patch('t3realms.vm_cua._guest_command', return_value=failure.cmd), patch(
                't3realms.vm_cua.subprocess.run', side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, 'stage failed.*CUA asset checksum mismatch') as caught:
                _remote(self.vm, {}, 'guest', 'stage', data=b'corrupt packet')
        self.assertNotIn('inline guest source', str(caught.exception))
        self.assertLess(len(str(caught.exception)), 1000)

    def test_failed_driver_staging_is_reported_without_automatic_retry(self):
        from t3realms.vm_driver import launcher
        record = self.vm.start('thread:owner')
        payload = {'id': record['id'], 'incarnation': record['compute_generation']}
        jobs, job_id = self.put_job('vm_driver', payload, state='failed', error='Guest driver checksum mismatch')
        with patch.object(Jobs, 'start') as start:
            for _ in range(2):
                with self.assertRaisesRegex(CodedError, 'Guest driver checksum mismatch') as caught:
                    launcher(self.vm, record['id'])
                self.assertEqual(caught.exception.code, 'failed')
                self.assertIn(job_id, str(caught.exception))
            start.assert_not_called()
        self.assertEqual(jobs.status(job_id)['state'], 'failed')

    def test_driver_staging_never_joins_an_older_incarnation(self):
        from t3realms.vm_driver import launcher
        record = self.vm.start('thread:owner')
        self.put_job('vm_driver', {'id': record['id'], 'incarnation': 'f' * 32})
        with patch.object(Jobs, 'start', return_value={'job_id': 'a' * 32}) as start:
            result = launcher(self.vm, record['id'])
        self.assertEqual(result['starting']['job_id'], 'a' * 32)
        start.assert_called_once_with('vm_driver', owner='thread:owner', input={
            'id': record['id'], 'incarnation': record['compute_generation']})

    def test_driver_worker_failure_is_terminal_and_visible_to_launcher(self):
        from t3realms.vm_driver import launcher
        record = self.vm.start('thread:owner')
        jobs, job_id = self.put_job('vm_driver', {'id': record['id'], 'incarnation': record['compute_generation']})
        with patch('t3realms.vm_manager.VmManager', return_value=self.vm), patch(
                't3realms.vm_cua.create_vm_driver_launcher', side_effect=ValueError('Guest driver checksum mismatch')):
            result = jobs.run(job_id)
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['code'], 'invalid_input')
        self.assertEqual(result['progress'], {'stage': 'staging guest driver'})
        self.assertIn('Guest driver checksum mismatch', result['error'])
        with patch.object(Jobs, 'start') as start:
            with self.assertRaisesRegex(CodedError, 'Guest driver checksum mismatch'):
                launcher(self.vm, record['id'])
            start.assert_not_called()

    def test_interrupted_driver_worker_remains_a_terminal_failure(self):
        from t3realms.vm_driver import launcher
        record = self.vm.start('thread:owner')
        jobs, job_id = self.put_job('vm_driver', {'id': record['id'], 'incarnation': record['compute_generation']})
        job = jobs.get(job_id)
        job['process'] = {'pid': 2147483647, 'start_time': 1}
        jobs.put(job)
        with patch.object(Jobs, 'start') as start:
            with self.assertRaisesRegex(CodedError, 'Owned job process exited') as caught:
                launcher(self.vm, record['id'])
            self.assertEqual(caught.exception.code, 'interrupted')
            start.assert_not_called()
        self.assertEqual(jobs.status(job_id)['state'], 'failed')

    def test_latest_explicit_driver_retry_supersedes_previous_failure(self):
        from t3realms.vm_driver import launcher
        record = self.vm.start('thread:owner')
        payload = {'id': record['id'], 'incarnation': record['compute_generation']}
        jobs, old = self.put_job('vm_driver', payload, state='failed', error='old failure')
        retry = dict(jobs.status(old), job_id='a' * 32, state='running', created_at=time.time() + 1)
        jobs.put(retry)
        with patch.object(Jobs, 'start') as start:
            self.assertEqual(launcher(self.vm, record['id'])['starting']['job_id'], retry['job_id'])
            start.assert_not_called()

    def test_late_boot_failure_is_terminal_and_retains_its_cause(self):
        def readiness(record, config):
            raise TimeoutError('Guest Hyprland desktop did not become ready before its boot deadline')
        self.vm._wait_for_desktop = readiness
        jobs, job_id = self.put_job('start', {'config': {'kind': 'omarchy-vm'}})
        with patch('t3realms.vm_manager.VmManager', return_value=self.vm):
            result = jobs.run(job_id)
        for result in (result, jobs.status(job_id), jobs.list(owner='thread:owner')[0]):
            self.assertEqual(result['state'], 'failed')
            self.assertEqual(result['code'], 'timeout')
            self.assertIn('Hyprland desktop', result['error'])
        self.assertEqual(self.vm.list()[0]['status'], 'stopped')
        self.assertFalse(self.active)

    def test_cancelled_job_fallback_cannot_stop_newer_compute(self):
        first = self.vm.start('thread:owner')
        self.vm.stop(first['id'])
        real_start = self.vm.start
        saved = {}
        def cancelled_start(owner, before_start):
            prepared = real_start(owner)
            before_start(prepared=prepared)
            self.vm.stop(prepared['id'])
            saved.update(real_start(owner))
            raise Cancelled()
        jobs, job_id = self.put_job('start', {'config': {'kind': 'omarchy-vm'}})
        with patch('t3realms.vm_manager.VmManager', return_value=self.vm), patch.object(self.vm, 'start', side_effect=cancelled_start):
            result = jobs.run(job_id)
        self.assertEqual(result['state'], 'cancelled')
        self.assertEqual(self.vm.validate(first['id'])['compute_generation'], saved['compute_generation'])


if __name__ == '__main__':
    unittest.main()
