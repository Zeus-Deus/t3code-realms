"""Recovery regressions with fake compute; no desktops, units or downloads.

Safety lessons adapted from Hermes Realms da5cdd3 (MIT,
Copyright (c) 2026 Zeus-Deus), tests/test_realms_stop_scope.py,
test_realms_workspace.py and test_realms_setup_progress.py.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from support import stopped_record
from t3realms import lifecycle
from t3realms.host_guard import host_escape, guard_argv
from t3realms.jobs import Jobs
from t3realms.manager import Manager


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='t3r-recovery-', dir='/var/tmp')
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)

    def test_cleanup_failure_isolated_and_exact_stop_remains_available(self):
        manager = Manager(self.home)
        healthy = stopped_record(self.home, 'healthy')
        failed = dict(stopped_record(self.home, 'failed'), status='cleanup_failed',
                      cleanup_error='Permission denied: private-runtime')
        manager.registry.put(failed)
        with patch('t3realms.manager.stop_scope'), \
                patch('t3realms.manager.remove_runtime', side_effect=lifecycle.RealmError('Permission denied')):
            self.assertEqual([row['id'] for row in manager.list('healthy')], [healthy['id']])
            rows = {row['id']: row for row in manager.list()}
            self.assertEqual(rows[failed['id']]['status'], 'cleanup_failed')
            self.assertTrue(rows[failed['id']]['cleanup_required'])
            self.assertIn('Permission denied', rows[failed['id']]['error'])
            with self.assertRaisesRegex(lifecycle.RealmError, 'Permission denied'):
                manager.stop(failed['id'])
        self.assertTrue(manager.stop(healthy['id']))
        self.assertTrue(Path(failed['workspace_dir']).is_dir())

    def test_unconfirmed_retirement_does_not_remove_runtime_or_poison_peer(self):
        manager = Manager(self.home)
        failed = dict(stopped_record(self.home, 'failed'), status='cleanup_failed')
        peer = stopped_record(self.home, 'peer')
        manager.registry.put(failed)
        with patch('t3realms.manager.stop_scope', side_effect=lifecycle.OwnershipError('scope invocation changed')), \
                patch('t3realms.manager.remove_runtime') as remove:
            rows = {row['id']: row for row in manager.list()}
            self.assertEqual(rows[peer['id']]['status'], 'stopped')
            self.assertTrue(rows[failed['id']]['cleanup_required'])
            self.assertIn('invocation changed', rows[failed['id']]['error'])
            remove.assert_not_called()

    def test_terminal_start_failure_survives_job_list_reconciliation(self):
        jobs = Jobs(self.home)
        record = {'job_id': 'a' * 32, 'kind': 'start', 'owner': 'owner',
                  'state': 'running', 'process': None, 'input': {'config': {}},
                  'created_at': time.time(), 'updated_at': time.time()}
        jobs.put(record)
        first = jobs.list('owner')[0]
        self.assertEqual((first['state'], first['code']), ('failed', 'interrupted'))
        self.assertEqual(Jobs(self.home).list('owner'), [first])
        self.assertIn('exited before recording', first['error'])

    def test_obsolete_job_progress_cannot_overwrite_terminal_result(self):
        jobs = Jobs(self.home)
        jid = 'b' * 32
        record = {'job_id': jid, 'kind': 'driver_install', 'owner': 'owner',
                  'state': 'queued', 'process': lifecycle.identity(os.getpid()), 'input': {},
                  'created_at': time.time(), 'updated_at': time.time()}
        jobs.put(record)
        def install(**kwargs):
            current = jobs.get(jid)
            jobs.put(dict(current, state='cancelled', code='cancelled', error='Already cancelled'))
            kwargs['progress']({'stage': 'obsolete'})
        with patch('t3realms.install_driver.install', side_effect=install), \
                patch('t3realms.diagnostics.driver_status', return_value={'verified': True}):
            jobs.run(jid)
        final = jobs.status(jid)
        self.assertEqual(final['state'], 'cancelled')
        self.assertNotIn('progress', final)
        self.assertNotIn('result', final)

    def test_cancelled_vm_start_never_stops_new_compute_with_same_workspace_generation(self):
        from t3realms.jobs import Cancelled
        for replaced in (False, True):
            jobs = Jobs(self.home)
            jid = 'c' * 32
            operation = {'id': 'v-' + 'a' * 24, 'generation': 'b' * 32,
                         'session_id': 'owner', 'compute_generation': 'c' * 32}
            current = dict(operation, compute_generation='d' * 32) if replaced else operation
            manager = MagicMock()
            locked = []
            from contextlib import contextmanager
            @contextmanager
            def lock():
                locked.append(True)
                try:
                    yield
                finally:
                    locked.pop()
            manager.registry.lock.side_effect = lock
            manager.registry.get.return_value = current
            manager.record.return_value = current
            def start(_owner, before_start):
                before_start(prepared=operation)
                raise Cancelled()
            manager.start.side_effect = start
            manager._stop_locked.side_effect = lambda _record: self.assertEqual(locked, [True])
            jobs.put({'job_id': jid, 'kind': 'start', 'owner': 'owner',
                      'input': {'config': {'kind': 'omarchy-vm'}}, 'state': 'queued',
                      'process': lifecycle.identity(os.getpid()),
                      'created_at': time.time(), 'updated_at': time.time()})
            with self.subTest(replaced=replaced), patch('t3realms.vm_manager.VmManager', return_value=manager):
                result = jobs.run(jid)
                self.assertEqual(result['state'], 'cancelled')
                manager.stop.assert_not_called()
                self.assertEqual(result['progress']['compute_generation'], operation['compute_generation'])
                if replaced:
                    manager._stop_locked.assert_not_called()
                    self.assertIn('incarnation changed', result['error'])
                else:
                    manager._stop_locked.assert_called_once_with(operation)

    def test_failed_stop_requires_fresh_terminal_observation(self):
        record = stopped_record(self.home)
        owned = {'ActiveState': 'active', 'Description': 'T3 Code realm ' + record['generation']}
        for outcome in ({'ActiveState': 'active'}, lifecycle.RealmError('query unavailable'),
                        {'ActiveState': 'inactive'}, {'ActiveState': 'failed'}):
            with self.subTest(outcome=outcome), \
                    patch('t3realms.lifecycle.scope_info', side_effect=[owned, outcome]) as query, \
                    patch('t3realms.lifecycle.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'stop')):
                if isinstance(outcome, Exception):
                    with self.assertRaisesRegex(lifecycle.RealmError, 'query unavailable'):
                        lifecycle.stop_scope(record)
                elif outcome['ActiveState'] == 'active':
                    with self.assertRaises(subprocess.CalledProcessError):
                        lifecycle.stop_scope(record)
                else:
                    lifecycle.stop_scope(record)
                self.assertEqual(query.call_count, 2)
        self.assertEqual(Manager(self.home).record(record['id']), record)


class GuardRecoveryTests(unittest.TestCase):
    def test_argument_assignments_are_data_and_private_inheritance_is_safe(self):
        for text in ("printf '%s\\n' A=1 DISPLAY=:0", 'env WAYLAND_DISPLAY="$WAYLAND_DISPLAY" true',
                     'echo DISPLAY=:0; printf A=1 DISPLAY=:0', 'env -u DISPLAY true',
                     'printf "%s" ";" DISPLAY=:0', "printf '%s' '&&' A=1 DISPLAY=:0",
                     'echo hi # ; DISPLAY=:0'):
            with self.subTest(text=text):
                self.assertIsNone(host_escape(text))
        guard_argv(['printf', '%s', 'A=1', 'DISPLAY=:0'])

    def test_real_prefixes_still_refuse_with_scoped_recovery(self):
        for text in ('A=1 DISPLAY=:0 app', 'echo okay;DISPLAY=:0 app',
                     'env -i A=1 WAYLAND_DISPLAY=wayland-0 app', 'export A=1 DISPLAY=:0',
                     'env DISPLAY="$HOST_DISPLAY" app', 'env -u OTHER DISPLAY=:0 app',
                     'env env DISPLAY=:0 app', 'export OTHER DISPLAY=:0',
                     'echo okay\nDISPLAY=:0 app', 'env OTHER="a b" DISPLAY=:0 app'):
            with self.subTest(text=text):
                reason = host_escape(text)
                self.assertIsNotNone(reason)
                self.assertIn('ordinary provider shell', reason)
                self.assertNotIn('approved host target', reason)


class CaptureBudgetTests(unittest.TestCase):
    def test_oversize_capture_is_removed_and_previous_asset_is_preserved(self):
        from t3realms.capture import capture
        import struct
        headers = {'png': b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + struct.pack('>II', 100, 50),
                   'jpeg': b'\xff\xd8\xff\xc0\x00\x0b\x08\x00\x32\x00\x64\x01\x01\x11\x00\xff\xd9'}
        with tempfile.TemporaryDirectory(prefix='t3r-budget-', dir='/var/tmp') as tmp:
            home = Path(tmp)
            previous = home / 'assets/previous.png'
            previous.parent.mkdir(mode=0o700)
            previous.write_bytes(b'retained image')
            for format, header in headers.items():
                data = header + b'\0' * (4 * 1024 * 1024 + 1 - len(header))
                def run(argv, **kwargs):
                    kwargs['stdout'].write(data)
                    return subprocess.CompletedProcess(argv, 0)
                with self.subTest(format=format), patch('t3realms.capture.subprocess.run', side_effect=run):
                    with self.assertRaisesRegex(lifecycle.RealmError, '4 MiB.*lower scale'):
                        capture({'home': str(home)}, {}, format=format)
                self.assertEqual(list(previous.parent.iterdir()), [previous])
                self.assertEqual(previous.read_bytes(), b'retained image')

    def test_shared_dimension_validation_rejects_oversize_vm_stream(self):
        from t3realms.capture import dimensions
        with self.assertRaisesRegex(lifecycle.RealmError, '4 MiB'):
            dimensions(b'\0' * (4 * 1024 * 1024 + 1), 'png')


if __name__ == '__main__':
    unittest.main()
