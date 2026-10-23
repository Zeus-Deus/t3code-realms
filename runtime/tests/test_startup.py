import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import select
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from t3realms.lifecycle import Registry, OwnershipError, atomic_json
from support import RUNTIME

SPAWN = subprocess.Popen
from t3realms.manager import Manager



class StartupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='t3r-start-', dir='/var/tmp')
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)

    def simulated_start(self, action):
        # All desktop/native boundaries are mocked; only the registry flock is real.
        runtime = self.home / 'desktop-fixture'
        waiting, resume = threading.Event(), threading.Event()
        state = {'active': False}
        errors, results = [], []
        manager = Manager(self.home)
        monitor = MagicMock()
        monitor.poll.return_value = None
        monitor.wait.return_value = 0
        def realm_path(value):
            return runtime if str(value).startswith('/run/user/') else Path(value)
        def wait(_delay):
            waiting.set()
            if not resume.wait(5):
                raise AssertionError('startup fixture was not resumed')
            # Model a scope activating after a concurrent stop request.
            state['active'] = True
            runtime.mkdir(mode=0o700, exist_ok=True)
            atomic_json(runtime / 'ready.json', {'env': {}, 'processes': {},
                                                'vnc_socket': str(runtime / 'wayvnc.sock')})
            atomic_json(runtime / 'supervisor.json', {'pid': 1234, 'start_time': 1})
        def stop(_record):
            state['active'] = False
        def unit(_name):
            return {'ActiveState': 'active' if state['active'] else 'inactive',
                    'InvocationID': 'a' * 32, 'ControlGroup': '/fixture'}
        def start():
            try:
                results.append(manager._start('thread:startup', self.home / 'payload', release_runtime=lambda: None))
            except BaseException as exc:
                errors.append(exc)
        with patch('t3realms.manager.Path', side_effect=realm_path), \
                patch('t3realms.lifecycle.validate_record'), \
                patch.object(manager, 'doctor', return_value={'tools': {}, 'systemd_user': True}), \
                patch('t3realms.manager.subprocess.Popen', return_value=monitor), \
                patch('t3realms.manager.time.sleep', side_effect=wait), \
                patch('t3realms.manager.scope_info', side_effect=unit), \
                patch.object(manager, '_stop_starting_guardian'), \
                patch('t3realms.manager.stop_scope', side_effect=stop) as stopped, \
                patch('t3realms.manager.validate_live'), \
                patch('t3realms.manager.validate_environment'), \
                patch('t3realms.manager.alive', return_value=False):
            thread = threading.Thread(target=start)
            thread.start()
            try:
                self.assertTrue(waiting.wait(3), 'start did not enter readiness wait')
                action(manager, resume, state)
            finally:
                resume.set()
                thread.join(5)
            self.assertFalse(thread.is_alive(), 'start did not terminate')
            state['records'] = manager.registry.records()
        return results, errors, state, stopped.call_count

    def test_list_from_another_process_completes_during_startup_wait(self):
        def action(manager, resume, state):
            program = ('import sys,json; from unittest.mock import patch; '
                       f'sys.path.insert(0, {str(RUNTIME)!r}); '
                       'from t3realms.manager import Manager; '
                       '\nwith patch("t3realms.lifecycle.validate_record"): '
                       'print(json.dumps(Manager(sys.argv[1]).list()), flush=True)')
            process = SPAWN([sys.executable, '-I', '-B', '-c', program, str(self.home)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([process.stdout], [], [], 2)[0],
                                'list blocked on the startup registry lock')
                records = json.loads(process.stdout.readline())
                self.assertEqual(records[0]['status'], 'starting')
            finally:
                resume.set()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)
        results, errors, state, _ = self.simulated_start(action)
        self.assertEqual(errors, [])
        self.assertEqual(results[0]['status'], 'running')
        self.assertEqual(results[0]['python_executable'], sys.executable)

    def test_stop_of_starting_record_cannot_publish_running_or_leave_scope(self):
        def action(manager, resume, state):
            # A nonblocking probe prevents the old implementation deadlocking this test.
            with manager.registry.lock(blocking=False):
                rid = manager.registry.records()[0]['id']
            manager.stop(rid)
        results, errors, state, stopped = self.simulated_start(action)
        self.assertEqual(results, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], OwnershipError)
        self.assertFalse(state['active'], 'scope activated after stop and was orphaned')
        self.assertGreater(stopped, 0)
        self.assertEqual(state['records'][0]['status'], 'stopped')

    def test_replacement_generation_is_not_overwritten_by_late_start(self):
        def action(manager, resume, state):
            with manager.registry.lock():
                current = manager.registry.records()[0]
                manager.registry.put(dict(current, generation='f' * 32))
        results, errors, state, stopped = self.simulated_start(action)
        self.assertEqual(results, [])
        self.assertIsInstance(errors[0], OwnershipError)
        self.assertEqual(state['records'][0]['generation'], 'f' * 32)
        self.assertEqual(state['records'][0]['status'], 'starting')
        self.assertFalse(state['active'])

    def test_reconcile_publication_of_same_generation_is_accepted(self):
        def action(manager, resume, state):
            with manager.registry.lock():
                current = manager.registry.records()[0]
                manager.registry.put(dict(current, status='running'))
        results, errors, state, _ = self.simulated_start(action)
        self.assertEqual(errors, [])
        self.assertEqual(results[0]['status'], 'running')

    def test_startup_guardian_cleanup_checks_identity_and_releases_lock(self):
        from support import stopped_record
        record = stopped_record(self.home)
        manager = Manager(self.home)
        owned = {'ActiveState': 'active', 'InvocationID': 'a' * 32,
                 'Description': 'T3 Code realm guardian ' + record['generation']}
        def stop(argv, **kwargs):
            self.assertEqual(argv, ['systemctl', '--user', 'stop', record['guardian_unit']])
            with manager.registry.lock(blocking=False):
                pass
        with patch('t3realms.manager.scope_info', return_value=owned), \
                patch('t3realms.manager.subprocess.run', side_effect=stop) as run:
            manager._stop_starting_guardian(record)
            run.assert_called_once()
        for changes in ({'Description': 'unrelated'}, {'InvocationID': 'b' * 32}):
            with patch('t3realms.manager.scope_info', return_value=dict(owned, **changes)), \
                    patch('t3realms.manager.subprocess.run') as run:
                with self.assertRaises(OwnershipError):
                    manager._stop_starting_guardian(dict(record, guardian_invocation_id='a' * 32))
                run.assert_not_called()
