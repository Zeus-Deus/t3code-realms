import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from support import RUNTIME, cli, await_process, stopped_record
from t3realms.jobs import Jobs
from t3realms.lifecycle import Registry, OwnershipError
from t3realms.runtime_store import RuntimeStore, prune_runtime


class RuntimeStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='t3r-r2-', dir='/var/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.store = RuntimeStore(self.home)

    def copy(self):
        with self.store.lock():
            return self.store.materialize()

    def snapshot(self):
        path = self.home / 'snapshot'
        shutil.copytree(RUNTIME / 't3realms', path / 't3realms')
        shutil.copyfile(RUNTIME / 't3realms_cli.py', path / 't3realms_cli.py')
        return path

    def different_copy(self):
        snapshot = self.snapshot()
        with (snapshot / 't3realms' / '__init__.py').open('a') as stream:
            stream.write('\n# Different plugin version for this fixture.\n')
        program = ('from t3realms.runtime_store import pinned_runtime; '
                   f'\nwith pinned_runtime({str(self.home)!r}) as payload: print(payload)')
        process = subprocess.run([sys.executable, '-B', '-P', '-c', program],
                                 env=dict(os.environ, PYTHONPATH=str(snapshot), PYTHONDONTWRITEBYTECODE='1'),
                                 capture_output=True, text=True, check=True)
        payload = Path(process.stdout.strip())
        jobs = Jobs(self.home)
        now = time.time()
        record = {'job_id': 'f' * 32, 'kind': 'selftest', 'owner': 'x', 'state': 'queued',
                  'created_at': now, 'updated_at': now, 'process': None, 'input': {},
                  'runtime_copy': str(payload)}
        with jobs.lock():
            jobs.put(record)
        return payload, record

    def test_atomic_copy_reused_with_private_modes(self):
        first = self.copy()
        inode = first.stat().st_ino
        self.assertEqual(len(first.name), 64)
        self.assertEqual(first.parent, self.home / 'runtime')
        self.assertEqual(self.copy(), first)
        self.assertEqual(first.stat().st_ino, inode)
        self.assertEqual(sorted(path.name for path in first.iterdir()), ['t3realms'])
        for path in (self.store.root, first, *first.rglob('*')):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        self.assertEqual(list(self.store.root.glob('.prepare-*')), [])

    def test_tamper_is_refused_without_repair_or_spawn(self):
        payload = self.copy()
        module = payload / 't3realms/cli.py'
        module.write_bytes(module.read_bytes() + b'\n# tampered\n')
        with patch('t3realms.jobs.subprocess.Popen') as spawn:
            with self.assertRaisesRegex(OwnershipError, 'contents hash changed'):
                Jobs(self.home).start('selftest')
            spawn.assert_not_called()
        self.assertTrue(module.read_bytes().endswith(b'# tampered\n'))

    def test_extra_file_and_permission_changes_are_refused(self):
        payload = self.copy()
        unexpected = payload / 'extra'
        unexpected.write_text('unexpected')
        with self.assertRaisesRegex(OwnershipError, 'unexpected contents'):
            self.copy()
        unexpected.unlink()
        module = payload / 't3realms/cli.py'
        module.chmod(0o644)
        with self.assertRaisesRegex(OwnershipError, 'ownership or mode'):
            self.copy()
        module.chmod(0o600)
        payload.chmod(0o755)
        with self.assertRaisesRegex(OwnershipError, 'ownership or mode'):
            self.copy()

    def test_copy_and_package_symlinks_are_refused(self):
        payload = self.copy()
        saved = self.home / 'saved-copy'
        payload.rename(saved)
        payload.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(OwnershipError):
            self.copy()
        payload.unlink()
        saved.rename(payload)
        module = payload / 't3realms/cli.py'
        target = self.home / 'external'
        module.rename(target)
        module.symlink_to(target)
        with self.assertRaises(OwnershipError):
            self.copy()
        self.assertTrue(target.is_file())

    def test_source_symlink_is_refused(self):
        snapshot = self.snapshot()
        module = snapshot / 't3realms/cli.py'
        module.unlink()
        module.symlink_to(RUNTIME / 't3realms/cli.py')
        response = cli(self.home, 'job_start', {'kind': 'selftest'}, entry=snapshot / 't3realms_cli.py')
        self.assertEqual(response['code'], 'ownership', response)
        self.assertEqual(list((self.home / 'jobs').glob('*.json')), [])

    def test_live_job_argv_environment_and_snapshot_deletion(self):
        snapshot = self.snapshot()
        started = cli(self.home, 'job_start', {'kind': 'selftest', 'input': {'seconds': 2}},
                      entry=snapshot / 't3realms_cli.py')
        self.assertTrue(started['ok'], started)
        job_id = started['result']['job_id']
        jobs = Jobs(self.home)
        self.addCleanup(lambda: await_process(jobs.cancel(job_id)['process']))
        record = jobs.status(job_id)
        payload = Path(record['runtime_copy'])
        pid = record['process']['pid']
        argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        environment = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
        self.assertIn(b'-B', argv)
        self.assertIn(b'-P', argv)
        self.assertIn(b't3realms.cli', argv)
        self.assertIn(b'PYTHONPATH=' + os.fsencode(payload), environment)
        self.assertIn(b'PYTHONDONTWRITEBYTECODE=1', environment)
        self.assertNotIn(os.fsencode(snapshot), b'\0'.join(argv + environment))
        shutil.rmtree(snapshot)
        await_process(record['process'])
        # A fresh import after the selftest delay publishes the terminal JSON;
        # source removal cannot be masked by modules cached before the delay.
        result = jobs.status(job_id)
        self.assertEqual(result['state'], 'succeeded', result)
        self.assertEqual(result['result'], {'completed': True})
        self.assertTrue(payload.is_dir())

    def test_cli_and_detached_job_do_not_modify_snapshot(self):
        snapshot = self.snapshot()
        def inventory():
            return {str(path.relative_to(snapshot)): None if path.is_dir() else path.read_bytes()
                    for path in snapshot.rglob('*')}
        before = inventory()
        entry = snapshot / 't3realms_cli.py'
        for command, data in [('list', {}), ('driver_status', {}), ('job_list', {}),
                              ('doctor', {}), ('start', {'owner': 'x', 'config': {'renderer': 'invalid'}})]:
            cli(self.home, command, data, env=dict(os.environ, PATH=''), entry=entry)
        response = cli(self.home, 'job_start', {'kind': 'selftest'}, entry=entry)
        self.assertTrue(response['ok'], response)
        job_id = response['result']['job_id']
        jobs = Jobs(self.home)
        record = jobs.status(job_id)
        await_process(record['process'])
        self.assertEqual(cli(self.home, 'job_status', {'job_id': job_id}, entry=entry)['result']['state'], 'succeeded')
        self.assertEqual(inventory(), before)
        self.assertEqual(list(snapshot.rglob('__pycache__')), [])
        self.assertEqual(list(self.store.root.rglob('*.pyc')), [])

    def test_pruning_keeps_nonterminal_jobs_and_live_realms(self):
        payload, job = self.different_copy()
        orphan = self.copy()
        self.assertNotEqual(payload, orphan)
        self.assertEqual(prune_runtime(self.home), [str(orphan)])
        self.assertTrue(payload.is_dir())
        job['state'] = 'succeeded'
        jobs = Jobs(self.home)
        with jobs.lock():
            jobs.put(job)
        record = stopped_record(self.home)
        record.update(status='starting', runtime_copy=str(payload))
        Registry(self.home).put(record)
        self.assertEqual(prune_runtime(self.home), [])
        record['status'] = 'stopped'
        Registry(self.home).put(record)
        with patch('t3realms.lifecycle.scope_info', return_value={'ActiveState': 'deactivating'}):
            self.assertEqual(prune_runtime(self.home), [])
        with patch('t3realms.lifecycle.scope_info', return_value={'ActiveState': 'inactive'}):
            self.assertEqual(prune_runtime(self.home), [str(payload)])

    def test_pruning_keeps_the_current_process_copy(self):
        payload = self.copy()
        program = ('from t3realms.runtime_store import prune_runtime; '
                   f'print(prune_runtime({str(self.home)!r}))')
        process = subprocess.run([sys.executable, '-B', '-P', '-c', program],
                                 env=dict(os.environ, PYTHONPATH=str(payload), PYTHONDONTWRITEBYTECODE='1'),
                                 capture_output=True, text=True, check=True)
        self.assertEqual(process.stdout.strip(), '[]')
        self.assertTrue(payload.is_dir())
        self.assertEqual(prune_runtime(self.home), [str(payload)])

    def test_pruning_defers_while_any_publication_lock_is_busy(self):
        payload = self.copy()
        registry = Registry(self.home)
        jobs = Jobs(self.home)
        for owner in (self.store, registry, jobs):
            with self.subTest(owner=type(owner).__name__), owner.lock():
                self.assertEqual(prune_runtime(self.home), [])
                self.assertTrue(payload.is_dir())
        self.assertEqual(prune_runtime(self.home), [str(payload)])

    def test_record_references_cannot_escape_store(self):
        record = stopped_record(self.home)
        for value in (str(self.home), str(self.home / 'runtime' / ('a' * 64) / '..'), None):
            with self.subTest(value=value), self.assertRaises(OwnershipError):
                Registry(self.home).put(dict(record, runtime_copy=value))

    def test_supervisor_spawns_worker_from_recorded_copy_without_bytecode(self):
        payload = self.copy()
        runtime = self.home / 'private-desktop-fixture'
        runtime.mkdir(mode=0o700)
        record = {'status': 'starting', 'runtime_dir': str(runtime), 'runtime_copy': str(payload), 'scope': 'fixture.scope',
                  'guardian_unit': 'fixture.service', 'generation': 'a' * 32}
        from t3realms.lifecycle import atomic_json
        atomic_json(runtime / 'ready.json', {'processes': {'worker': {'pid': 42, 'start_time': 1}}})
        from unittest.mock import MagicMock
        registry = MagicMock()
        registry.get.return_value = record
        from t3realms.supervisor import run
        with patch('t3realms.supervisor.Registry', return_value=registry), \
                patch('t3realms.supervisor.subprocess.Popen') as spawn, \
                patch('builtins.print'), \
                patch('t3realms.supervisor.alive', return_value=False), \
                patch('t3realms.supervisor.cleanup') as cleanup:
            run(self.home, 'fixture')
        argv = spawn.call_args.args[0]
        env = spawn.call_args.kwargs['env']
        self.assertIn('-B', argv)
        self.assertEqual(argv[argv.index('-m') + 1], 't3realms.bootstrap')
        self.assertEqual(env['PYTHONPATH'], str(payload))
        self.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')
        cleanup.assert_called_once_with(self.home, 'fixture', record['generation'])
