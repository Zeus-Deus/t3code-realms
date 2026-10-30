import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from t3realms import components, setup_worker, vm_ssh
from t3realms.cli import dispatch
from t3realms.config import Config, driver_path, vm_data_path
from t3realms.jobs import Jobs
from t3realms.lifecycle import BusyError, RealmError, SetupRequired, atomic_json


class Base(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name).resolve()


class ComponentsTest(Base):
    def install_driver(self):
        target = driver_path(self.home)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(b'x' * 8192)
        target.chmod(0o700)
        target.with_name('.cua-driver-verified.json').write_text('[]')
        return target

    def install_vm(self):
        data = vm_data_path(self.home)
        for part in ('base', 'iso', 'identity/.ssh'):
            (data / part).mkdir(mode=0o700, parents=True, exist_ok=True)
        (data / 'iso/omarchy-4.0.4.iso').write_bytes(b'i' * 8192)
        return data

    def test_summary_reports_what_is_installed_and_who_did_it(self):
        self.install_driver()
        self.install_vm()
        components.remember(self.home, driver={'by': 'agent'}, packages=['qemu-full'])
        components.remember(self.home, packages=['mtools'])
        result = dispatch(self.home, 'components', {})
        self.assertTrue(result['driver']['present'])
        self.assertEqual(result['driver']['installedBy'], 'agent')
        self.assertGreater(result['driver']['bytes'], 0)
        self.assertFalse(result['vm']['present'])
        self.assertGreater(result['vm']['bytes'], 0)
        self.assertEqual(result['packages']['names'], ['mtools', 'qemu-full'])
        self.assertEqual(result['packages']['removeCommand'], 'sudo pacman -Rns mtools qemu-full')
        self.assertEqual(result['totalBytes'], result['driver']['bytes'] + result['vm']['bytes'] + result['workspaces']['bytes'])

    def test_empty_machine(self):
        result = dispatch(self.home, 'components', {})
        self.assertFalse(result['driver']['present'])
        self.assertEqual(result['totalBytes'], 0)
        self.assertIsNone(result['packages']['removeCommand'])

    def test_remove_driver_and_vm(self):
        target = self.install_driver()
        data = self.install_vm()
        components.remember(self.home, driver={'by': 'agent'}, vm={'by': 'agent'}, packages=['qemu-full'])
        dispatch(self.home, 'component_remove', {'component': 'driver'})
        self.assertFalse(target.exists())
        self.assertFalse(target.with_name('.cua-driver-verified.json').exists())
        dispatch(self.home, 'component_remove', {'component': 'vm'})
        for part in ('base', 'iso', 'identity'):
            self.assertFalse((data / part).exists())
        state = components.read_state(self.home)
        self.assertEqual(state, {'packages': ['qemu-full']})

    def test_orphaned_vm_overlay_keeps_the_base(self):
        data = self.install_vm()
        orphan = self.home / 'realms/vm/abc'
        orphan.mkdir(parents=True)
        with self.assertRaisesRegex(RealmError, 'workspaces'):
            components.remove(self.home, 'vm')
        self.assertTrue((data / 'base').exists())

    def test_failed_install_stays_stopped_after_its_history_expires(self):
        jobs = Jobs(self.home)
        record = {'job_id': 'b' * 32, 'kind': 'vm_setup', 'owner': None, 'state': 'failed', 'error': 'offline',
                  'input': {'config': {}, 'review_id': 'r', 'unattended': True}, 'created_at': 1.0, 'updated_at': 1.0, 'process': None}
        jobs.put(record)
        with jobs.lock():
            jobs.prune(jobs.records())
        self.assertEqual(list(jobs.root.glob('*.json')), [])
        config = {'config': {'kind': 'omarchy-vm'}}
        self.assertEqual(dispatch(self.home, 'setup_plan', config)['halt']['error'], 'offline')
        self.assertIsNone(dispatch(self.home, 'setup_plan', {'config': {}})['halt'])
        # Another agent's job doesn't clear it; a person's retry does.
        jobs.put(dict(record, job_id='c' * 32, state='queued'))
        self.assertIsNotNone(components.halted(self.home, 'omarchy-vm'))
        jobs.put(dict(record, job_id='d' * 32, state='queued', input={'config': {}, 'review_id': 'r'}))
        self.assertIsNone(components.halted(self.home, 'omarchy-vm'))

    def test_success_clears_a_stop(self):
        jobs = Jobs(self.home)
        record = {'job_id': 'e' * 32, 'kind': 'setup', 'owner': None, 'state': 'cancelled',
                  'input': {'config': {}, 'review_id': 'r'}, 'created_at': 1.0, 'updated_at': 1.0, 'process': None}
        jobs.put(record)
        self.assertEqual(components.halted(self.home, 'realm')['state'], 'cancelled')
        jobs.put(dict(record, state='succeeded'))
        self.assertIsNone(components.halted(self.home, 'realm'))

    def test_dangling_base_still_lists_so_the_page_can_finish_removing_it(self):
        data = self.install_vm()
        (data / 'current-base.json').write_text('{}')
        (data / 'current-base.json').chmod(0o600)
        result = dispatch(self.home, 'components', {})
        self.assertFalse(result['vm']['present'])
        self.assertGreater(result['vm']['bytes'], 0)
        dispatch(self.home, 'component_remove', {'component': 'vm'})
        self.assertFalse((data / 'current-base.json').exists())

    def test_unattended_start_is_refused_while_halted(self):
        jobs = Jobs(self.home)
        record = {'job_id': 'f' * 32, 'kind': 'setup', 'owner': None, 'state': 'running', 'process': {'pid': 999999, 'start_time': 1},
                  'input': {'config': {}, 'review_id': 'r', 'unattended': True}, 'created_at': time.time(), 'updated_at': time.time()}
        jobs.put(record)
        # The dead job is reconciled inside start, which then sees the halt it just caused.
        with self.assertRaises(SetupRequired):
            jobs.start('setup', input={'config': {}, 'review_id': 'r', 'unattended': True})
        self.assertEqual(jobs.status('f' * 32)['state'], 'failed')
        self.assertEqual(len(list(jobs.root.glob('*.json'))), 1)

    def test_teardown_removes_workspaces_then_components_and_reports_failures(self):
        target = self.install_driver()
        data = self.install_vm()
        order = []
        desktop = mock.Mock(list=lambda: [{'id': 'r-1', 'session_id': 'a', 'status': 'stopped'}, {'id': 'r-2', 'session_id': 'b', 'status': 'stopped'}])
        desktop.delete_snapshot.side_effect = lambda realm, session_id: {'token': 't'}
        def delete(realm, *, session_id, token):
            if realm == 'r-2': raise RealmError('still open')
            order.append(realm)
        desktop.delete.side_effect = delete
        vm = mock.Mock(list=lambda: [{'id': 'v-1', 'session_id': 'c', 'status': 'recovery-required'}])
        vm.delete_snapshot.side_effect = lambda realm, session_id, discard: {'token': 't'}
        vm.delete.side_effect = lambda realm, session_id, token, discard: order.append((realm, discard))
        with mock.patch('t3realms.manager.Manager', return_value=desktop), mock.patch('t3realms.vm_manager.VmManager', return_value=vm):
            result = components.teardown(self.home, {}, 'a' * 32, lambda value: None)
        self.assertEqual(order, ['r-1', ('v-1', True)])
        self.assertEqual([item['name'] for item in result['failed']], ['r-2'])
        self.assertFalse(target.exists())
        self.assertFalse((data / 'iso').exists())

    def test_teardown_refuses_running_realms(self):
        desktop = mock.Mock(list=lambda: [{'id': 'r-1', 'session_id': 'a', 'status': 'running'}])
        vm = mock.Mock(list=lambda: [])
        with mock.patch('t3realms.manager.Manager', return_value=desktop), mock.patch('t3realms.vm_manager.VmManager', return_value=vm):
            with self.assertRaises(BusyError):
                components.teardown(self.home, {}, 'a' * 32, lambda value: None)
        desktop.delete.assert_not_called()

    def test_teardown_is_a_job_and_excludes_setup(self):
        jobs = Jobs(self.home)
        with self.assertRaises(ValueError):
            jobs.start('teardown', input={'extra': 1})
        result = jobs.start('teardown', input={'config': {}})
        with self.assertRaises(BusyError):
            jobs.start('setup', input={'config': {}, 'review_id': 'r'})
        deadline = time.time() + 10
        while jobs.status(result['job_id'])['state'] not in ('succeeded', 'failed') and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(jobs.status(result['job_id'])['state'], 'succeeded', jobs.status(result['job_id']))
        self.assertEqual(jobs.status(result['job_id'])['result'], {'failed': []})

    def test_only_known_components(self):
        with self.assertRaises(ValueError):
            dispatch(self.home, 'component_remove', {'component': '../bin'})

    def test_running_realm_keeps_the_driver_and_workspaces_keep_the_base(self):
        target = self.install_driver()
        data = self.install_vm()
        desktop = mock.Mock(records=lambda: [{'status': 'running'}], lock=components.Registry(self.home).lock, root=self.home / 'realms')
        vm = mock.Mock(records=lambda: [{'kind': 'omarchy-vm', 'status': 'stopped'}], root=self.home / 'realms')
        with mock.patch.object(components, 'registries', return_value=(desktop, vm)):
            with self.assertRaisesRegex(RealmError, 'Stop running Realms'):
                components.remove(self.home, 'driver')
            with self.assertRaisesRegex(RealmError, 'workspaces'):
                components.remove(self.home, 'vm')
        self.assertTrue(target.exists())
        self.assertTrue((data / 'base').exists())

    def test_active_job_blocks_removal(self):
        target = self.install_driver()
        record = {'job_id': 'a' * 32, 'state': 'running'}
        with mock.patch.object(Jobs, 'records', return_value=[record]):
            with self.assertRaises(BusyError):
                components.remove(self.home, 'driver')
        self.assertTrue(target.exists())

    def test_symlinked_data_is_refused(self):
        self.install_vm()
        outside = self.home / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('keep')
        os.symlink(outside, vm_data_path(self.home) / 'bases')
        with self.assertRaises(Exception):
            components.remove(self.home, 'vm')
        self.assertTrue((outside / 'keep').exists())

    def test_download_progress_counts_partial_iso(self):
        self.install_vm()
        part = vm_data_path(self.home) / 'iso/omarchy-4.0.5.iso.part'
        part.write_bytes(b'p' * 100)
        (vm_data_path(self.home) / 'iso/omarchy-4.0.5.iso.sig').write_bytes(b's' * 100)
        self.assertEqual(dispatch(self.home, 'vm_download', {})['bytes'], 8192 + 100)


class UnattendedSetupTest(Base):
    def plan(self, **changes):
        return {'reviewId': 'review', 'blockers': [], 'packages': [], 'missing': [], 'argv': None, 'command': None,
                'driver': {'installed': False}, 'base': {'present': False}, **changes}

    def job(self, **changes):
        return {'job_id': 'a' * 32, 'kind': 'setup', 'input': {'config': {}, 'review_id': 'review', 'unattended': True, **changes}}

    def test_unattended_can_never_reach_packages(self):
        with mock.patch.object(setup_worker, 'plan', return_value=self.plan(packages=['labwc'], argv=['x'], command='x')), \
                mock.patch.object(setup_worker, 'run_command') as command:
            with self.assertRaisesRegex(SetupRequired, 'needs a person'):
                setup_worker.run(self.home, self.job(), lambda value: None)
        command.assert_not_called()

    def test_review_must_still_match(self):
        with mock.patch.object(setup_worker, 'plan', return_value=self.plan(reviewId='other')):
            with self.assertRaises(Exception):
                setup_worker.run(self.home, self.job(), lambda value: None)

    def test_validation(self):
        good = {'config': {}, 'review_id': 'r'}
        setup_worker.validate_setup_input(good)
        setup_worker.validate_setup_input(dict(good, unattended=True))
        for bad in (dict(good, unattended=False), dict(good, unattended='yes'), dict(good, extra=1), {'config': {}}, dict(good, review_id=1)):
            with self.assertRaises(ValueError):
                setup_worker.validate_setup_input(bad)

    def test_driver_install_records_who_did_it(self):
        ready = self.plan(); ready['driver'] = {'installed': False}
        with mock.patch.object(setup_worker, 'plan', return_value=ready), \
                mock.patch('t3realms.install_driver.install'), \
                mock.patch('t3realms.diagnostics.doctor', return_value={'ready': True}):
            setup_worker.run(self.home, self.job(), lambda value: None)
        self.assertEqual(components.read_state(self.home)['driver']['by'], 'agent')


class IdentityTest(Base):
    @unittest.skipUnless(__import__('shutil').which('ssh-keygen'), 'needs ssh-keygen')
    def test_own_private_key_is_created_once(self):
        key = vm_ssh.ensure_identity(self.home)
        self.assertEqual(key, vm_data_path(self.home) / 'identity/.ssh/id_ed25519')
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(key.parent.stat().st_mode), 0o700)
        before = key.read_bytes()
        self.assertEqual(vm_ssh.ensure_identity(self.home).read_bytes(), before)

    def test_incomplete_key_is_not_overwritten(self):
        ssh = vm_data_path(self.home) / 'identity/.ssh'
        ssh.mkdir(mode=0o700, parents=True)
        (ssh / 'id_ed25519').write_text('secret')
        with self.assertRaises(Exception):
            vm_ssh.ensure_identity(self.home)
        self.assertEqual((ssh / 'id_ed25519').read_text(), 'secret')

    def test_missing_keygen_is_a_setup_error(self):
        with mock.patch.object(subprocess, 'run', side_effect=OSError):
            with self.assertRaises(SetupRequired):
                vm_ssh.ensure_identity(self.home)

    def test_guest_connections_prefer_realms_key_and_keep_older_bases_working(self):
        options = vm_ssh.ssh_options({'home': str(self.home), 'runtime_dir': '/tmp/x'})
        identities = [options[index + 1] for index, option in enumerate(options) if option == '-i']
        self.assertEqual(identities, [str(vm_data_path(self.home) / 'identity/.ssh/id_ed25519'),
                                      str(Path.home() / '.ssh/id_ed25519')])

    def test_vm_plan_needs_no_personal_key(self):
        from t3realms import vm_setup
        with mock.patch.object(Path, 'home', return_value=self.home):
            report = vm_setup.doctor(self.home, Config.from_object({'kind': 'omarchy-vm'}))
        self.assertFalse(any('id_ed25519' in name for name in report['missing']))

    def test_free_space_does_not_change_the_review(self):
        from t3realms import vm_setup
        config = Config.from_object({'kind': 'omarchy-vm'})
        with mock.patch.object(vm_setup, 'resources', return_value={'blockers': ['Insufficient free storage']}):
            short = vm_setup.plan(self.home, config)
        with mock.patch.object(vm_setup, 'resources', return_value={'blockers': []}):
            roomy = vm_setup.plan(self.home, config)
        self.assertEqual(short['reviewId'], roomy['reviewId'])
        self.assertEqual(short['resources']['blockers'], ['Insufficient free storage'])
        self.assertNotIn('Insufficient free storage', short['blockers'])


if __name__ == '__main__':
    unittest.main()
