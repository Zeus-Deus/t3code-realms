import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
from t3realms.config import Config
from t3realms.lifecycle import OwnershipError, identity
from t3realms.jobs import Jobs, Cancelled


class SetupTests(unittest.TestCase):
    def setUp(self):
        release = patch('t3realms.setup_plan.platform.freedesktop_os_release', return_value={'ID': 'arch'})
        release.start()
        self.addCleanup(release.stop)
        self.tmp = tempfile.TemporaryDirectory(prefix='t3r-setup-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.report = {'missing': ['labwc', 'Xwayland', 'bwrap', 'verified cua-driver'],
                       'ready': False, 'systemd_user': True, 'platform': 'linux', 'arch': 'x86_64',
                       'driver': {'path': str(self.home / 'bin/cua-driver'), 'verified': False}, 'message': 'setup'}

    def plan(self, **kwargs):
        from t3realms.setup_plan import plan
        with patch('t3realms.diagnostics.doctor', return_value=self.report), \
                patch('t3realms.setup_plan.shutil.which', side_effect=lambda name: '/usr/bin/' + name if name not in kwargs.get('absent', ()) else None):
            return plan(self.home, Config())

    def test_review_lists_exact_arch_packages_command_and_binds_changes(self):
        plan = self.plan()
        self.assertEqual(plan['packages'], ['bubblewrap', 'labwc', 'xorg-xwayland'])
        self.assertEqual(plan['blockers'], [])
        self.assertEqual(plan['argv'], ['/usr/bin/pkexec', '/usr/bin/timeout', '--signal=TERM', '--kill-after=10s',
                                        '1800s', '/usr/bin/pacman', '-S', '--needed', '--noconfirm', '--', *plan['packages']])
        self.assertEqual(plan['command'], ' '.join(plan['argv']))
        self.report['missing'].remove('labwc')
        self.assertNotEqual(plan['reviewId'], self.plan()['reviewId'])

    def test_non_arch_pkexec_and_manual_prerequisites_block(self):
        self.assertTrue(self.plan(absent=['pacman'])['blockers'])
        self.assertTrue(self.plan(absent=['pkexec'])['blockers'])
        self.report['missing'] += ['systemd_user', '/dev/kvm access', 'existing ~/.ssh/id_ed25519 key pair (never created or replaced)']
        plan = self.plan()
        self.assertEqual(len(plan['blockers']), 3)
        self.assertNotIn('chmod', plan['command'])
        self.assertNotIn('ssh-keygen', plan['command'])

    def test_vm_firmware_and_package_dependencies_are_installable(self):
        from t3realms.vm_setup import plan
        report = dict(self.report, blockers=['qemu-system-x86_64', 'qemu-full', 'mformat',
                          '/usr/share/edk2/x64/OVMF_CODE.4m.fd'], base_image={'present': False, 'path': 'base'})
        with patch('t3realms.vm_setup.doctor', return_value=report), \
                patch('t3realms.setup_plan.shutil.which', side_effect=lambda name: '/usr/bin/' + name):
            value = plan(self.home, Config.from_object({'kind': 'omarchy-vm'}))
        self.assertEqual(value['packages'], ['edk2-ovmf', 'mtools', 'qemu-full'])
        self.assertEqual(value['blockers'], [])

    def test_reviewed_setup_revalidates_before_packages_and_after_packages(self):
        from t3realms.setup_worker import run
        plan = self.plan()
        job = {'job_id': 'a' * 32, 'kind': 'setup', 'input': {'config': {}, 'review_id': plan['reviewId']}}
        ready = dict(plan, packages=[], blockers=[], argv=None, command=None)
        with patch('t3realms.setup_worker.plan', side_effect=[plan, ready]), \
                patch('t3realms.setup_worker.install_packages') as packages, \
                patch('t3realms.install_driver.install') as driver, \
                patch('t3realms.diagnostics.doctor', return_value={'ready': True}):
            self.assertTrue(run(self.home, job, Mock())['ready'])
            packages.assert_called_once()
            driver.assert_called_once()
        job['input']['review_id'] = 'changed'
        with patch('t3realms.setup_worker.plan', return_value=plan), \
                patch('t3realms.setup_worker.install_packages') as packages:
            with self.assertRaises(OwnershipError): run(self.home, job, Mock())
            packages.assert_not_called()

    def test_cancelled_package_phase_never_installs_driver(self):
        from t3realms.setup_worker import run
        plan = self.plan()
        job = {'job_id': 'a' * 32, 'kind': 'setup', 'input': {'config': {}, 'review_id': plan['reviewId']}}
        with patch('t3realms.setup_worker.plan', return_value=plan), \
                patch('t3realms.setup_worker.install_packages', side_effect=Cancelled), \
                patch('t3realms.install_driver.install') as driver:
            with self.assertRaises(Cancelled): run(self.home, job, Mock())
            driver.assert_not_called()

    def test_detached_setup_publishes_progress_and_result_without_native_effects(self):
        jobs = Jobs(self.home)
        job_id = 'c' * 32
        now = time.time()
        jobs.put({'job_id': job_id, 'kind': 'setup', 'owner': None, 'input': {'config': {}, 'review_id': 'review'},
                  'state': 'queued', 'created_at': now, 'updated_at': now, 'process': identity(os.getpid())})
        def run(home, record, progress):
            progress({'stage': 'packages', 'packages': ['labwc']})
            return {'ready': True}
        with patch('t3realms.setup_worker.run', side_effect=run): result = jobs.run(job_id)
        self.assertEqual(result['state'], 'succeeded')
        self.assertEqual(result['progress']['stage'], 'packages')
        self.assertEqual(result['result'], {'ready': True})

    def test_package_runner_drains_after_cancellation_without_signalling_privileged_child(self):
        from t3realms.setup_worker import run_command
        process = Mock(returncode=0)
        process.wait.side_effect = [Cancelled(), (None, None)]
        with patch('t3realms.setup_worker.subprocess.Popen', return_value=process) as spawn, \
                patch('t3realms.setup_worker.signal.pthread_sigmask'):
            with self.assertRaises(Cancelled): run_command(['reviewed-command'], {'PATH': '/usr/bin'}, 99)
        self.assertEqual(process.wait.call_count, 2)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.assertEqual(spawn.call_args.kwargs['pass_fds'], (99,))
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])

    def test_no_setup_phase_can_bypass_a_draining_package_transaction(self):
        import fcntl
        from t3realms.setup_worker import install_packages
        from t3realms.lifecycle import BusyError
        fd = os.open(self.home / 'setup-packages.lock', os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with patch('t3realms.setup_worker.run_command') as runner:
            with self.assertRaises(BusyError):
                install_packages(self.home, {'packages': [], 'argv': None, 'command': None}, Mock())
            runner.assert_not_called()

    def test_non_arch_with_pacman_is_still_an_explicit_blocker(self):
        with patch('t3realms.setup_plan.distribution', return_value='unsupported'):
            value = self.plan()
        self.assertEqual(value['packages'], [])
        self.assertTrue(value['blockers'])

    def test_review_changes_when_native_authorization_is_unavailable(self):
        self.assertNotEqual(self.plan()['reviewId'], self.plan(absent=['pkexec'])['reviewId'])

    def test_worker_refuses_remaining_or_new_packages_after_install(self):
        from t3realms.setup_worker import run
        plan = self.plan()
        job = {'job_id': 'a' * 32, 'input': {'config': {}, 'review_id': plan['reviewId']}}
        with patch('t3realms.setup_worker.plan', return_value=plan), \
                patch('t3realms.setup_worker.install_packages'), \
                patch('t3realms.install_driver.install') as driver:
            with self.assertRaises(Exception) as failure: run(self.home, job, Mock())
            self.assertIn('review setup again', str(failure.exception))
            driver.assert_not_called()

    def test_package_command_cannot_expand_beyond_the_reviewed_allowlist(self):
        from t3realms.setup_worker import install_packages
        plan = self.plan()
        for change in ({'packages': ['labwc', 'unreviewed']}, {'argv': ['sh', '-c', 'anything']}):
            with patch('t3realms.setup_worker.run_command') as runner:
                with self.assertRaises(OwnershipError): install_packages(self.home, dict(plan, **change), Mock())
                runner.assert_not_called()

    def test_global_setup_admission_and_strict_kind_inputs_before_spawn(self):
        from t3realms.lifecycle import BusyError
        jobs = Jobs(self.home)
        now = time.time()
        jobs.put({'job_id': 'd' * 32, 'kind': 'setup', 'owner': None, 'input': {'config': {}, 'review_id': 'review'},
                  'state': 'running', 'created_at': now, 'updated_at': now, 'process': identity(os.getpid())})
        with patch('t3realms.jobs.subprocess.Popen') as spawn:
            for kind, config in [('setup', {}), ('vm_setup', {'kind': 'omarchy-vm'}), ('driver_install', None)]:
                payload = {} if config is None else {'config': config, 'review_id': 'review'}
                with self.assertRaises(BusyError): jobs.start(kind, input=payload)
            for kind, payload in [('setup', {}), ('setup', {'config': {'kind': 'omarchy-vm'}, 'review_id': 'review'}),
                                  ('vm_setup', {'config': {}, 'review_id': 'review'})]:
                with self.assertRaises(ValueError): jobs.start(kind, input=payload)
            spawn.assert_not_called()

    def test_package_supervisor_applies_bound_and_keeps_lock_until_owned_child_exits(self):
        from t3realms.package_process import supervise
        import subprocess
        process = Mock(returncode=0, pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired('fake', 1820), 0]
        with patch('t3realms.package_process.subprocess.Popen', return_value=process), \
                patch('t3realms.package_process.os.killpg', side_effect=PermissionError) as kill:
            self.assertEqual(supervise(['fake-reviewed-command'], {}), 124)
        process.wait.assert_any_call(timeout=1820)
        self.assertEqual(process.wait.call_count, 2)
        kill.assert_called_once_with(12345, 9)

    def test_regular_setup_blocks_an_unsupported_driver_architecture(self):
        self.report['arch'] = 'aarch64'
        value = self.plan()
        self.assertIn('Linux x86-64', value['blockers'])
        self.assertFalse(value['ready'])
