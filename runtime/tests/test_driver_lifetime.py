"""Regular driver ownership and lifetime with fake processes/native boundaries."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import socket
import subprocess
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import MagicMock, patch

from t3realms import driver
from t3realms.lifecycle import OwnershipError, BusyError, atomic_json


class DriverLifetimeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='t3r-driver-life-', dir='/var/tmp')
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.record = {'id': 'r-' + 'a' * 24, 'generation': 'b' * 32,
                       'runtime_dir': str(self.home), 'status': 'running',
                       'cgroup': '/fixture',
                       'supervisor': {'pid': 100, 'start_time': 1}}
        self.manager = MagicMock()
        self.manager.record.return_value = self.record
        self.manager.registry.lock.side_effect = lambda: nullcontext()
        self.manager.registry.get.return_value = self.record
        self.process = {'pid': 200, 'start_time': 2}

    def endpoint(self):
        endpoint = self.home / 'cua-driver.sock'
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(endpoint))
        sock.close()
        atomic_json(self.home / '.cua-driver.sock.owner.json', {
            'id': self.record['id'], 'generation': self.record['generation'], 'process': self.process})
        return endpoint

    def test_stale_endpoint_removed_only_after_proven_owner_exit(self):
        from t3realms.driver_lifetime import serve_guard
        endpoint = self.endpoint()
        with patch('t3realms.driver_lifetime.alive', return_value=False):
            with serve_guard(self.manager, self.record, endpoint):
                self.assertFalse(endpoint.exists())

    def test_live_unknown_or_foreign_endpoint_is_never_unlinked(self):
        from t3realms.driver_lifetime import serve_guard
        endpoint = self.endpoint()
        receipt = self.home / '.cua-driver.sock.owner.json'
        before = endpoint.lstat().st_ino
        with patch('t3realms.driver_lifetime.alive', return_value=True):
            with self.assertRaises(OwnershipError), serve_guard(self.manager, self.record, endpoint):
                pass
        for value in (None, {'id': self.record['id'], 'generation': 'c' * 32, 'process': self.process},
                      {'id': self.record['id'], 'generation': self.record['generation'], 'process': None}):
            if value is None:
                receipt.unlink()
            else:
                atomic_json(receipt, value)
            with self.subTest(value=value), patch('t3realms.driver_lifetime.alive', return_value=False):
                with self.assertRaises(OwnershipError), serve_guard(self.manager, self.record, endpoint):
                    pass
            self.assertEqual(endpoint.lstat().st_ino, before)

    def test_live_listener_is_preserved_even_if_process_receipt_is_dead(self):
        from t3realms.driver_lifetime import serve_guard
        endpoint = self.endpoint()
        endpoint.unlink()
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(endpoint))
            listener.listen(1)
            before = endpoint.lstat().st_ino
            with patch('t3realms.driver_lifetime.alive', return_value=False):
                with self.assertRaises(OwnershipError), serve_guard(self.manager, self.record, endpoint):
                    pass
            self.assertEqual(endpoint.lstat().st_ino, before)

    def test_endpoint_symlink_and_concurrent_serve_are_refused(self):
        from t3realms.driver_lifetime import serve_guard
        endpoint = self.home / 'cua-driver.sock'
        with serve_guard(self.manager, self.record, endpoint):
            with self.assertRaises(BusyError), serve_guard(self.manager, self.record, endpoint):
                pass
        sentinel = self.home / 'sentinel'
        sentinel.write_bytes(b'keep')
        endpoint.symlink_to(sentinel)
        with self.assertRaises(OwnershipError), serve_guard(self.manager, self.record, endpoint):
            pass
        self.assertEqual(sentinel.read_bytes(), b'keep')

    def test_mcp_proxy_and_bwrap_group_retire_on_idle_stop_or_replacement(self):
        from t3realms.driver_lifetime import run_contained
        for changed in (dict(self.record, status='stopped'), dict(self.record, generation='c' * 32)):
            child = MagicMock(pid=self.process['pid'])
            child.wait.side_effect = [subprocess.TimeoutExpired('bwrap', .5), 0]
            child.poll.return_value = None
            self.manager.record.side_effect = [self.record, changed]
            with self.subTest(changed=changed), \
                    patch('t3realms.driver_lifetime.subprocess.Popen', return_value=child) as spawn, \
                    patch('t3realms.driver_lifetime.identity', return_value=self.process), \
                    patch('t3realms.driver_lifetime.alive', return_value=True), \
                    patch('t3realms.driver_lifetime.os.getpgid', return_value=self.process['pid']), \
                    patch('t3realms.driver_lifetime.os.getsid', return_value=self.process['pid']), \
                    patch('t3realms.driver_lifetime.os.killpg') as kill:
                with self.assertRaises(OwnershipError):
                    run_contained(self.manager, self.record, ['/fake/bwrap', 'mcp'], {'HOME': '/private'})
                self.assertTrue(spawn.call_args.kwargs['start_new_session'])
                kill.assert_called_once()
                self.assertEqual(child.wait.call_count, 2)

    def test_reused_process_identity_is_never_signalled(self):
        from t3realms.driver_lifetime import run_contained
        child = MagicMock(pid=self.process['pid'])
        child.wait.side_effect = subprocess.TimeoutExpired('bwrap', .5)
        child.poll.return_value = None
        self.manager.record.side_effect = [self.record, dict(self.record, status='stopped')]
        with patch('t3realms.driver_lifetime.subprocess.Popen', return_value=child), \
                patch('t3realms.driver_lifetime.alive', return_value=True), \
                patch('t3realms.driver_lifetime.identity', side_effect=[self.process, {'pid': 200, 'start_time': 3}]), \
                patch('t3realms.driver_lifetime.os.killpg') as kill:
            with self.assertRaises(OwnershipError):
                run_contained(self.manager, self.record, ['/fake/bwrap'], {})
            kill.assert_not_called()

    def test_launcher_supervises_mcp_instead_of_untracked_exec(self):
        self.manager.env.return_value = {'HOME': '/private'}
        with patch('t3realms.manager.Manager', return_value=self.manager), \
                patch('t3realms.install_driver.execution_verified', return_value=True), \
                patch('t3realms.driver.sandbox_command', return_value=['/fake/bwrap']), \
                patch('t3realms.driver_lifetime.run_contained', return_value=0) as supervise, \
                patch('t3realms.driver.os.execve') as execute, \
                patch.object(sys, 'argv', ['launcher', 'mcp']):
            driver.driver_main(str(self.home), self.record['id'], str(self.home / 'bin/cua-driver'), self.record['generation'])
            supervise.assert_called_once()
            execute.assert_not_called()

    def test_serve_reconnects_after_retired_daemon_left_socket(self):
        endpoint = self.endpoint()
        self.manager.env.return_value = {'HOME': '/private'}
        child = MagicMock(pid=300)
        child.wait.return_value = 0
        child.poll.return_value = 0
        def spawn(*_args, **_kwargs):
            self.assertFalse(endpoint.exists(), 'stale embedded endpoint reached the new driver')
            return child
        with patch('t3realms.manager.Manager', return_value=self.manager), \
                patch('t3realms.install_driver.execution_verified', return_value=True), \
                patch('t3realms.driver.sandbox_command', return_value=['/fake/bwrap']), \
                patch('t3realms.driver_lifetime.alive', side_effect=lambda process: process == self.record['supervisor']), \
                patch('t3realms.driver_lifetime.identity', return_value={'pid': 300, 'start_time': 3}), \
                patch('t3realms.driver_lifetime.subprocess.Popen', side_effect=spawn) as spawned, \
                patch('t3realms.driver.os.execve') as execute, \
                patch.object(sys, 'argv', ['launcher', 'serve']):
            driver.driver_main(str(self.home), self.record['id'], str(self.home / 'bin/cua-driver'), self.record['generation'])
            spawned.assert_called_once()
            execute.assert_not_called()

    def test_endpoint_exchange_during_probe_is_preserved(self):
        from t3realms.driver_lifetime import serve_guard
        endpoint = self.endpoint()
        before = endpoint.lstat().st_ino
        probe = MagicMock()
        probe.__enter__.return_value = probe
        def exchange(_path):
            endpoint.rename(self.home / 'old-socket')
            endpoint.write_bytes(b'concurrent replacement')
            raise ConnectionRefusedError(111, 'refused')
        probe.connect.side_effect = exchange
        with patch('t3realms.driver_lifetime.alive', return_value=False), \
                patch('t3realms.driver_lifetime.socket.socket', return_value=probe):
            with self.assertRaises(OwnershipError), serve_guard(self.manager, self.record, endpoint):
                pass
        self.assertNotEqual(endpoint.lstat().st_ino, before)
        self.assertEqual(endpoint.read_bytes(), b'concurrent replacement')

    def test_unresponsive_owned_child_is_killed_and_reaped_after_term(self):
        from t3realms.driver_lifetime import run_contained
        child = MagicMock(pid=self.process['pid'])
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('bwrap', .5),
                                 subprocess.TimeoutExpired('bwrap', 3), -9]
        self.manager.record.side_effect = [self.record, dict(self.record, status='stopped')]
        with patch('t3realms.driver_lifetime.subprocess.Popen', return_value=child), \
                patch('t3realms.driver_lifetime.alive', return_value=True), \
                patch('t3realms.driver_lifetime.identity', return_value=self.process), \
                patch('t3realms.driver_lifetime.os.getpgid', return_value=self.process['pid']), \
                patch('t3realms.driver_lifetime.os.getsid', return_value=self.process['pid']), \
                patch('t3realms.driver_lifetime.os.killpg') as kill:
            with self.assertRaises(OwnershipError): run_contained(self.manager, self.record, ['/fake/bwrap'], {})
        import signal
        self.assertEqual([call.args for call in kill.call_args_list],
                         [(self.process['pid'], signal.SIGTERM), (self.process['pid'], signal.SIGKILL)])
        self.assertEqual(child.wait.call_count, 3)

    def test_live_receipt_without_bound_endpoint_prevents_duplicate_spawn(self):
        from t3realms.driver_lifetime import serve_guard
        endpoint = self.endpoint()
        endpoint.unlink()
        with patch('t3realms.driver_lifetime.alive', return_value=True):
            with self.assertRaises(OwnershipError), serve_guard(self.manager, self.record, endpoint):
                pass

    def test_driver_stop_recovers_native_receipt_without_node_tracking(self):
        from t3realms.driver_lifetime import stop_driver
        endpoint = self.endpoint()
        parent = {'pid': 201, 'start_time': 4}
        atomic_json(self.home / '.cua-driver.sock.owner.json', {
            'id': self.record['id'], 'generation': self.record['generation'],
            'process': self.process, 'supervisor': parent})
        active = [True]
        def stop(process, *, cgroup):
            self.assertEqual(process, parent)
            self.assertEqual(cgroup, '/fixture')
            active[0] = False
        def alive(process):
            return process == self.record['supervisor'] or active[0]
        with patch('t3realms.driver_lifetime.alive', side_effect=alive), \
                patch('t3realms.driver_lifetime._stop_owner', side_effect=stop) as retire:
            self.assertEqual(stop_driver(self.manager, self.record), {'retired': True})
        retire.assert_called_once_with(parent, cgroup='/fixture')
        self.assertFalse(endpoint.exists())

    def test_driver_stop_refuses_unconfirmed_child_retirement(self):
        from t3realms.driver_lifetime import stop_driver
        endpoint = self.endpoint()
        parent = {'pid': 201, 'start_time': 4}
        atomic_json(self.home / '.cua-driver.sock.owner.json', {
            'id': self.record['id'], 'generation': self.record['generation'],
            'process': self.process, 'supervisor': parent})
        with patch('t3realms.driver_lifetime.alive', return_value=True), \
                patch('t3realms.driver_lifetime._stop_owner'):
            with self.assertRaisesRegex(OwnershipError, 'retirement.*unconfirmed'):
                stop_driver(self.manager, self.record)
        self.assertTrue(endpoint.exists())

    def test_driver_stop_cli_checks_owner_and_incarnation_before_effects(self):
        from t3realms.cli import dispatch
        from support import stopped_record
        record = stopped_record(self.home, 'owner')
        with patch('t3realms.driver_lifetime.stop_driver', return_value={'retired': True}) as stop:
            for owner, incarnation in (('foreign', record['generation']), ('owner', 'f' * 32)):
                with self.subTest(owner=owner), self.assertRaises(OwnershipError):
                    dispatch(self.home, 'driver_stop', {'id': record['id'], 'owner': owner, 'incarnation': incarnation})
            stop.assert_not_called()
            result = dispatch(self.home, 'driver_stop', {'id': record['id'], 'owner': 'owner',
                                                       'incarnation': record['generation']})
            self.assertEqual(result, {'retired': True})
            stop.assert_called_once()

    def test_supervisor_pidfd_never_signals_reused_pid_and_closes_descriptor(self):
        from t3realms.driver_lifetime import _stop_owner
        for current in (None, dict(self.process, start_time=99), self.process):
            with self.subTest(current=current), \
                    patch('t3realms.driver_lifetime.os.pidfd_open', return_value=77), \
                    patch('t3realms.driver_lifetime.identity', return_value=current), \
                    patch.object(Path, 'read_text', return_value='0::/fixture'), \
                    patch('t3realms.driver_lifetime.signal.pidfd_send_signal') as send, \
                    patch('t3realms.driver_lifetime.select.select', return_value=([77], [], [])), \
                    patch('t3realms.driver_lifetime.os.close') as close:
                if current is not None and current != self.process:
                    with self.assertRaises(OwnershipError): _stop_owner(self.process, cgroup='/fixture')
                else:
                    _stop_owner(self.process, cgroup='/fixture')
                self.assertEqual(send.call_count, int(current == self.process))
                close.assert_called_once_with(77)

    def test_supervisor_retirement_timeout_is_not_success(self):
        from t3realms.driver_lifetime import _stop_owner
        with patch('t3realms.driver_lifetime.os.pidfd_open', return_value=77), \
                patch('t3realms.driver_lifetime.identity', return_value=self.process), \
                patch.object(Path, 'read_text', return_value='0::/fixture'), \
                patch('t3realms.driver_lifetime.signal.pidfd_send_signal'), \
                patch('t3realms.driver_lifetime.select.select', return_value=([], [], [])), \
                patch('t3realms.driver_lifetime.os.close'):
            with self.assertRaisesRegex(BusyError, 'unconfirmed'): _stop_owner(self.process, cgroup='/fixture')

    def test_corrupt_receipt_cannot_signal_process_outside_realm_cgroup(self):
        from t3realms.driver_lifetime import _stop_owner
        with patch('t3realms.driver_lifetime.os.pidfd_open', return_value=77), \
                patch('t3realms.driver_lifetime.identity', return_value=self.process), \
                patch.object(Path, 'read_text', return_value='0::/some-other-realm'), \
                patch('t3realms.driver_lifetime.signal.pidfd_send_signal') as send, \
                patch('t3realms.driver_lifetime.os.close'):
            with self.assertRaisesRegex(OwnershipError, 'cgroup'):
                _stop_owner(self.process, cgroup='/fixture')
            send.assert_not_called()

    def test_term_is_forwarded_and_child_reaped_before_wrapper_returns(self):
        from t3realms.driver_lifetime import run_contained
        import signal
        previous = signal.getsignal(signal.SIGTERM)
        child = MagicMock(pid=self.process['pid'])
        child.poll.return_value = None
        calls = []
        def wait(**_kwargs):
            calls.append(True)
            if len(calls) == 1: signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return 0
        child.wait.side_effect = wait
        with patch('t3realms.driver_lifetime.subprocess.Popen', return_value=child), \
                patch('t3realms.driver_lifetime.alive', return_value=True), \
                patch('t3realms.driver_lifetime.identity', return_value=self.process), \
                patch('t3realms.driver_lifetime.os.getpgid', return_value=self.process['pid']), \
                patch('t3realms.driver_lifetime.os.getsid', return_value=self.process['pid']), \
                patch('t3realms.driver_lifetime.os.killpg') as kill:
            self.assertEqual(run_contained(self.manager, self.record, ['/fake/bwrap'], {}), 128 + signal.SIGTERM)
            kill.assert_called_once_with(self.process['pid'], signal.SIGTERM)
        self.assertEqual(len(calls), 2)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)


if __name__ == '__main__':
    unittest.main()
