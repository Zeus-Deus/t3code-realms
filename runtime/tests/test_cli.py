import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from support import CLI, cli, stopped_record
from t3realms.cli import dispatch
from t3realms.diagnostics import doctor
from t3realms.errors import error_code
from t3realms.lifecycle import (NotFoundError, NotRunningError, SetupRequired, BusyError,
                                OwnershipError, RealmError)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='t3r-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def test_error_codes_and_envelope(self):
        self.assertEqual(cli(self.home, 'list'), {'ok': True, 'result': []})
        for command, data, code in (
            ('list', [], 'invalid_input'), ('list', {'extra': True}, 'invalid_input'),
            ('start', {'owner': ''}, 'invalid_input'),
            ('start', {'owner': 'x', 'config': {'renderer': 'bad'}}, 'invalid_input'),
            ('stop', {'id': 'bad'}, 'invalid_input'),
            ('stop', {'id': 'r-' + 'f' * 24}, 'not_found'),
            ('vnc_endpoint', {'id': '../bad'}, 'invalid_input'),
            ('vnc_endpoint', {'id': 'r-' + 'f' * 24}, 'not_found'),
            ('job_status', {'job_id': 'f' * 32}, 'not_found'),
            ('job_start', {'kind': 'bad'}, 'invalid_input')):
            with self.subTest(command=command, data=data):
                result = cli(self.home, command, data)
                self.assertIs(result['ok'], False)
                self.assertEqual(result['code'], code, result)
                self.assertIsInstance(result['error'], str)

    def test_not_running_and_ownership(self):
        record = stopped_record(self.home)
        self.assertEqual(cli(self.home, 'touch', {'id': record['id']})['code'], 'not_running')
        self.assertEqual(cli(self.home, 'touch', {'id': record['id'], 'owner': 'else'})['code'], 'ownership')
        self.assertEqual(cli(self.home, 'vnc_endpoint', {'id': record['id']})['code'], 'not_running')
        self.assertEqual(cli(self.home, 'vnc_endpoint', {'id': record['id'], 'owner': 'else'})['code'], 'ownership')

    def test_home_codes(self):
        self.assertEqual(cli(self.home / 'missing', 'list')['code'], 'invalid_input')
        self.assertEqual(cli('relative', 'list')['code'], 'invalid_input')
        self.home.chmod(0o755)
        self.assertEqual(cli(self.home, 'list')['code'], 'ownership')

    def test_invalid_json_still_one_line_and_exit_zero(self):
        for payload in ('{', 'null', '{"owner":NaN}'):
            process = subprocess.run([sys.executable, '-I', str(CLI), '--home', str(self.home),
                                      'list', '--input', payload], capture_output=True, text=True)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(len(process.stdout.splitlines()), 1)
            self.assertEqual(json.loads(process.stdout)['code'], 'invalid_input')

    def test_required_home_is_usage_error(self):
        result = subprocess.run([sys.executable, '-I', str(CLI), 'list'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_doctor_is_readonly_with_empty_path(self):
        empty = self.home / 'empty-path'
        empty.mkdir(mode=0o700)
        before = sorted(self.home.iterdir())
        report = cli(self.home, 'doctor', env=dict(os.environ, PATH=str(empty)))['result']
        self.assertFalse(report['ready'])
        self.assertFalse(report['systemd_user'])
        self.assertIn('labwc', report['missing'])
        self.assertIsNone(report['tools']['labwc'])
        self.assertEqual(report['driver']['path'], str(self.home / 'bin' / 'cua-driver'))
        self.assertEqual(before, sorted(self.home.iterdir()))

    def test_doctor_executes_only_readonly_systemctl_probe(self):
        def which(name):
            return '/usr/bin/' + name
        def run(argv, **kwargs):
            self.assertEqual(argv, ['/usr/bin/systemctl', '--user', 'show', 'basic.target', '--property=ActiveState'])
            return subprocess.CompletedProcess(argv, 0, 'ActiveState=active\n', '')
        with patch('t3realms.diagnostics.shutil.which', side_effect=which), \
                patch('t3realms.diagnostics.subprocess.run', side_effect=run) as probe:
            report = doctor(self.home)
        self.assertEqual(probe.call_count, 1)
        self.assertTrue(report['systemd_user'])
        self.assertFalse(report['driver']['verified'])
        self.assertFalse(self.home.joinpath('realms').exists())

    def test_setup_required_prevents_native_spawn(self):
        empty = self.home / 'empty-path'
        empty.mkdir(mode=0o700)
        response = cli(self.home, 'start', {'owner': 'thread:test', 'config': {}},
                       env=dict(os.environ, PATH=str(empty)))
        self.assertEqual(response['code'], 'setup_required')
        self.assertFalse((self.home / 'realms' / 'workspaces').exists())

    def test_stable_error_mapping(self):
        for error, expected in ((ValueError('x'), 'invalid_input'), (NotFoundError('x'), 'not_found'),
                                (OwnershipError('x'), 'ownership'), (NotRunningError('x'), 'not_running'),
                                (SetupRequired('x'), 'setup_required'), (BusyError('x'), 'busy'),
                                (TimeoutError('x'), 'timeout'), (RealmError('x'), 'failed')):
            self.assertEqual(error_code(error), expected)

    def test_blocking_start_uses_bounded_wait_and_requests_cleanup(self):
        from unittest.mock import MagicMock
        from t3realms.cli import blocking_start
        jobs = MagicMock()
        jobs.start.return_value = {'job_id': 'd' * 32}
        jobs.status.return_value = {'state': 'running', 'process': {'pid': 1234, 'start_time': 1}}
        with patch('t3realms.jobs.Jobs', return_value=jobs), \
                patch('t3realms.cli.os.pidfd_open', return_value=10), \
                patch('t3realms.cli.os.close'), \
                patch('t3realms.cli.select.select', return_value=([], [], [])) as wait:
            with self.assertRaises(TimeoutError):
                blocking_start(self.home, 'x', {})
        self.assertLessEqual(wait.call_args.args[3], 29)
        jobs.cancel.assert_called_once_with('d' * 32)

    def test_delete_roundtrip_through_json_with_inactive_units(self):
        record = stopped_record(self.home)
        owner = record['session_id']
        target = {'id': record['id'], 'owner': owner}
        response = cli(self.home, 'delete_snapshot', target)
        if response.get('code') == 'failed' and 'could not inspect systemd unit' in response.get('error', ''):
            self.skipTest('read-only systemd user-manager query unavailable')
        self.assertTrue(response['ok'], response)
        self.assertTrue(Path(record['workspace_dir']).exists())
        legacy = cli(self.home, 'delete', dict(target, snapshot=response['result']))
        self.assertEqual(legacy['code'], 'invalid_input')
        result = cli(self.home, 'delete', dict(target, token=response['result']['token']))
        self.assertEqual(result, {'ok': True, 'result': True})
        self.assertFalse(Path(record['workspace_dir']).exists())

    def test_doctor_reads_only_driver_receipt_and_binary_metadata(self):
        from t3realms.install_driver import _execution_identity, write_receipt
        target = self.home / 'bin/cua-driver'
        target.parent.mkdir(mode=0o700)
        target.write_bytes(b'diagnostic fixture; never execute or hash')
        target.chmod(0o700)
        write_receipt(target.with_name('.cua-driver-verified.json'), _execution_identity(target))
        with patch('t3realms.diagnostics.shutil.which', return_value=None), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('doctor read executable')):
            report = doctor(self.home)
        self.assertTrue(report['driver']['installed'])
        self.assertTrue(report['driver']['verified'])
