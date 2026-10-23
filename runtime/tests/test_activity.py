import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import stat
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from support import stopped_record
from t3realms.driver import create_driver_launcher
from t3realms.lifecycle import Registry
from t3realms.manager import Manager
from t3realms.runtime_store import pinned_runtime


class ActivityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='t3r-activity-', dir='/var/tmp')
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.record = stopped_record(self.home)
        with pinned_runtime(self.home) as payload:
            self.record['runtime_copy'] = str(payload)
        self.record.update(python_executable=sys.executable, status='running', last_activity=1, supervisor={},
                           vnc_socket=self.record['runtime_dir'] + '/wayvnc.sock', vnc_port=None,
                           processes={'worker': {'pid': 1234, 'start_time': 1}})
        self.registry = Registry(self.home)
        self.registry.put(self.record)
        self.manager = Manager(self.home)

    def exercise(self, operation):
        self.registry.put(self.record)
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.getsockopt.return_value = struct.pack('3i', 1234, os.getuid(), 0)
        connection.makefile.return_value.__enter__.return_value.readline.return_value = b'{"result": {}}\n'
        lstat = Path.lstat
        def socket_stat(path, *args, **kwargs):
            if str(path) == self.record['runtime_dir'] + '/control':
                return os.stat_result((stat.S_IFSOCK | 0o600, 0, 0, 0, os.getuid(), 0, 0, 0, 0, 0))
            return lstat(path, *args, **kwargs)
        with patch('t3realms.manager.validate_live'), \
                patch('t3realms.manager.validate_environment'), \
                patch('t3realms.manager.validate_sockets'), \
                patch('t3realms.manager.private_json', return_value={'env': {}}), \
                patch('t3realms.manager.alive', return_value=True), \
                patch('t3realms.manager.time.time', return_value=100), \
                patch('t3realms.manager.identity', return_value=self.record['processes']['worker']), \
                patch('t3realms.manager.socket.socket', return_value=connection), \
                patch.object(Path, 'lstat', socket_stat), \
                patch('t3realms.windows.count_windows', return_value=0), \
                patch('t3realms.install_driver.execution_verified', return_value=True), \
                patch('t3realms.driver._write_driver_launcher', return_value='/fixture/launcher'):
            operation()
        return self.registry.get(self.record['id'])['last_activity']

    def test_readonly_commands_do_not_renew_idle_lease(self):
        rid = self.record['id']
        for name, operation in (
            ('env', lambda: self.manager.env(rid)),
            ('record', lambda: self.manager.record(rid)),
            ('list', self.manager.list),
            ('windows', lambda: self.manager.windows(rid)),
            ('outputs', lambda: self.manager.outputs(rid)),
            ('vnc_endpoint', lambda: self.manager.vnc_endpoint(rid)),
            ('driver_launcher', lambda: create_driver_launcher(self.manager, rid)),
        ):
            with self.subTest(command=name):
                self.assertEqual(self.exercise(operation), 1)

    def test_agent_use_frames_and_touch_renew_idle_lease(self):
        rid = self.record['id']
        for name, operation in (
            ('exec', lambda: self.manager.exec(rid, ['true'])),
            ('job', lambda: self.manager.job(rid, 'fixture')),
            ('signal', lambda: self.manager.signal(rid, 'fixture', 'TERM')),
            ('shot', lambda: self.manager.shot(rid)),
            ('resize', lambda: self.manager.resize(rid, '800x600')),
            ('touch', lambda: self.manager.touch(rid)),
        ):
            with self.subTest(command=name):
                self.assertEqual(self.exercise(operation), 100)

    def test_delete_snapshot_does_not_renew_idle_lease(self):
        self.record['status'] = 'stopped'
        self.registry.put(self.record)
        before = self.registry.path(self.record['id']).read_bytes()
        with patch('t3realms.manager.scope_info', return_value={'ActiveState': 'inactive'}):
            self.manager.delete_snapshot(self.record['id'], session_id=self.record['session_id'])
        self.assertEqual(self.registry.path(self.record['id']).read_bytes(), before)
