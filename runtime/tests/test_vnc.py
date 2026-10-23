import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import socket
import tempfile
import unittest
from unittest.mock import patch

from support import stopped_record, cli
from t3realms.lifecycle import OwnershipError, Registry, atomic_json, validate_sockets
from t3realms.manager import Manager


class VncRefusalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='t3r-vnc-', dir='/var/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)

    def test_endpoint_requires_live_validation_before_socket_inspection(self):
        record = stopped_record(self.home)
        record.update(status='running', vnc_socket=record['runtime_dir'] + '/wayvnc.sock', vnc_port=None)
        Registry(self.home).put(record)
        with patch('t3realms.manager.validate_live', side_effect=OwnershipError('dead scope')), \
                patch('t3realms.manager.validate_sockets') as inspect:
            with self.assertRaisesRegex(OwnershipError, 'dead scope'):
                Manager(self.home).vnc_endpoint(record['id'])
            inspect.assert_not_called()

    def test_socket_mode_type_owner_and_cgroup_refusals(self):
        path = self.home / 'wayvnc.sock'
        record = {'cgroup': '/nonexistent-test-cgroup'}
        with self.assertRaises(OwnershipError):
            validate_sockets(record, [path], mode=0o600)
        path.write_bytes(b'regular file')
        with self.assertRaisesRegex(OwnershipError, 'socket ownership'):
            validate_sockets(record, [path], mode=0o600)
        path.unlink()
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            path.chmod(0o660)
            with self.assertRaisesRegex(OwnershipError, 'socket mode'):
                validate_sockets(record, [path], mode=0o600)
            path.chmod(0o600)
            with patch('t3realms.lifecycle.os.getuid', return_value=os.getuid() + 1):
                with self.assertRaisesRegex(OwnershipError, 'socket ownership'):
                    validate_sockets(record, [path], mode=0o600)
            original = Path.read_text
            def read_text(file, *args, **kwargs):
                if str(file) == '/sys/fs/cgroup/nonexistent-test-cgroup/cgroup.procs':
                    return ''
                return original(file, *args, **kwargs)
            with patch.object(Path, 'read_text', read_text):
                with self.assertRaisesRegex(OwnershipError, 'does not own socket'):
                    validate_sockets(record, [path], mode=0o600)
        path.unlink()
        external = self.home / 'external'
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(external))
            path.symlink_to(external)
            with self.assertRaisesRegex(OwnershipError, 'socket ownership'):
                validate_sockets(record, [path], mode=0o600)

    def test_advertised_path_cannot_escape_private_runtime(self):
        record = stopped_record(self.home)
        record.update(status='running', vnc_socket=str(self.home / 'foreign.sock'), vnc_port=None)
        registry = Registry(self.home)
        atomic_json(registry.path(record['id']), record)
        response = cli(self.home, 'vnc_endpoint', {'id': record['id']})
        self.assertEqual(response['code'], 'ownership', response)
