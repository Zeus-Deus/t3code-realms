import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import hashlib
import io
import os
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from t3realms import install_driver
from t3realms.capture import asset_path, capture, capture_options, dimensions
from t3realms.host_guard import host_escape, guard_argv
from t3realms.lifecycle import OwnershipError, RealmError

PNG = b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + struct.pack('>II', 100, 50) + b'\0' * 9
JPEG = b'\xff\xd8\xff\xc0\x00\x0b\x08\x00\x32\x00\x64\x01\x01\x11\x00\xff\xd9'


class CaptureDriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='t3r-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def test_shot_path_confinement_and_symlinks(self):
        self.assertEqual(asset_path(self.home, 'assets/a.png'), self.home / 'assets/a.png')
        for value in ('../outside.png', '/var/tmp/outside.png', 'assets/../out.png', 'assets/sub/file.png'):
            with self.subTest(value=value), self.assertRaises(OwnershipError):
                asset_path(self.home, value)
        (self.home / 'assets/link.png').symlink_to(self.home / 'elsewhere')
        with self.assertRaises(OwnershipError):
            asset_path(self.home, 'assets/link.png')
        (self.home / 'assets/link.png').unlink()
        (self.home / 'assets').rmdir()
        (self.home / 'assets').symlink_to(self.home)
        with self.assertRaises(OwnershipError):
            asset_path(self.home, 'assets/a.png')

    def test_shot_formats_metadata_and_private_permissions(self):
        for format, data in (('png', PNG), ('jpeg', JPEG)):
            def run(argv, **kwargs):
                self.assertEqual(argv[0], 'grim')
                self.assertEqual(argv[-1], '-')
                self.assertIn(format, argv)
                if format == 'jpeg':
                    self.assertEqual(argv[argv.index('-q') + 1], '80')
                self.assertEqual(os.fstat(kwargs['stdout'].fileno()).st_mode & 0o777, 0o600)
                kwargs['stdout'].write(data)
                return subprocess.CompletedProcess(argv, 0)
            with patch('t3realms.capture.subprocess.run', side_effect=run):
                result = capture({'home': str(self.home)}, {}, format=format,
                                 quality=80 if format == 'jpeg' else None, scale=0.5)
            self.assertEqual((result['width'], result['height']), (100, 50))
            self.assertEqual(result['bytes'], len(data))
            self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(result['mimeType'], 'image/' + format)
            self.assertTrue(result['path'].startswith('assets/'))
            self.assertEqual((self.home / result['path']).stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.home / 'assets').stat().st_mode & 0o777, 0o700)

    def test_capture_failure_removes_partial_asset(self):
        with patch('t3realms.capture.subprocess.run', side_effect=RuntimeError('capture failed')):
            with self.assertRaises(RuntimeError):
                capture({'home': str(self.home)}, {})
        self.assertEqual(list((self.home / 'assets').iterdir()), [])

    def test_capture_options_validation(self):
        for args in (('gif', None, 1), ('jpeg', 0, 1), ('jpeg', True, 1),
                     ('jpeg', 101, 1), ('png', 20, 1), ('png', None, .09),
                     ('png', None, float('inf')), ('png', None, True)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                capture_options(*args)
        for format in ('png', 'jpeg'):
            with self.assertRaises(RealmError):
                dimensions(b'bad', format)

    def test_checksum_mismatch_archive_is_refused(self):
        archive = self.home / 'bad.tar.gz'
        archive.write_bytes(b'wrong archive')
        with patch('t3realms.install_driver.subprocess.run') as run:
            with self.assertRaisesRegex(ValueError, 'release checksum mismatch'):
                install_driver.install_archive(archive, self.home / 'bin/cua-driver')
            run.assert_not_called()
        self.assertFalse((self.home / 'bin').exists())

    def test_valid_structure_wrong_binary_is_refused(self):
        archive = self.home / 'fixture.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            info = tarfile.TarInfo(install_driver.MEMBER)
            payload = b'not the pinned driver; never execute'
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        with patch.object(install_driver, 'ARCHIVE_SHA256', checksum), \
                patch('t3realms.install_driver.subprocess.run') as run:
            with self.assertRaisesRegex(ValueError, 'binary checksum mismatch'):
                install_driver.install_archive(archive, self.home / 'bin/cua-driver')
            run.assert_not_called()
        self.assertFalse((self.home / 'bin').exists())

    def test_download_stops_at_size_cap_without_installing_or_executing(self):
        response = io.BytesIO(b'x' * 1025)
        with patch.object(install_driver, 'MAX_ARCHIVE_BYTES', 1024, create=True), \
                patch('t3realms.install_driver.urllib.request.urlopen', return_value=response), \
                patch('t3realms.install_driver.install_archive') as install, \
                patch('t3realms.install_driver.subprocess.run') as run:
            with self.assertRaisesRegex(ValueError, 'size limit'):
                install_driver.install(home=self.home)
            install.assert_not_called()
            run.assert_not_called()
        self.assertFalse((self.home / 'bin/cua-driver').exists())

    def test_download_hashes_stream_and_refuses_before_archive_processing(self):
        with patch('t3realms.install_driver.urllib.request.urlopen', return_value=io.BytesIO(b'wrong')), \
                patch('t3realms.install_driver.install_archive') as install:
            with self.assertRaisesRegex(ValueError, 'release checksum mismatch'):
                install_driver.install(home=self.home)
            install.assert_not_called()

    def test_execution_receipt_is_identity_bound_and_readonly(self):
        target = self.home / 'cua-driver'
        payload = b'receipt fixture, never executed'
        target.write_bytes(payload)
        target.chmod(0o700)
        with patch.object(install_driver, 'BINARY_SHA256', hashlib.sha256(payload).hexdigest()), \
                patch('t3realms.install_driver.subprocess.run') as run:
            self.assertTrue(install_driver.installed(target))
            self.assertFalse(install_driver.execution_verified(target))
            install_driver.write_receipt(target.with_name('.cua-driver-verified.json'),
                                         install_driver._execution_identity(target))
            self.assertTrue(install_driver.execution_verified(target))
            os.utime(target, ns=(0, 0))
            self.assertFalse(install_driver.execution_verified(target))
            run.assert_not_called()

    def test_guard_catches_assignments_but_allows_ordinary_args(self):
        for command in ('env WAYLAND_DISPLAY=wayland-0 grim x', 'export DISPLAY=:0; x',
                        'echo ok; XDG_RUNTIME_DIR=/run/user/1000 grim x',
                        'env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus x'):
            self.assertIsNotNone(host_escape(command), command)
        for command in ('echo DISPLAY=:0', 'env DISPLAY= x', 'echo hello',
                        'XDG_RUNTIME_DIR=/run/user/1000/t3r-abc app', 'echo "unterminated'):
            self.assertIsNone(host_escape(command), command)
        with self.assertRaises(OwnershipError):
            guard_argv(['sh', '-c', 'env WAYLAND_DISPLAY=wayland-0 grim x'])
        with self.assertRaises(OwnershipError):
            guard_argv(['bash', '-lc', 'DISPLAY=:0 x'])
        guard_argv(['printf', '%s', 'hello'])

from types import SimpleNamespace
from unittest.mock import MagicMock
from t3realms.driver import create_driver_launcher, driver_main, sandbox_command
from t3realms.config import Config
from t3realms.lifecycle import SetupRequired, atomic_json
from t3realms.manager import Manager


class DriverLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='t3r-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.runtime = self.home / 'r'
        self.runtime.mkdir(mode=0o700)
        self.record = {'id': 'r-' + 'a' * 24, 'generation': 'b' * 32,
                       'python_executable': sys.executable,
                       'runtime_dir': str(self.runtime), 'workspace_dir': str(self.home / 'workspace')}
        from t3realms.runtime_store import pinned_runtime
        with pinned_runtime(self.home) as payload:
            self.record['runtime_copy'] = str(payload)

    def test_launcher_identity_modes_and_tamper_detection(self):
        manager = Manager(self.home)
        with patch.object(manager, 'env', return_value={}), \
                patch.object(manager, 'record', return_value=self.record), \
                patch.object(manager.registry, 'get', return_value=self.record), \
                patch('t3realms.driver.validate_live'), \
                patch('t3realms.install_driver.execution_verified', return_value=True):
            path = Path(create_driver_launcher(manager, self.record['id']))
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            content = path.read_text()
            self.assertIn(str(self.home / 'bin/cua-driver'), content)
            self.assertIn(self.record['generation'], content)
            self.assertIn('from t3realms.driver import driver_main', content)
            self.assertIn(self.record['runtime_copy'], content)
            self.assertNotIn(str(Path(__file__).resolve().parents[1] / 't3realms'), content)
            self.assertTrue(content.startswith(f'#!{sys.executable} -IB\n'))
            self.assertEqual(create_driver_launcher(manager, self.record['id']), str(path))
            path.write_text(content + '# tampered\n')
            with self.assertRaises(OwnershipError):
                create_driver_launcher(manager, self.record['id'])

    def test_launcher_interpreter_is_pinned_to_generation(self):
        manager = Manager(self.home)
        with patch.object(manager, 'env', return_value={}), \
                patch.object(manager, 'record', return_value=self.record), \
                patch.object(manager.registry, 'get', return_value=self.record), \
                patch('t3realms.driver.validate_live'), \
                patch('t3realms.install_driver.execution_verified', return_value=True):
            launcher = Path(create_driver_launcher(manager, self.record['id']))
            before = launcher.read_bytes()
            with patch.object(sys, 'executable', '/different/python'):
                self.assertEqual(create_driver_launcher(manager, self.record['id']), str(launcher))
            self.assertEqual(launcher.read_bytes(), before)

    def test_launcher_requires_execution_receipt(self):
        manager = Manager(self.home)
        with patch.object(manager, 'env', return_value={}), \
                patch.object(manager, 'record', return_value=self.record):
            with self.assertRaises(SetupRequired):
                create_driver_launcher(manager, self.record['id'])
        self.assertFalse((self.runtime / 'cua-contained').exists())

    def test_launcher_refuses_tampered_runtime_copy(self):
        payload = Path(self.record['runtime_copy'])
        module = payload / 't3realms/driver.py'
        module.write_bytes(module.read_bytes() + b'\n# tampered\n')
        manager = Manager(self.home)
        with patch.object(manager, 'env', return_value={}), \
                patch.object(manager, 'record', return_value=self.record), \
                patch('t3realms.install_driver.execution_verified', return_value=True):
            with self.assertRaisesRegex(OwnershipError, 'contents hash changed'):
                create_driver_launcher(manager, self.record['id'])
        self.assertFalse((self.runtime / 'cua-contained').exists())

    def test_launcher_runs_with_private_env_telemetry_and_frozen_options(self):
        manager = MagicMock()
        manager.record.return_value = self.record
        manager.env.return_value = {'HOME': '/private', 'WAYLAND_DISPLAY': 'wayland-1'}
        manager.config = Config(overlay=False, cursor_theme='private.cursor')
        with patch('t3realms.manager.Manager', return_value=manager), \
                patch('t3realms.install_driver.execution_verified', return_value=True), \
                patch('t3realms.driver.sandbox_command', return_value=['/usr/bin/false']) as command, \
                patch('t3realms.driver.os.execve') as execute, \
                patch.object(sys, 'argv', ['launcher', 'mcp']):
            driver_main(str(self.home), self.record['id'], str(self.home / 'bin/cua-driver'), self.record['generation'])
            args = command.call_args.args[2]
            self.assertIn('--embedded', args)
            self.assertIn('--no-overlay', args)
            self.assertEqual(args[args.index('--cursor-theme') + 1], 'private.cursor')
            self.assertEqual(args[args.index('--socket') + 1], str(self.runtime / 'cua-driver.sock'))
            env = execute.call_args.args[2]
            self.assertEqual(env['CUA_DRIVER_RS_TELEMETRY_ENABLED'], '0')
            self.assertNotIn('HYPRLAND_INSTANCE_SIGNATURE', env)

    def test_sandbox_argv_contains_only_private_home_and_runtime(self):
        executable = self.home / 'cua-driver'
        executable.write_bytes(b'fixture never executed')
        atomic_json(self.runtime / 'ready.json', {'env': {'DISPLAY': ':99999'}})
        with patch('t3realms.driver.validate_live'), patch('t3realms.driver.shutil.which', return_value='/usr/bin/bwrap'):
            args = sandbox_command(self.record, executable, ['mcp'])
        self.assertIn('--unshare-net', args)
        self.assertIn('--unshare-pid', args)
        self.assertIn(str(self.runtime), args)
        self.assertIn(str(self.home / 'workspace/home'), args)
        self.assertNotIn(str(Path.home()), args)
        self.assertNotIn('/dev/input', args)
        self.assertNotIn('/dev/uinput', args)
        self.assertEqual(args[-2:], ['/opt/realm-driver', 'mcp'])
