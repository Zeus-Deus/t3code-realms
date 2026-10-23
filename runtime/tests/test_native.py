"""Opt-in only: real user-manager units, private desktops, and driver download."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import unittest

from support import RUNTIME, cli, await_process
from t3realms.config import effective_home
from t3realms.jobs import Jobs
from t3realms.lifecycle import (Registry, alive, host_control_env, private_json,
                                scope_info, validate_live)
from t3realms.manager import Manager
from t3realms.runtime_store import RuntimeStore


def receive(connection, length):
    chunks = bytearray()
    while len(chunks) < length:
        data = connection.recv(length - len(chunks))
        if not data:
            raise AssertionError('RFB server closed during handshake')
        chunks.extend(data)
    return bytes(chunks)


@unittest.skipUnless(os.environ.get('T3REALMS_NATIVE') == '1', 'requires explicit native approval: T3REALMS_NATIVE=1')
class NativeTests(unittest.TestCase):
    def test_native_lifecycle(self):
        # Observe host socket identities without connecting to the desktop.
        host_sockets = {}
        actual_wayland = os.environ.get('WAYLAND_DISPLAY', '')
        if re.fullmatch('wayland-[0-9]+', actual_wayland):
            path = Path(f'/run/user/{os.getuid()}') / actual_wayland
            if path.exists():
                host_sockets[path] = path.lstat()
        actual_x = os.environ.get('DISPLAY', '')
        if re.fullmatch(r':[0-9]+(?:\.[0-9]+)?', actual_x):
            path = Path('/tmp/.X11-unix/X' + actual_x[1:].split('.')[0])
            if path.exists():
                host_sockets[path] = path.lstat()
        with tempfile.TemporaryDirectory(prefix='t3r-native-', dir='/var/tmp') as directory:
            scratch = Path(directory)
            if 'T3REALMS_NATIVE_HOME' in os.environ:
                home = effective_home(os.environ['T3REALMS_NATIVE_HOME'])
                self.assertTrue(str(home).startswith('/var/tmp/'), 'use a throwaway --home under /var/tmp')
                self.assertFalse((home / 'realms').exists(), 'native --home must have no existing realms')
            else:
                home = scratch / 'data'
                home.mkdir(mode=0o700)
            original = scratch / 'plugin-snapshot'
            updated = scratch / 'plugin-update'
            for snapshot in (original, updated):
                shutil.copytree(RUNTIME / 't3realms', snapshot / 't3realms')
                shutil.copyfile(RUNTIME / 't3realms_cli.py', snapshot / 't3realms_cli.py')
            with (updated / 't3realms/__init__.py').open('a') as stream:
                stream.write('\n# Simulated new plugin snapshot.\n')
            # Pause only the copied fixture's start waiter. A second CLI must
            # acquire the real registry lock before this gate is released.
            with (original / 't3realms/manager.py').open('a') as stream:
                stream.write("\n_native_wait_for_ready = Manager._wait_for_ready\n\ndef _native_startup_barrier(self, record, monitor, logfile):\n    with socket.socket(socket.AF_UNIX) as connection:\n        connection.settimeout(15)\n        connection.connect(str(self.home / 'native-startup-barrier.sock'))\n        connection.sendall(b'waiting')\n        if connection.recv(1) != b'1':\n            raise RuntimeError('native startup barrier closed')\n    return _native_wait_for_ready(self, record, monitor, logfile)\n\nManager._wait_for_ready = _native_startup_barrier\n")
            original_entry = original / 't3realms_cli.py'
            updated_entry = updated / 't3realms_cli.py'
            before = {str(path.relative_to(original)): path.read_bytes()
                      for path in original.rglob('*') if path.is_file()}

            # Download and --version verification belong inside the native gate.
            install = cli(home, 'job_start', {'kind': 'driver_install'}, entry=original_entry)
            self.assertTrue(install['ok'], install)
            jobs = Jobs(home)
            install_id = install['result']['job_id']
            try:
                await_process(jobs.status(install_id)['process'], timeout=180)
                installed = jobs.status(install_id)
                self.assertEqual(installed['state'], 'succeeded', installed)
            finally:
                await_process(jobs.cancel(install_id)['process'], timeout=30)

            owner = 'thread:native-qualification'
            hostile = dict(os.environ, WAYLAND_DISPLAY='host-not-for-realms', DISPLAY=':999999',
                           DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent-host-bus',
                           HYPRLAND_INSTANCE_SIGNATURE='host-sentinel', HYPRLAND_CMD='host-sentinel')
            barrier = socket.socket(socket.AF_UNIX)
            self.addCleanup(barrier.close)
            self.addCleanup(lambda: (home / 'native-startup-barrier.sock').unlink(missing_ok=True))
            barrier.settimeout(15)
            barrier_path = home / 'native-startup-barrier.sock'
            barrier.bind(str(barrier_path))
            barrier_path.chmod(0o600)
            barrier.listen(1)
            # A job preserves a cancellation receipt even for partial startup.
            response = cli(home, 'job_start', {'kind': 'start', 'owner': owner,
                           'input': {'config': {'size': '800x600', 'renderer': 'pixman', 'idle_ttl': 120}}},
                           env=hostile, entry=original_entry)
            self.assertTrue(response['ok'], response)
            start_id = response['result']['job_id']
            record = None
            try:
                with barrier.accept()[0] as waiting:
                    self.assertEqual(receive(waiting, 7), b'waiting')
                    try:
                        listed = subprocess.run([sys.executable, '-I', '-B', str(original_entry),
                            '--home', str(home), 'list', '--input', json.dumps({'owner': owner})],
                            capture_output=True, text=True, check=True, timeout=2)
                        listing = json.loads(listed.stdout)
                        self.assertTrue(listing['ok'], listing)
                        self.assertEqual(listing['result'][0]['status'], 'starting')
                        print('native: separate CLI list returned during paused startup', flush=True)
                    finally:
                        waiting.sendall(b'1')
                barrier.close()
                barrier_path.unlink()
                await_process(jobs.status(start_id)['process'], timeout=45)
                started = jobs.status(start_id)
                self.assertEqual(started['state'], 'succeeded', started)
                record = started['result']
                rid = record['id']
                self.assertEqual(record['python_executable'], sys.executable)
                stable = Path(record['runtime_copy'])
                self.assertEqual(stable.parent, home / 'runtime')
                self.assertEqual(RuntimeStore(home).verify(str(stable)), stable)
                runtime = Path(record['runtime_dir'])
                self.assertEqual(private_json(runtime / 'spec.json')['runtime_copy'], str(stable))
                validate_live(record)
                env = Manager(home).env(rid)
                for key in ('HYPRLAND_INSTANCE_SIGNATURE', 'HYPRLAND_CMD', 'SSH_AUTH_SOCK', 'WAYLAND_SOCKET'):
                    self.assertNotIn(key, env)
                self.assertNotEqual(env['WAYLAND_DISPLAY'], hostile['WAYLAND_DISPLAY'])
                self.assertNotEqual(env['DISPLAY'], hostile['DISPLAY'])
                self.assertEqual(env['XDG_RUNTIME_DIR'], str(runtime))
                self.assertNotEqual(env['XDG_RUNTIME_DIR'], f'/run/user/{os.getuid()}')
                self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'], 'unix:path=' + str(runtime / 'bus'))
                self.assertTrue(env['AT_SPI_BUS_ADDRESS'].startswith('unix:path=' + str(runtime / 'at-spi') + '/'))
                self.assertEqual(env['HOME'], str(Path(record['workspace_dir']) / 'home'))
                self.assertTrue((runtime / env['WAYLAND_DISPLAY']).is_socket())
                xsocket = Path('/tmp/.X11-unix/X' + env['DISPLAY'][1:])
                print('native owned resources: ' + json.dumps({key: record[key] for key in
                    ('id', 'generation', 'scope', 'guardian_unit', 'runtime_dir', 'python_executable')}
                    | {'xsocket': str(xsocket)}), flush=True)
                self.assertNotIn(xsocket, host_sockets)
                self.assertNotIn(runtime / env['WAYLAND_DISPLAY'], host_sockets)
                for process in (record['supervisor'], record['processes']['worker']):
                    pid = process['pid']
                    argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                    environment = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
                    self.assertIn(b'-B', argv)
                    self.assertIn(b'PYTHONPATH=' + os.fsencode(stable), environment)
                    self.assertIn(b'PYTHONDONTWRITEBYTECODE=1', environment)
                    self.assertNotIn(os.fsencode(original), b'\0'.join(argv + environment))
                unit = subprocess.run(['systemctl', '--user', 'show', record['guardian_unit'],
                                       '--property=Environment,ExecStopPost'], env=host_control_env(),
                                      capture_output=True, text=True, check=True, timeout=10).stdout
                self.assertIn(str(stable), unit)
                self.assertIn('PYTHONDONTWRITEBYTECODE=1', unit)
                self.assertIn('-B', unit)
                self.assertNotIn(str(original), unit)

                endpoint = cli(home, 'vnc_endpoint', {'id': rid, 'owner': owner}, entry=original_entry)
                self.assertEqual(endpoint, {'ok': True, 'result': {'path': str(runtime / 'wayvnc.sock')}})
                info = (runtime / 'wayvnc.sock').lstat()
                self.assertTrue(stat.S_ISSOCK(info.st_mode))
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.settimeout(10)
                    connection.connect(endpoint['result']['path'])
                    self.assertEqual(receive(connection, 12), b'RFB 003.008\n')
                    connection.sendall(b'RFB 003.008\n')
                    count = receive(connection, 1)[0]
                    self.assertGreater(count, 0)
                    self.assertIn(1, receive(connection, count))
                    connection.sendall(b'\x01')
                    self.assertEqual(receive(connection, 4), b'\0\0\0\0')
                    connection.sendall(b'\x01')
                    server = receive(connection, 24)
                    self.assertEqual(struct.unpack('!HH', server[:4]), (800, 600))
                    name_length = struct.unpack('!I', server[20:24])[0]
                    self.assertLess(name_length, 65536)
                    receive(connection, name_length)

                after = {str(path.relative_to(original)): path.read_bytes()
                         for path in original.rglob('*') if path.is_file()}
                self.assertEqual(after, before)
                self.assertEqual(list(original.rglob('__pycache__')), [])
                shutil.rmtree(original)
                self.assertFalse(original.exists())
                # A new caller snapshot must still use the running generation's payload.
                launched = cli(home, 'driver_launcher', {'id': rid, 'owner': owner}, entry=updated_entry)
                self.assertTrue(launched['ok'], launched)
                content = Path(launched['result']['path']).read_text()
                self.assertTrue(content.startswith(f"#!{record['python_executable']} -IB\n"))
                self.assertIn(str(stable), content)
                self.assertNotIn(str(original), content)
                self.assertNotIn(str(updated), content)
                self.assertEqual(RuntimeStore(home).verify(str(stable)), stable)
                output = Manager(home).exec(rid, ['sh', '-c', 'echo hi'], cwd=env['HOME'], wait=True)
                self.assertEqual(output['returncode'], 0)
                self.assertEqual(output['stdout'], 'hi\n')
                shot = cli(home, 'shot', {'id': rid, 'owner': owner, 'format': 'jpeg',
                                         'quality': 80, 'scale': .5}, entry=updated_entry)
                self.assertTrue(shot['ok'], shot)
                self.assertEqual(shot['result']['mimeType'], 'image/jpeg')
                self.assertEqual((shot['result']['width'], shot['result']['height']), (400, 300))
                self.assertTrue((home / shot['result']['path']).is_file())
                windows = cli(home, 'windows', {'id': rid, 'owner': owner}, entry=updated_entry)
                self.assertTrue(windows['ok'], windows)
                self.assertIn('count', windows['result'])
                retained = Path(record['workspace_dir']) / 'home' / 'retained-after-stop.txt'
                retained.write_text('workspace survives compute teardown\n')
                # Terminating the guardian forces systemd's deferred
                # ExecStopPost cleanup to import from the surviving copy.
                retired = subprocess.run(['systemctl', '--user', 'stop', record['guardian_unit']],
                                         env=host_control_env(), capture_output=True, text=True, timeout=25)
                self.assertEqual(retired.returncode, 0, retired.stderr)
                stopped = cli(home, 'stop', {'id': rid, 'owner': owner}, entry=updated_entry)
                self.assertEqual(stopped, {'ok': True, 'result': True})
            finally:
                await_process(jobs.cancel(start_id)['process'], timeout=45)
                Manager(home).stop_owner(owner)
                # Synchronize ExecStopPost even after stop() observed supervisor exit.
                for owned in Registry(home).records():
                    if (owned['session_id'] == owner and
                            scope_info(owned['guardian_unit'])['ActiveState'] not in ('inactive', 'failed')):
                        subprocess.run(['systemctl', '--user', 'stop', owned['guardian_unit']],
                                       env=host_control_env(), check=True, capture_output=True, timeout=20)
            self.assertIsNotNone(record)
            self.assertEqual(Registry(home).get(rid)['status'], 'stopped')
            self.assertFalse(runtime.exists())
            self.assertFalse(xsocket.exists())
            self.assertTrue(Path(record['workspace_dir']).is_dir())
            self.assertEqual(retained.read_text(), 'workspace survives compute teardown\n')
            for unit_name in (record['scope'], record['guardian_unit']):
                self.assertIn(scope_info(unit_name)['ActiveState'], ('inactive', 'failed'))
            for process in (record['supervisor'], *record['processes'].values()):
                self.assertFalse(alive(process), process)
            for path, previous in host_sockets.items():
                current = path.lstat()
                self.assertEqual((current.st_dev, current.st_ino, current.st_ctime_ns),
                                 (previous.st_dev, previous.st_ino, previous.st_ctime_ns))
            snapshot = cli(home, 'delete_snapshot', {'id': rid, 'owner': owner}, entry=updated_entry)
            self.assertTrue(snapshot['ok'], snapshot)
            self.assertRegex(snapshot['result']['token'], r'^[0-9a-f]{64}$')
            deleted = cli(home, 'delete', {'id': rid, 'owner': owner,
                                         'token': snapshot['result']['token']}, entry=updated_entry)
            self.assertEqual(deleted, {'ok': True, 'result': True})
            self.assertFalse(Path(record['workspace_dir']).exists())
            print('native: exact units inactive, recorded PIDs dead, private runtime/X socket removed, '
                  'host display socket identities unchanged, workspace deleted by token', flush=True)
