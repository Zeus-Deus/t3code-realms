import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os
import select
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from t3realms.bootstrap import (JOB_LIMIT, admit_job, private_environment, reap_jobs)
from t3realms.lifecycle import (OUTPUT_LIMIT_BYTES, BusyError, NotFoundError,
                                OwnershipError, atomic_json, identity)
from t3realms.manager import Manager
from support import stopped_record


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='t3r-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def test_output_drains_overflow_and_retains_results_for_five_minutes(self):
        process = subprocess.Popen([sys.executable, '-c',
                                    'import os; os.write(1,b"x"*400000); os.write(2,b"y"*400000)'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(process.stderr.close)
        self.addCleanup(process.stdout.close)
        self.addCleanup(lambda: process.wait(timeout=5))
        metadata = {'job_id': 'test', 'output_complete': False,
                    'stdout_truncated': False, 'stderr_truncated': False}
        for key in ('stdout', 'stderr'):
            path = self.home / (key + '.log')
            path.touch(mode=0o600)
            metadata[key + '_path'] = str(path)
            os.set_blocking(getattr(process, key).fileno(), False)
        jobs = {'test': (process, metadata)}
        finished = {}
        with patch('t3realms.bootstrap.job_clock', return_value=0):
            while not metadata['output_complete']:
                readers = [pipe for pipe in (process.stdout, process.stderr) if not pipe.closed]
                self.assertTrue(select.select(readers, [], [], 5)[0], 'writer did not produce output or EOF')
                reap_jobs(jobs, finished)
            process.wait(timeout=5)
            reap_jobs(jobs, finished)
        self.assertEqual(process.returncode, 0)
        self.assertTrue(metadata['stdout_truncated'])
        self.assertTrue(metadata['stderr_truncated'])
        self.assertEqual(Path(metadata['stdout_path']).read_bytes(), b'x' * OUTPUT_LIMIT_BYTES)
        self.assertEqual(Path(metadata['stderr_path']).read_bytes(), b'y' * OUTPUT_LIMIT_BYTES)
        with patch('t3realms.bootstrap.job_clock', return_value=299):
            reap_jobs(jobs, finished)
        self.assertIn('test', jobs)
        with patch('t3realms.bootstrap.job_clock', return_value=300):
            reap_jobs(jobs, finished)
        self.assertEqual(jobs, {})
        self.assertFalse(Path(metadata['stdout_path']).exists())

    def test_job_capacity_rejects_new_work_without_evicting_old_results(self):
        jobs = {str(index): None for index in range(JOB_LIMIT)}
        with self.assertRaises(BusyError):
            admit_job(jobs, {'op': 'exec'})
        self.assertEqual(len(jobs), JOB_LIMIT)
        admit_job(jobs, {'op': 'job', 'job_id': '0'})
        with self.assertRaises(NotFoundError):
            admit_job(jobs, {'op': 'signal', 'job_id': 'absent'})

    def test_private_environment_strips_ambient_host_handles(self):
        record = stopped_record(self.home)
        runtime = self.home / 'private-runtime'
        runtime.mkdir(mode=0o700)
        atomic_json(runtime / 'workspace.json', record)
        with patch.dict(os.environ, {'WAYLAND_DISPLAY': 'host-wayland', 'DISPLAY': ':0',
                                    'HYPRLAND_INSTANCE_SIGNATURE': 'host', 'SWAYSOCK': 'host',
                                    'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus'}):
            env = private_environment(runtime)
        for key in ('WAYLAND_DISPLAY', 'DISPLAY', 'HYPRLAND_INSTANCE_SIGNATURE', 'SWAYSOCK',
                    'DBUS_SESSION_BUS_ADDRESS'):
            self.assertNotIn(key, env)
        self.assertEqual(env['HOME'], record['workspace_dir'] + '/home')
        self.assertEqual(env['XDG_RUNTIME_DIR'], str(runtime))
        self.assertEqual(env['CUA_DRIVER_RS_TELEMETRY_ENABLED'], '0')
        (runtime / 'workspace.json').unlink()
        with self.assertRaises(OwnershipError):
            private_environment(runtime)

    def rpc_server(self, mode=0o600):
        runtime = self.home / 'r'
        runtime.mkdir(mode=0o700)
        code = '''import json, os, socket, sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.bind(sys.argv[1]); os.chmod(sys.argv[1],int(sys.argv[2])); s.listen(1)
print('ready',flush=True)
s.settimeout(5)
try:
 c,_=s.accept()
 with c:
  request=c.makefile('rb').readline()
  if request:
   c.sendall(json.dumps({'result':json.loads(request)}).encode()+b'\\n')
except TimeoutError:
 pass
'''
        process = subprocess.Popen([sys.executable, '-I', '-c', code,
                                    str(runtime / 'control'), str(mode)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        self.addCleanup(process.stderr.close)
        self.addCleanup(process.stdout.close)
        self.addCleanup(lambda: process.wait(timeout=6))
        self.assertTrue(select.select([process.stdout], [], [], 5)[0])
        self.assertEqual(process.stdout.readline(), b'ready\n')
        return runtime, process

    def test_rpc_kernel_peer_identity_and_payload(self):
        runtime, process = self.rpc_server()
        manager = Manager(self.home)
        record = {'runtime_dir': str(runtime), 'processes': {'worker': identity(process.pid)}}
        with patch.object(manager, 'env', return_value={}), patch.object(manager.registry, 'get', return_value=record):
            result = manager._rpc('r-' + 'a' * 24, renew=False, op='outputs')
        self.assertEqual(result['op'], 'outputs')
        self.assertEqual(result['client_process'], identity(os.getpid()))

    def test_rpc_rejects_pid_start_time_mismatch(self):
        runtime, process = self.rpc_server()
        manager = Manager(self.home)
        worker = identity(process.pid)
        record = {'runtime_dir': str(runtime),
                  'processes': {'worker': dict(worker, start_time=worker['start_time'] + 1)}}
        with patch.object(manager, 'env', return_value={}), patch.object(manager.registry, 'get', return_value=record):
            with self.assertRaises(OwnershipError):
                manager._rpc('r-' + 'a' * 24, renew=False, op='outputs')

    def test_rpc_rejects_nonprivate_control_socket(self):
        runtime, process = self.rpc_server(mode=0o666)
        manager = Manager(self.home)
        record = {'runtime_dir': str(runtime), 'processes': {'worker': identity(process.pid)}}
        with patch.object(manager, 'env', return_value={}), patch.object(manager.registry, 'get', return_value=record):
            with self.assertRaises(OwnershipError):
                manager._rpc('r-' + 'a' * 24, renew=False, op='outputs')
        # Unblock just our harmless test server, using its captured Popen object.
        process.terminate()
