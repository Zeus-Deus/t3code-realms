"""VM protocol and ownership proof with fake compute; never starts QEMU."""
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from t3realms.config import Config
from t3realms import vm_transfer_archive as archive
from t3realms.vm_manager import VmManager, validate_vm_record, VENDORED_SHA256, VENDORED_SCRIPT
from t3realms.lifecycle import OwnershipError

class VmContracts(unittest.TestCase):
    def test_vm_config_is_strict_and_independent(self):
        config = Config.from_object({'kind': 'omarchy-vm', 'vm': {'memory': 4096, 'cpus': 3, 'network': False}})
        self.assertEqual(config.vm.memory, 4096)
        self.assertFalse(config.vm.network)
        for value in ({'kind': 'other'}, {'vm': {'memory': True}}, {'vm': {'cpus': 0}}, {'vm': {'workspace_retention_days': -1}}, {'vm': {'network': 'false'}}):
            with self.subTest(value=value), self.assertRaises(ValueError): Config.from_object(value)

    def test_vendor_digest_and_home_are_ours(self):
        import hashlib
        self.assertEqual(hashlib.sha256(VENDORED_SCRIPT.read_bytes()).hexdigest(), VENDORED_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); home.chmod(0o700)
            vm = VmManager(home)
            self.assertTrue(vm.data.is_relative_to(home))
            with patch('t3realms.vm_manager.subprocess.run') as run, patch.object(Path, 'read_bytes', return_value=b'tampered'):
                with self.assertRaisesRegex(RuntimeError, 'pin'): vm._run_script(['launch'], vm_home=home)
                run.assert_not_called()

    def test_unit_and_runtime_replacement_are_refused(self):
        with self.assertRaises(OwnershipError):
            validate_vm_record({'id': 'v-' + 'a'*24, 'generation': 'a'*32, 'unit': 'hermes-vm-live.service'})

class ArchiveContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
    def packed(self, source):
        stream = io.BytesIO(); archive.pack(source, stream); stream.seek(0); return stream
    def test_literal_container_idempotence_merge_and_conflicts(self):
        source = self.root / "project [*] 日本語"; source.mkdir()
        name = "a' *?\\.bin"; (source / name).write_bytes(bytes(range(256)))
        (source / 'link').symlink_to(name)
        target = self.root / 'export'; target.mkdir()
        final = Path(archive.unpack(self.packed(source), target))
        self.assertEqual(final, target / source.name)
        inode = (final / name).stat().st_ino
        archive.unpack(self.packed(source), final, directory_exact=True)
        self.assertEqual((final / name).stat().st_ino, inode)
        (source / 'addition').write_text('new')
        archive.unpack(self.packed(source), final, directory_exact=True)
        (source / name).write_text('changed')
        with self.assertRaisesRegex(ValueError, 'conflict'): archive.unpack(self.packed(source), final, directory_exact=True)
        self.assertEqual((final / name).read_bytes(), bytes(range(256)))
        self.assertEqual(os.readlink(final / 'link'), name)
    def test_cleanup_preserves_concurrent_replacement(self):
        source = self.root / 'source'; source.mkdir(); (source / 'new').write_bytes(b'copy'); (source / 'link').symlink_to('new')
        target = self.root / 'target'; target.mkdir()
        original = archive._publish
        def publish(selected, fd, name):
            if name == 'link':
                replacement = self.root / 'replacement'; replacement.write_bytes(b'concurrent')
                os.replace(replacement, target / 'new')
                raise OSError('injected')
            return original(selected, fd, name)
        with patch.object(archive, '_publish', side_effect=publish), self.assertRaisesRegex(OSError, 'injected'):
            archive.unpack(self.packed(source), target, directory_exact=True)
        self.assertEqual((target / 'new').read_bytes(), b'concurrent')
    def test_external_symlink_never_exports(self):
        source = self.root / 'source'; source.mkdir(); (source / 'escape').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'link'): self.packed(source)

class VmLifecycle(unittest.TestCase):
    def setUp(self):
        from t3realms import vm_manager as module
        from t3realms.lifecycle import atomic_json, identity
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.home = self.root / 'plugin'; self.home.mkdir(mode=0o700)
        import subprocess
        self.real_run = subprocess.run
        self.active = {}; self.commands = []
        def scope(unit): return dict(self.active.get(unit, {'ActiveState': 'inactive', 'LoadState': 'not-found'}))
        for name in ('vm_manager', 'vm_lifetime', 'vm_ssh', 'vm_progress'):
            p = patch('t3realms.' + name + '.scope_info', side_effect=scope); p.start(); self.addCleanup(p.stop)
        p = patch.object(module, '_generation_paths', side_effect=lambda uid, gen: self.root / ('run-' + gen)); p.start(); self.addCleanup(p.stop)
        p = patch.object(module, 'require_resources'); p.start(); self.addCleanup(p.stop)
        self.vm = VmManager(self.home)
        base = self.vm.base_home(); base.mkdir(parents=True, mode=0o700)
        for name in ('disk.qcow2', 'OVMF_VARS.4m.fd'): (base / name).write_bytes(b'base contents')
        atomic_json(base / 'base.json', {'built_at': 1})
        def clone(session, base):
            from t3realms.vm_workspace import create
            for name in ('disk.qcow2', 'OVMF_VARS.4m.fd'): (session / name).write_bytes(b'guest work')
            record = self.vm.registry.get('v-' + session.name[:24]); create(record); return record['workspace']
        self.vm._clone_base = clone
        self.vm._wait_for_desktop = lambda record, config: None
        p = patch('t3realms.vm_manager.subprocess.run', return_value=__import__('types').SimpleNamespace(returncode=0)); p.start(); self.addCleanup(p.stop)
        def install(record):
            from t3realms.vm_lifetime import owner_unit
            self.active[owner_unit(record)] = {'ActiveState': 'active', 'InvocationID': 'b'*32, 'ControlGroup': '/test',
                'Description': 'T3 Code VM guardian ' + record['compute_generation']}
            record['supervisor'] = identity(os.getpid()); record['owner_invocation_id'] = 'b'*32
            atomic_json(Path(record['runtime_dir']) / 'supervisor.json', record['supervisor'])
        p = patch('t3realms.vm_lifetime.install', side_effect=install); p.start(); self.addCleanup(p.stop)
        def launch(argv, **kwargs):
            from t3realms.vm_progress import report
            record = self.vm.operation; self.commands.append((argv, kwargs))
            self.active[record['unit']] = {'ActiveState': 'active', 'InvocationID': 'c'*32, 'ControlGroup': '/test',
                'Description': 'T3 Code VM ' + record['compute_generation']}
            report(str(self.home), record['id'], record['compute_generation'], None, 'launched')
            (Path(record['runtime_dir']) / 'vnc.sock').touch(mode=0o600)
        self.vm._run_script = launch
        def enroll(record):
            path = Path(record['runtime_dir']) / 'ssh_known_hosts'
            if not path.exists(): path.write_bytes(b'pinned guest key\n'); path.chmod(0o600)
        p = patch.object(module, 'enroll_host_key', side_effect=enroll); p.start(); self.addCleanup(p.stop)
        def retire(record):
            for unit in self.vm._compute_units(record): self.active.pop(unit, None)
        p = patch('t3realms.vm_lifetime.retire', side_effect=retire); p.start(); self.addCleanup(p.stop)
        p = patch('t3realms.vm_lifetime.remove_dropin'); p.start(); self.addCleanup(p.stop)

    def test_stop_resume_keeps_disk_and_rotates_compute_identity(self):
        record = self.vm.start('thread:owner'); disk = Path(record['session_dir']) / 'disk.qcow2'; inode = disk.stat().st_ino
        self.assertEqual(self.vm.validate(record['id'])['status'], 'running')
        self.vm.stop(record['id']); self.assertEqual(self.vm.record(record['id'])['status'], 'stopped')
        again = self.vm.start('thread:owner')
        self.assertEqual(again['id'], record['id']); self.assertNotEqual(again['compute_generation'], record['compute_generation'])
        self.assertEqual((disk.stat().st_ino, disk.read_bytes()), (inode, b'guest work'))

    def test_stop_does_not_require_a_surviving_runtime_ssh_pin(self):
        record = self.vm.start('thread:owner')
        (Path(record['runtime_dir']) / 'ssh_known_hosts').unlink()
        self.assertTrue(self.vm.stop(record['id']))
        self.assertEqual(self.vm.record(record['id'])['status'], 'stopped')
        self.assertTrue((Path(record['session_dir']) / 'disk.qcow2').exists())

    def test_readonly_status_does_not_renew_idle(self):
        record = self.vm.start('thread:owner'); before = self.vm.record(record['id'])['last_activity']
        self.vm.validate(record['id']); self.vm.list(); self.vm.windows(record['id'])
        self.assertEqual(self.vm.record(record['id'])['last_activity'], before)
        with patch('t3realms.vm_manager.time.time', return_value=before + 1): self.vm.touch(record['id'])
        self.assertEqual(self.vm.record(record['id'])['last_activity'], before + 1)

    def test_disk_replacement_requires_explicit_discard(self):
        record = self.vm.start('thread:owner'); self.vm.stop(record['id'])
        disk = Path(record['session_dir']) / 'disk.qcow2'; new = disk.with_name('new'); new.write_bytes(b'changed'); os.replace(new, disk)
        self.assertEqual(self.vm.list()[0]['status'], 'recovery-required')
        with self.assertRaisesRegex(RuntimeError, 'recovery'): self.vm.start('thread:owner')
        with self.assertRaises(RuntimeError): self.vm.delete_snapshot(record['id'], session_id='thread:owner')
        snapshot = self.vm.delete_snapshot(record['id'], session_id='thread:owner', discard=True)
        self.assertTrue(self.vm.delete(record['id'], session_id='thread:owner', token=snapshot['token'], discard=True))
        self.assertFalse(disk.exists()); self.assertTrue(self.vm.base_home().exists())

    def test_delete_token_rejects_stale_publication_and_wrong_owner(self):
        record = self.vm.start('thread:owner'); self.vm.stop(record['id'])
        with self.assertRaises(OwnershipError): self.vm.record(record['id'], owner='thread:other')
        review = self.vm.delete_snapshot(record['id'], session_id='thread:owner')
        self.vm.registry.put(self.vm.record(record['id']))
        with self.assertRaises(OwnershipError): self.vm.delete(record['id'], session_id='thread:owner', token=review['token'])
        review = self.vm.delete_snapshot(record['id'], session_id='thread:owner')
        self.assertTrue(self.vm.delete(record['id'], session_id='thread:owner', token=review['token']))
        self.assertEqual(self.vm.list(), [])

    def test_retention_setting_zero_keeps_and_fourteen_expires(self):
        from dataclasses import replace
        record = self.vm.start('thread:owner'); self.vm.stop(record['id'])
        record = self.vm.record(record['id']); record.update(last_activity=1, stopped_at=1); self.vm.registry.put(record)
        self.vm.config = replace(self.vm.config, vm=replace(self.vm.config.vm, workspace_retention_days=0))
        self.assertEqual(len(self.vm.list()), 1)
        self.vm.config = replace(self.vm.config, vm=replace(self.vm.config.vm, workspace_retention_days=14))
        self.assertEqual(self.vm.list(), []); self.assertTrue(self.vm.base_home().exists())

    def test_start_releases_lock_and_honors_stop(self):
        from t3realms.vm_progress import report
        def launch(argv, **kwargs):
            import subprocess
            code = 'import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)'
            self.real_run([sys.executable, '-I', '-B', '-c', code, str(self.vm.registry.root / '.lock')], check=True)
            self.vm.stop(self.vm.operation['id'])
            report(str(self.home), self.vm.operation['id'], self.vm.operation['compute_generation'], None, 'launched')
        self.vm._run_script = launch
        with self.assertRaises(OwnershipError): self.vm.start('thread:owner')
        self.assertFalse(self.active); self.assertNotEqual(self.vm.registry.records()[0]['status'], 'running')

    def test_transfer_job_refuses_other_owner_and_incarnation(self):
        from t3realms.vm_jobs import validate_input
        record = self.vm.start('thread:owner')
        value = {'id': record['id'], 'incarnation': record['compute_generation'], 'direction': 'pull', 'source': '/guest', 'destination': '/export'}
        with self.assertRaises(OwnershipError): validate_input(self.home, 'transfer', 'thread:other', value)
        value['incarnation'] = 'f'*32
        with self.assertRaises(OwnershipError): validate_input(self.home, 'transfer', 'thread:owner', value)

class VmTransportContracts(unittest.TestCase):
    def test_vm_proxy_group_signal_allows_guest_retirement_receipt(self):
        import json
        import signal
        import socket
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory); runtime.chmod(0o700)
            ready = runtime / 'ready.sock'
            guest = ('import json,socket,sys\n'
                     f's=socket.socket(socket.AF_UNIX);s.connect({str(ready)!r});s.sendall(b"READY");s.close()\n'
                     'for line in sys.stdin:\n'
                     ' if line.strip()=="STOP": break\n'
                     'print(json.dumps({"driver_returncode":0,"cleaned":True}),flush=True)\n')
            code = (f'import sys;sys.path.insert(0,{str(Path(__file__).resolve().parents[1])!r})\n'
                    'from unittest.mock import patch\nfrom pathlib import Path\n'
                    'from t3realms.vm_cua import VmDriverProxy\n'
                    'p=VmDriverProxy.__new__(VmDriverProxy);p.vm=None;p.spec={"guest":{},"user":"guest"}\n'
                    f'p.runtime=Path({directory!r})\n'
                    f'with patch("t3realms.vm_cua._guest_command",return_value=[sys.executable,"-I","-B","-c",{guest!r}]):\n'
                    ' raise SystemExit(p._serve({}, {"socket":"hc-0123456789ab.sock","args":["serve"],"manifest":None}))\n')
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(ready)); listener.listen(1); listener.settimeout(5)
                process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                try:
                    with listener.accept()[0] as peer:
                        self.assertEqual(peer.recv(5), b'READY')
                    os.killpg(process.pid, signal.SIGTERM)
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 0, stderr.decode())
                    self.assertEqual(json.loads((runtime/'hc-0123456789ab.sock.retired').read_text()),
                                     {'driver_returncode':0, 'cleaned':True})
                finally:
                    if process.poll() is None:
                        process.kill(); process.communicate(timeout=5)

    def test_default_vm_mcp_invocation_keeps_authorization_on_serve(self):
        from t3realms.vm_cua import default_invocation
        runtime = Path('/run/user/1000/t3v-test')
        socket = str(runtime / 'hc-0123456789ab.sock')
        self.assertEqual(default_invocation(['mcp'], runtime, '0123456789abcdef'),
                         ['mcp', '--embedded', '--socket', socket])
        self.assertEqual(default_invocation(['serve'], runtime, '0123456789abcdef'),
                         ['serve', '--embedded', '--socket', socket, '--no-permissions-gate', '--no-overlay'])

    def test_guest_socket_startup_is_retryable_without_hiding_identity_errors(self):
        from t3realms.vm_cua_guest import driver_socket_identity
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory); runtime.chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'no Cua Driver daemon listening'):
                driver_socket_identity(runtime)
            with patch('t3realms.vm_cua_guest.read_owned', return_value=b'{"pid":123,"start":"456"}'):
                with self.assertRaisesRegex(ValueError, 'no Cua Driver daemon listening'):
                    driver_socket_identity(runtime)
                with patch('t3realms.vm_cua_guest.socket_identity', return_value={'peer_pid':999,'peer_start':'456'}):
                    with self.assertRaisesRegex(ValueError, 'replaced'):
                        driver_socket_identity(runtime)

    def test_ssh_pins_and_forwarding_flags(self):
        from t3realms.vm_ssh import ssh_options
        options = ssh_options({'runtime_dir': '/isolated'})
        for value in ('StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null', 'ForwardAgent=no', 'ForwardX11=no', 'IdentitiesOnly=yes'):
            self.assertIn(value, options)
        self.assertIn('UserKnownHostsFile=/isolated/ssh_known_hosts', options)
        self.assertEqual(options[:2], ['-F', '/dev/null'])

    def test_guest_environment_does_not_inherit_host_credentials(self):
        from t3realms.vm_launch import guest_script
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'secret', 'SSH_AUTH_SOCK': '/host-agent', 'DISPLAY': ':0'}):
            script = guest_script(['printf', '%s', 'literal $()'], '/guest/path')
        for value in ('secret', '/host-agent', ':0'): self.assertNotIn(value, script)
        self.assertIn('runuser', script)

    def test_cua_only_accepts_private_socket_and_inline_pixels(self):
        from t3realms.vm_cua import parse_invocation
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory); runtime.chmod(0o700)
            args = ['mcp', '--embedded', '--socket', str(runtime / 'hc-0123456789ab.sock')]
            self.assertEqual(parse_invocation(args, runtime)['socket'], 'hc-0123456789ab.sock')
            for argv in (['mcp'], ['mcp', '--embedded', '--socket', '/host/socket'], ['call', 'get_desktop_state', '{"screenshot_out_file":"/host/canary"}', '--socket', str(runtime/'hc-0123456789ab.sock')]):
                with self.assertRaises(ValueError): parse_invocation(argv, runtime)

class VmSafetyRegression(unittest.TestCase):
    def test_registry_rejects_invalid_compute_incarnation_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); home.chmod(0o700); vm = VmManager(home)
            with self.assertRaises(OwnershipError): vm.registry.put({'id': 'v-'+'a'*24, 'home': str(home), 'generation': 'a'*32})

    def test_setup_review_changes_with_resources_release_and_network(self):
        from t3realms.vm_setup import plan
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); home.chmod(0o700)
            report = {'base_image': {'present': False, 'path': str(home/'vm/base/disk.qcow2')}, 'driver': {'path':str(home/'bin/cua-driver'), 'verified':False},
                      'blockers': [], 'ready':False, 'platform':'linux', 'arch':'x86_64', 'systemd_user':True, 'message':'setup'}
            with patch('t3realms.vm_setup.doctor', return_value=report):
                config = Config.from_object({'kind':'omarchy-vm'}); original = plan(home, config)
                for vm in (replace(config.vm, memory=4096), replace(config.vm, release='4.0.3'), replace(config.vm, network=False)):
                    self.assertNotEqual(original['reviewId'], plan(home, replace(config, vm=vm))['reviewId'])
                self.assertEqual(original['downloads'][0]['signer'], '40DFB630FF42BCFFB047046CF0134EE680CAC571')
                self.assertEqual(original['storage']['requiredFreeBytes'], 46 * 1024**3)

    def test_retirement_refuses_a_replaced_vm_before_any_stop(self):
        from t3realms.vm_lifetime import retire
        record = {'unit':'owned.service', 'invocation_id':'a'*32}
        with patch('t3realms.vm_lifetime.scope_info', return_value={'ActiveState':'active','InvocationID':'b'*32}), patch('t3realms.vm_lifetime.subprocess.run') as run:
            with self.assertRaises(OwnershipError): retire(record)
            run.assert_not_called()

class VmInterruptedStartup(unittest.TestCase):
    def test_startup_owner_death_is_not_a_live_lease(self):
        from t3realms.vm_lifetime import startup_abandoned
        from t3realms.lifecycle import identity
        record = {'status': 'starting', 'startup_process': identity(os.getpid())}
        self.assertFalse(startup_abandoned(record))
        with patch('t3realms.vm_lifetime.alive', return_value=False): self.assertTrue(startup_abandoned(record))
        record['status'] = 'running'
        with patch('t3realms.vm_lifetime.alive', return_value=False): self.assertFalse(startup_abandoned(record))

class VmPortAdmission(unittest.TestCase):
    def test_no_free_ssh_port_leaves_no_unregistered_workspace(self):
        from t3realms.vm_manager import VmError
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); home = root / 'plugin'; home.mkdir(mode=0o700)
            vm = VmManager(home)
            with patch('t3realms.vm_manager._generation_paths', side_effect=lambda uid, gen: root / ('run-'+gen)), patch.object(vm, 'base_status', return_value={'present':True}), patch('t3realms.vm_manager.require_resources'), patch.object(vm, '_free_port', side_effect=VmError('no free loopback SSH port')):
                with self.assertRaises(VmError): vm.start('thread:owner')
            self.assertEqual(list((vm.registry.root / 'vm').glob('*')), [])
            self.assertEqual(list(root.glob('run-*')), [])

class VmDesktopSizing(unittest.TestCase):
    def test_resize_uses_the_guests_actual_monitor(self):
        from types import SimpleNamespace
        vm = VmManager.__new__(VmManager)
        record = {'runtime_dir':'/private', 'ssh_port':2300}
        with patch('t3realms.vm_manager.subprocess.run', side_effect=[SimpleNamespace(returncode=0, stdout='[{"name":"Virtual-2"}]', stderr=''), SimpleNamespace(returncode=0, stdout='ok', stderr='')]) as run:
            vm._desktop_resize(record,'800x600')
        self.assertIn('Virtual-2,800x600@60,auto,1', run.call_args.args[0][-1])
        self.assertNotIn('ForwardAgent=yes', run.call_args.args[0])

    def test_resize_uses_lua_when_legacy_keyword_reports_success_without_applying(self):
        from types import SimpleNamespace
        vm = VmManager.__new__(VmManager)
        record = {'runtime_dir':'/private', 'ssh_port':2300}
        replies = [SimpleNamespace(returncode=0, stdout='[{"name":"Virtual-2"}]', stderr=''),
                   SimpleNamespace(returncode=0, stdout="keyword can't work with non-legacy parsers. Use eval.\n", stderr=''),
                   SimpleNamespace(returncode=0, stdout='ok', stderr='')]
        with patch('t3realms.vm_manager.subprocess.run', side_effect=replies) as run:
            vm._desktop_resize(record, '800x600')
        self.assertEqual(run.call_count, 3)
        self.assertIn('eval', run.call_args.args[0][-1])
        self.assertIn('hl.monitor', run.call_args.args[0][-1])
        self.assertIn('800x600', run.call_args.args[0][-1])
