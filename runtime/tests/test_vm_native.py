"""Approval-only VM qualification. Default discovery skips before any setup effect."""
import json
import os
from pathlib import Path
import select
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@unittest.skipUnless(os.environ.get('T3REALMS_NATIVE_VM') == '1', 'requires explicit native VM approval: T3REALMS_NATIVE_VM=1')
class NativeVm(unittest.TestCase):
    def test_signed_base_overlay_guest_capture_and_selected_copies(self):
        from t3realms.config import Config, effective_home
        from t3realms.jobs import Jobs
        from t3realms.vm_setup import plan
        from t3realms.vm_manager import VmManager
        supplied = os.environ.get('T3REALMS_NATIVE_VM_HOME')
        home = Path(supplied) if supplied else Path(tempfile.mkdtemp(prefix='t3realms-vm-native-', dir='/var/tmp'))
        self.assertTrue(str(home).startswith('/var/tmp/t3realms-vm-native-'))
        self.assertEqual(list(home.iterdir()), [], 'native qualification requires a fresh, empty home')
        effective_home(home)
        print('NATIVE_VM_HOME=' + str(home), flush=True)
        config = {'kind': 'omarchy-vm', 'size': '800x600', 'vm': {'memory': 3072, 'cpus': 2, 'disk_size': '40G'}}
        reviewed = plan(home, Config.from_object(config)); self.assertEqual(reviewed['blockers'], [], reviewed)
        jobs = Jobs(home)
        def wait(job_id, timeout):
            record = jobs.status(job_id)
            if record['state'] not in {'succeeded', 'failed', 'cancelled'}:
                try: fd = os.pidfd_open(record['process']['pid'])
                except ProcessLookupError: fd = None
                if fd is not None:
                    try: self.assertTrue(select.select([fd], [], [], timeout)[0], 'owned native job exceeded its deadline')
                    finally: os.close(fd)
            record = jobs.status(job_id); self.assertEqual(record['state'], 'succeeded', record)
            return record['result']
        setup = jobs.start('vm_setup', input={'config': config, 'review_id': reviewed['reviewId']})
        wait(setup['job_id'], 5700)
        vm = VmManager(home, config=config)
        owner = 'thread:native-vm-qualification'
        record = wait(jobs.start('start', owner=owner, input={'config': config})['job_id'], 900)
        vm_id = record['id']; stopped = False
        try:
            self.assertEqual(record['session_id'], owner)
            self.assertTrue(Path(record['session_dir']).is_relative_to(home))
            result = vm.guest_run(vm_id, ['uname', '-s'], timeout=10); self.assertEqual(result['stdout'].strip(), 'Linux')
            source = home / "selected literal [*] 日本語"; source.mkdir(); (source/'binary').write_bytes(bytes(range(256)))
            remote = str(Path(vm.guest_home(vm_id)) / source.name)
            pushed = vm.push(vm_id, str(source), remote); self.assertEqual(pushed['destination'], remote)
            self.assertEqual(vm.push(vm_id, str(source), remote)['destination'], remote)
            export = home/'export'; export.mkdir()
            pulled = vm.pull(vm_id, remote, str(export)); actual = Path(pulled['destination'])
            self.assertEqual(actual, export/source.name); self.assertEqual((actual/'binary').read_bytes(), bytes(range(256)))
            (actual/'binary').write_bytes(b'local changes')
            with self.assertRaises(ValueError): vm.pull(vm_id, remote, str(export))
            self.assertEqual((actual/'binary').read_bytes(), b'local changes')
            vm.resize(vm_id, '800x600')
            shot = vm.shot(vm_id, format='jpeg', quality=70, scale=.5)
            self.assertGreater(shot['bytes'], 100); self.assertLessEqual(shot['bytes'], 4*1024**2)
            vm.vnc_endpoint(vm_id)
            disk = Path(record['session_dir'])/'disk.qcow2'; inode = disk.stat().st_ino
            vm.stop(vm_id); stopped = True
            self.assertTrue(disk.exists()); self.assertEqual(vm.record(vm_id)['status'], 'stopped')
            again = wait(jobs.start('start', owner=owner, input={'config':config})['job_id'], 900)
            stopped = False
            self.assertEqual(again['id'], vm_id); self.assertEqual(disk.stat().st_ino, inode)
            self.assertNotEqual(again['compute_generation'], record['compute_generation'])
            vm.stop(vm_id); stopped = True
            review = vm.delete_snapshot(vm_id, session_id=owner)
            vm.delete(vm_id, session_id=owner, token=review['token'])
            self.assertFalse(disk.exists()); self.assertTrue(vm.base_status()['present'])
            self.assertEqual(vm.list(), [])
        finally:
            if not stopped and vm.registry.path(vm_id).exists(): vm.stop(vm_id)
        # Shared base/ISO, job logs and captures are intentionally retained for inspection.
        # Their deletion requires a separate decision after cleanup has been audited.
