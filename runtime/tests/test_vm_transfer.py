"""Real byte-stream transfer proof using a local receiver, without SSH or a VM."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from t3realms import vm_transfer as transfer, vm_transfer_archive as archive


class LocalReceiver:
    def __init__(self, root):
        self.home = root/'plugin'; self.home.mkdir(mode=0o700)
        self.guest = root/'guest'; self.guest.mkdir(mode=0o700)
    def validate(self, vm_id):
        if vm_id != 'fixture': raise ValueError('wrong owner')
        return {'session_id': vm_id}
    def guest_user(self, vm_id): return 'fixture-user'
    def guest_home(self, vm_id): return str(self.guest)
    def guest_run(self, vm_id, argv, *, user):
        return {'returncode': subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True).returncode}
    def ssh_argv(self, record, *, user):
        return [sys.executable, '-I', '-B', '-S', '-c', "import os,sys; os.execv('/bin/sh',['sh','-c',sys.argv[-1]])"]


class Transfers(unittest.TestCase):
    def test_literal_binary_push_pull_conflict_and_container(self):
        for direction in ('push', 'pull'):
            for directory in (False, True):
                with self.subTest(direction=direction, directory=directory), tempfile.TemporaryDirectory() as temporary:
                    root=Path(temporary); vm=LocalReceiver(root)
                    source=root/"selected project's 日本語 [*]?\\"
                    payload=bytes(range(256))*513+b'\0\xff'
                    if directory:
                        source.mkdir(); file=source/'binary'; (source/'link').symlink_to('binary')
                    else: file=source
                    file.write_bytes(payload)
                    target=root/'explicit target'; actual=target
                    if directory and direction=='pull': target.mkdir(); actual=target/source.name
                    operation=getattr(transfer, direction)
                    def copy(): return operation(vm, 'fixture', str(source), str(target))
                    self.assertEqual(copy()['destination'], str(actual))
                    copied=actual/'binary' if directory else actual
                    before=copied.stat().st_ino
                    self.assertEqual(copy()['destination'], str(actual)); self.assertEqual(copied.stat().st_ino,before)
                    if directory:
                        (source/'addition').write_bytes(b'new'); (actual/'unrelated').write_bytes(b'keep')
                        copy(); self.assertEqual((actual/'addition').read_bytes(),b'new'); self.assertEqual((actual/'unrelated').read_bytes(),b'keep')
                    file.write_bytes(b'changed')
                    with self.assertRaisesRegex(ValueError,'conflict'): copy()
                    self.assertEqual(copied.read_bytes(),payload)

    def test_push_default_is_guest_home_plus_basename(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); vm=LocalReceiver(root); source=root/'selected'; source.write_bytes(b'only selected')
            result=transfer.push(vm,'fixture',str(source),None)
            self.assertEqual(result['destination'],str(vm.guest/source.name))
            self.assertEqual((vm.guest/source.name).read_bytes(),b'only selected')

    def test_archive_rejects_traversal_hardlinks_devices_and_duplicate_entries(self):
        for attack in ('traversal','hardlink','device','duplicate'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary); stream=io.BytesIO()
                with tarfile.open(fileobj=stream,mode='w') as tar:
                    entry=tarfile.TarInfo('selected'); entry.type=tarfile.DIRTYPE; tar.addfile(entry)
                    entry=tarfile.TarInfo('selected/../../outside' if attack=='traversal' else 'selected/file')
                    if attack=='hardlink': entry.type=tarfile.LNKTYPE; entry.linkname='/etc/passwd'
                    elif attack=='device': entry.type=tarfile.CHRTYPE
                    tar.addfile(entry)
                    if attack=='duplicate': tar.addfile(entry)
                stream.seek(0)
                with self.assertRaises(ValueError): archive.unpack(stream,root/'destination')
                self.assertFalse((root/'destination').exists())
