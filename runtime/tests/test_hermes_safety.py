"""Hermes safety regressions adapted to unittest and fake native boundaries.

Adapted from Hermes Realms da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus):
tests/test_realms_workspace.py, test_realms_workspace_native.py,
test_realms_vm_transfer_conflicts.py, test_realms_vm_transfer_namespace.py,
test_realms_vm_transfer_mounts.py, test_realms_vm_transfer_stream.py,
test_realms_vm_transfer_copy.py, test_realms_prepare_readonly.py,
test_realms_driver_verification_privacy.py and test_realms_setup_progress.py.
Native Hermes tests are represented by injected syscall/compute failures here;
these tests do not qualify mount namespaces, systemd, SSH or real driver boots.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contextlib import ExitStack
import errno
import hashlib
import io
import os
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from support import stopped_record
from t3realms import install_driver, lifecycle, supervisor, vm_transfer as transport
from t3realms import vm_transfer_archive as archive
from t3realms.config import Config
from t3realms.manager import Manager
from t3realms.setup_plan import plan


def packed(source):
    stream = io.BytesIO()
    archive.pack(source, stream)
    stream.seek(0)
    return stream


def snapshot(root):
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        data = os.readlink(path) if stat.S_ISLNK(mode) else path.read_bytes() if stat.S_ISREG(mode) else None
        result[str(path.relative_to(root))] = (mode, data)
    return result


class SafetyFixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='t3r-hermes-safety-', dir='/var/tmp')
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)

    def case(self, name):
        root = self.home / name
        root.mkdir(mode=0o700)
        return root


class DeleteSafetyTests(SafetyFixture):
    def test_interrupted_delete_requires_fresh_review_and_preserves_peer(self):
        for phase in ('home', 'receipt', 'directory', 'registry'):
            with self.subTest(phase=phase):
                home = self.case(phase)
                manager = Manager(home)
                record = stopped_record(home, 'owner-one')
                peer = stopped_record(home, 'owner-two')
                root, peer_root = Path(record['workspace_dir']), Path(peer['workspace_dir'])
                (root / 'home/sentinel').write_bytes(b'private-work')
                (peer_root / 'home/sentinel').write_bytes(b'peer-work')
                original_tree, original_unlink, original_rmdir = shutil.rmtree, Path.unlink, Path.rmdir
                def rmtree(path, *args, **kwargs):
                    if phase == 'home' and Path(path) == root / 'home':
                        raise OSError('injected deletion interruption')
                    return original_tree(path, *args, **kwargs)
                def unlink(path, *args, **kwargs):
                    selected = root / 'owner.json' if phase == 'receipt' else manager.registry.path(record['id'])
                    if phase in ('receipt', 'registry') and path == selected:
                        raise OSError('injected deletion interruption')
                    return original_unlink(path, *args, **kwargs)
                def rmdir(path, *args, **kwargs):
                    if phase == 'directory' and path == root:
                        raise OSError('injected deletion interruption')
                    return original_rmdir(path, *args, **kwargs)
                with patch('t3realms.manager.scope_info', return_value={'ActiveState': 'inactive'}):
                    proposal = manager.delete_snapshot(record['id'], session_id='owner-one')
                    with patch('shutil.rmtree', side_effect=rmtree), patch.object(Path, 'unlink', unlink), \
                            patch.object(Path, 'rmdir', rmdir), self.assertRaisesRegex(OSError, 'injected deletion'):
                        manager.delete(record['id'], session_id='owner-one', token=proposal['token'])
                    fresh = Manager(home)
                    rows = {row['id']: row for row in fresh.list()}
                    self.assertEqual(rows[record['id']]['status'], 'deleting')
                    self.assertEqual(rows[peer['id']]['status'], 'stopped')
                    with self.assertRaises(lifecycle.OwnershipError):
                        fresh.delete(record['id'], session_id='owner-one', token=proposal['token'])
                    with self.assertRaises(lifecycle.OwnershipError):
                        fresh.delete_snapshot(record['id'], session_id='owner-two')
                    self.assertTrue(fresh.stop(record['id']))
                    supervisor.cleanup(home, record['id'], record['generation'])
                    self.assertEqual(fresh.record(record['id'])['status'], 'deleting')
                    proposal = fresh.delete_snapshot(record['id'], session_id='owner-one')
                    fresh.delete(record['id'], session_id='owner-one', token=proposal['token'])
                self.assertFalse(root.exists())
                self.assertFalse(fresh.registry.path(record['id']).exists())
                self.assertEqual((peer_root / 'home/sentinel').read_bytes(), b'peer-work')

    def test_missing_or_replaced_home_never_inherits_delete_authority(self):
        manager = Manager(self.home)
        record = stopped_record(self.home)
        root = Path(record['workspace_dir'])
        (root / 'home/sentinel').write_bytes(b'keep')
        with patch('t3realms.manager.scope_info', return_value={'ActiveState': 'inactive'}):
            proposal = manager.delete_snapshot(record['id'], session_id=record['session_id'])
            (root / 'home').rename(root / 'saved')
            for kind in ('missing', 'directory', 'symlink'):
                with self.subTest(kind=kind):
                    if kind == 'directory':
                        (root / 'home').mkdir(mode=0o700)
                    if kind == 'symlink':
                        (root / 'home').rmdir()
                        (root / 'home').symlink_to(root / 'saved', target_is_directory=True)
                    with self.assertRaises(lifecycle.OwnershipError):
                        manager.delete(record['id'], session_id=record['session_id'], token=proposal['token'])
                    self.assertEqual((root / 'saved/sentinel').read_bytes(), b'keep')

    def test_supervisor_cleanup_refuses_replacement_generation(self):
        record = stopped_record(self.home)
        with patch('t3realms.supervisor.stop_scope') as stop, patch('t3realms.supervisor.remove_runtime') as remove:
            supervisor.cleanup(self.home, record['id'], 'f' * 32)
            stop.assert_not_called()
            remove.assert_not_called()
        self.assertEqual(Manager(self.home).record(record['id']), record)

    def test_runtime_removal_failure_keeps_workspace_and_retryable_receipt(self):
        record = stopped_record(self.home)
        root = self.home / 'fake-runtime'
        root.mkdir(mode=0o700)
        (root / 'socket-placeholder').write_bytes(b'temporary')
        record = dict(record, runtime_dir=str(root), status='running')
        registry = MagicMock()
        values = []
        registry.put.side_effect = lambda value: values.append(dict(value))
        with patch('t3realms.lifecycle.validate_record'), patch('t3realms.lifecycle.shutil.rmtree', side_effect=PermissionError('denied')), \
                patch('os.chmod') as chmod:
            with self.assertRaisesRegex(lifecycle.RealmError, 'cleanup failed'):
                lifecycle.remove_runtime(registry, record)
            chmod.assert_not_called()
        self.assertEqual(values[-1]['status'], 'cleanup_failed')
        self.assertIn('denied', values[-1]['cleanup_error'])
        self.assertTrue(Path(record['workspace_dir']).is_dir())
        with patch('t3realms.lifecycle.validate_record'):
            lifecycle.remove_runtime(registry, values[-1])
        self.assertEqual(values[-1]['status'], 'stopped')
        self.assertNotIn('cleanup_error', values[-1])
        self.assertFalse(root.exists())
        self.assertTrue(Path(record['workspace_dir']).is_dir())


class TransferSafetyTests(SafetyFixture):
    def test_conflict_preflight_preserves_entire_selected_copy(self):
        for kind in ('bytes', 'file-directory', 'directory-file', 'link'):
            with self.subTest(kind=kind):
                root = self.case(kind)
                source, destination = root / 'source', root / 'destination'
                source.mkdir(); destination.mkdir()
                (source / 'a-new').write_bytes(b'new\x00\xff')
                old, incoming = destination / 'z-conflict', source / 'z-conflict'
                if kind == 'directory-file':
                    incoming.mkdir(); (incoming / 'child').write_bytes(b'original source')
                    old.write_bytes(b'original destination')
                elif kind == 'file-directory':
                    incoming.write_bytes(b'original source'); old.mkdir()
                    (old / 'child').write_bytes(b'original destination')
                elif kind == 'link':
                    incoming.symlink_to('a-new'); old.symlink_to('retained')
                    (destination / 'retained').write_bytes(b'original destination')
                else:
                    incoming.write_bytes(b'original source'); old.write_bytes(b'original destination')
                before_source, before_destination = snapshot(source), snapshot(destination)
                with patch.object(archive, '_publish', wraps=archive._publish) as publish:
                    with self.assertRaisesRegex(ValueError, 'conflict'):
                        archive.unpack(packed(source), destination, directory_exact=True)
                    publish.assert_not_called()
                self.assertEqual(snapshot(source), before_source)
                self.assertEqual(snapshot(destination), before_destination)

    def test_concurrent_destination_appearance_is_not_overwritten(self):
        for appearance in ('file', 'symlink', 'directory'):
            with self.subTest(appearance=appearance):
                root = self.case(appearance)
                source, destination = root / 'source', root / 'destination'
                source.mkdir(); destination.mkdir()
                (source / 'a-new').write_bytes(b'first addition')
                (source / 'z-race').write_bytes(b'selected bytes')
                outside = root / 'outside'; outside.write_bytes(b'outside sentinel')
                original = archive._publish
                witnessed = []
                def publish(selected, fd, name):
                    if name == 'z-race':
                        target = destination / name
                        if appearance == 'file': target.write_bytes(b'concurrent bytes')
                        elif appearance == 'symlink': target.symlink_to(outside)
                        else: target.mkdir()
                        witnessed.append(target.lstat().st_ino)
                    return original(selected, fd, name)
                with patch.object(archive, '_publish', side_effect=publish):
                    with self.assertRaisesRegex(ValueError, 'conflict'):
                        archive.unpack(packed(source), destination, directory_exact=True)
                self.assertEqual(witnessed, [(destination / 'z-race').lstat().st_ino])
                self.assertFalse((destination / 'a-new').exists())
                self.assertEqual(outside.read_bytes(), b'outside sentinel')
                self.assertEqual((source / 'z-race').read_bytes(), b'selected bytes')
                self.assertEqual(list(root.rglob('.t3realms-transfer-*')), [])

    def test_failed_copy_removes_only_its_additions(self):
        for failure in (OSError, KeyboardInterrupt, PermissionError):
            for existing in (False, True):
                with self.subTest(failure=failure, existing=existing):
                    root = self.case(failure.__name__ + str(existing))
                    source, destination = root / 'source', root / 'destination'
                    (source / 'new-dir').mkdir(parents=True)
                    (source / 'new-dir/file').write_bytes(b'new\x00\xff')
                    (source / 'z-link').symlink_to('new-dir/file')
                    if existing:
                        destination.mkdir(); (destination / 'unrelated').write_bytes(b'keep')
                    before, before_source = snapshot(destination), snapshot(source)
                    original = archive._publish
                    def publish(selected, fd, name):
                        if name == 'z-link': raise failure('injected publication interruption')
                        return original(selected, fd, name)
                    with patch.object(archive, '_publish', side_effect=publish), self.assertRaises(failure):
                        archive.unpack(packed(source), destination, directory_exact=True)
                    self.assertEqual(snapshot(source), before_source)
                    if existing: self.assertEqual(snapshot(destination), before)
                    else: self.assertFalse(destination.exists())
                    self.assertEqual(list(root.rglob('.t3realms-transfer-*')), [])

    def test_directory_open_failure_does_not_leave_partial_tree(self):
        source, destination = self.home / 'source', self.home / 'destination'
        source.mkdir(); (source / 'file').write_bytes(b'source preserved')
        stream, original = packed(source), os.open
        failures = []
        def exhausted(path, flags, *args, **kwargs):
            if path == destination.name and destination.exists() and not failures:
                failures.append(True)
                raise OSError(errno.EMFILE, 'injected descriptor exhaustion')
            return original(path, flags, *args, **kwargs)
        with patch('os.open', side_effect=exhausted), self.assertRaisesRegex(OSError, 'descriptor exhaustion'):
            archive.unpack(stream, destination, directory_exact=True)
        self.assertEqual(failures, [True])
        self.assertFalse(destination.exists())
        self.assertEqual((source / 'file').read_bytes(), b'source preserved')

    def test_rollback_preserves_concurrently_replaced_link(self):
        source, destination = self.home / 'source', self.home / 'destination'
        source.mkdir(); destination.mkdir()
        (source / 'new').write_bytes(b'copied'); (source / 'link').symlink_to('new')
        (destination / 'unrelated').write_bytes(b'existing work')
        outside = self.home / 'outside'; outside.write_bytes(b'outside sentinel')
        original = archive._publish
        def interrupt(selected, fd, name):
            if name == 'link':
                replacement = self.home / 'replacement'; replacement.symlink_to(outside)
                os.replace(replacement, destination / 'new')
                raise OSError('injected failure')
            return original(selected, fd, name)
        with patch.object(archive, '_publish', side_effect=interrupt), self.assertRaisesRegex(OSError, 'injected failure') as caught:
            archive.unpack(packed(source), destination, directory_exact=True)
        self.assertTrue(any('cleanup incomplete' in note for note in caught.exception.__notes__))
        self.assertEqual(os.readlink(destination / 'new'), str(outside))
        self.assertEqual(outside.read_bytes(), b'outside sentinel')
        self.assertEqual((destination / 'unrelated').read_bytes(), b'existing work')

    def test_exdev_publication_no_space_and_race_matrix(self):
        for placement in ('root', 'nested', 'full', 'nested-full', 'nested-race'):
            with self.subTest(placement=placement):
                root = self.case(placement)
                source, destination = root / 'source', root / 'destination'
                destination.mkdir()
                nested = placement.startswith('nested')
                if nested:
                    (source / 'sub').mkdir(parents=True); (destination / 'sub').mkdir()
                    (source / 'a-new').write_bytes(b'first addition')
                    selected, target = source / 'sub/file', destination / 'sub/file'
                    (source / 'sub/link').symlink_to('file')
                else:
                    selected, target = source, destination / source.name
                selected.write_bytes(b'new file bytes')
                sentinel = destination / 'retained'; sentinel.write_bytes(b'previous contents')
                original_link, original_write = archive._link_new, archive.LimitedWriter.write
                copying = []
                def link_new(path, fd, name, *, source_fd=None):
                    if source_fd is None:
                        if name == target.name: copying.append(True)
                        raise OSError(errno.EXDEV, 'injected cross-device link')
                    if placement == 'nested-race' and name == 'file':
                        target.write_bytes(b'concurrent destination')
                    return original_link(path, fd, name, source_fd=source_fd)
                def write(writer, data):
                    if copying and placement.endswith('full'):
                        raise OSError(errno.ENOSPC, 'injected no space on destination')
                    return original_write(writer, data)
                stream = packed(source)
                with patch.object(archive, '_link_new', side_effect=link_new), patch.object(archive.LimitedWriter, 'write', write):
                    if placement.endswith('full'):
                        with self.assertRaises(OSError) as caught:
                            archive.unpack(stream, destination, directory_exact=nested)
                        self.assertEqual(caught.exception.errno, errno.ENOSPC)
                        self.assertFalse(target.exists())
                    elif placement.endswith('race'):
                        with self.assertRaisesRegex(ValueError, 'conflict'):
                            archive.unpack(stream, destination, directory_exact=True)
                        self.assertEqual(target.read_bytes(), b'concurrent destination')
                    else:
                        archive.unpack(stream, destination, directory_exact=nested)
                        self.assertEqual(target.read_bytes(), b'new file bytes')
                        if nested: self.assertEqual((destination / 'sub/link').read_bytes(), b'new file bytes')
                if placement.endswith(('full', 'race')): self.assertFalse((destination / 'a-new').exists())
                self.assertEqual(sentinel.read_bytes(), b'previous contents')
                self.assertEqual(selected.read_bytes(), b'new file bytes')
                self.assertEqual(list(root.rglob('.t3realms-transfer-*')), [])

    def test_source_exchange_cannot_export_new_symlink_target(self):
        source, outside = self.home / 'selected', self.home / 'outside'
        source.mkdir(); outside.mkdir()
        (source / 'ordinary').write_bytes(b'allowed')
        sentinel = b'fixture-only-unselected-content'; (outside / 'sentinel').write_bytes(sentinel)
        original, swapped = Path.is_symlink, []
        def exchange(path):
            result = original(path)
            if path == source and not swapped:
                swapped.append(True); source.rename(self.home / 'original'); source.symlink_to(outside, target_is_directory=True)
            return result
        stream = io.BytesIO()
        with patch.object(Path, 'is_symlink', exchange):
            try: archive.pack(source, stream)
            except (ValueError, OSError): pass
        self.assertEqual(swapped, [True])
        self.assertNotIn(sentinel, stream.getvalue())

    def test_relative_link_preserves_literal_target_and_meaning(self):
        for index, (pivot, target, referent) in enumerate((('deep/inside', 'pivot/../file', 'deep/file'),
                ('deep/inside', 'pivot/../../file', 'file'), ('a/b/c', 'pivot/../../../file', 'file'))):
            with self.subTest(pivot=pivot, target=target):
                root = self.case(str(index)); source, destination = root / 'source', root / 'destination'
                (source / pivot).mkdir(parents=True); (source / 'file').write_bytes(b'wrong')
                (source / referent).write_bytes(b'expected')
                (source / 'pivot').symlink_to(pivot, target_is_directory=True); (source / 'link').symlink_to(target)
                archive.unpack(packed(source), destination, directory_exact=True)
                self.assertEqual(os.readlink(destination / 'link'), target)
                self.assertEqual((destination / 'link').read_bytes(), b'expected')

    def test_retained_link_cannot_turn_incoming_link_into_escape(self):
        source, destination, outside = self.home / 'source', self.home / 'destination', self.home / 'outside'
        source.mkdir(); destination.mkdir(); outside.mkdir()
        (source / 'leak').symlink_to('bridge/sentinel'); (outside / 'sentinel').write_bytes(b'untouched')
        (destination / 'bridge').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'link'):
            archive.unpack(packed(source), destination, directory_exact=True)
        self.assertFalse((destination / 'leak').is_symlink())
        (source / 'leak').unlink(); (source / 'ordinary').write_bytes(b'copied')
        archive.unpack(packed(source), destination, directory_exact=True)
        self.assertEqual((destination / 'ordinary').read_bytes(), b'copied')
        self.assertEqual((outside / 'sentinel').read_bytes(), b'untouched')

    def test_private_new_directory_and_retained_mode(self):
        source, destination = self.home / 'source', self.home / 'destination'
        source.mkdir(mode=0o700); (source / 'file').write_bytes(b'private')
        previous = os.umask(0o022)
        try:
            archive.unpack(packed(source), destination, directory_exact=True)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode) & 0o077, 0)
            destination.chmod(0o750)
            archive.unpack(packed(source), destination, directory_exact=True)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o750)
        finally:
            os.umask(previous)

    def test_writable_destination_does_not_require_writable_parent(self):
        for exact in (False, True):
            with self.subTest(exact=exact):
                root = self.case(str(exact))
                source, parent = root / 'source', root / 'readonly-parent'
                destination = parent / 'destination'
                destination.mkdir(parents=True)
                (destination / 'unrelated').write_bytes(b'unchanged')
                if exact:
                    source.mkdir(); (source / 'file').write_bytes(b'copied')
                else:
                    source.write_bytes(b'copied')
                parent.chmod(0o555)
                try:
                    archive.unpack(packed(source), destination, directory_exact=exact)
                    self.assertEqual((destination / ('file' if exact else source.name)).read_bytes(), b'copied')
                    self.assertEqual((destination / 'unrelated').read_bytes(), b'unchanged')
                    self.assertEqual(list(parent.glob('.t3realms-transfer-*')), [])
                finally:
                    parent.chmod(0o700)

    def test_missing_literal_source_never_selects_glob_decoy(self):
        decoy = self.home / 'literal-one'; decoy.write_bytes(b'never selected')
        stream = io.BytesIO()
        with self.assertRaises(FileNotFoundError): archive.pack(self.home / 'literal-*', stream)
        self.assertNotIn(b'never selected', stream.getvalue())
        self.assertEqual(decoy.read_bytes(), b'never selected')


class SetupSafetyTests(SafetyFixture):
    def test_verification_disables_inherited_telemetry(self):
        target = self.home / 'driver'; target.write_bytes(b'fake executable, never run'); target.chmod(0o700)
        checksum = hashlib.sha256(target.read_bytes()).hexdigest()
        for inherited in ('', '1'):
            with self.subTest(inherited=inherited), patch.dict(os.environ, {'CUA_DRIVER_RS_TELEMETRY_ENABLED': inherited}), \
                    patch.object(install_driver, 'BINARY_SHA256', checksum), \
                    patch.object(install_driver.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, install_driver.VERSION)) as run:
                install_driver.verify_execution(target)
                self.assertEqual(run.call_args.kwargs['env']['CUA_DRIVER_RS_TELEMETRY_ENABLED'], '0')
                self.assertTrue(install_driver.execution_verified(target))

    def test_cold_setup_plan_is_readonly_and_reports_unsupported_platform(self):
        before = snapshot(self.home)
        for platform in ('linux', 'darwin', 'win32'):
            report = {'platform': platform, 'arch': 'x86_64', 'systemd_user': False,
                      'ready': False, 'missing': ['labwc'], 'message': 'missing labwc',
                      'driver': {'path': str(self.home / 'bin/cua-driver'), 'verified': False}}
            with self.subTest(platform=platform), patch('t3realms.diagnostics.doctor', return_value=report), \
                    patch('t3realms.setup_plan.sys.platform', platform), \
                    patch('t3realms.setup_plan.distribution', return_value='unsupported'), \
                    patch('subprocess.run') as run:
                result = plan(self.home, Config())
                self.assertFalse(result['ready']); self.assertTrue(result['blockers'])
                self.assertIsNone(result['argv']); run.assert_not_called()
                self.assertEqual(snapshot(self.home), before)


class StreamSafetyTests(SafetyFixture):
    def stream_fixture(self, chunks, *, returncode=0):
        process = MagicMock()
        process.__enter__.return_value = process
        process.returncode = None
        process.poll.side_effect = lambda: process.returncode
        def wait(**_kwargs):
            process.returncode = returncode
            return returncode
        process.wait.side_effect = wait
        process.stdout.fileno.return_value = 10
        process.stderr.fileno.return_value = 11
        keys = {}
        selector = MagicMock()
        selector.__enter__.return_value = selector
        def register(file, _events, data):
            fd = file.fileno(); keys[fd] = SimpleNamespace(fd=fd, fileobj=file, data=data)
        selector.register.side_effect = register
        selector.unregister.side_effect = lambda file: keys.pop(file.fileno())
        selector.get_map.side_effect = lambda: keys
        selector.select.side_effect = lambda _timeout: [(key, 1) for key in list(keys.values())]
        def read(fd, _limit):
            return chunks[fd].pop(0) if chunks[fd] else b''
        return process, selector, read

    def test_stream_drains_bounded_diagnostics_without_ambient_secret(self):
        process, selector, read = self.stream_fixture({10: [b'exact response'], 11: [b'x' * 65536] * 20})
        with patch.dict(os.environ, {'TRANSFER_HOST_SECRET': 'fixture-only-canary'}), \
                patch.object(transport.subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(transport.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(transport.os, 'read', side_effect=read) as reads:
            result = transport.run_stream(['/fake/ssh'])
        self.assertEqual(result, b'exact response')
        self.assertNotIn('TRANSFER_HOST_SECRET', spawn.call_args.kwargs['env'])
        self.assertGreater(reads.call_count, 20)
        process.kill.assert_not_called()

    def test_stream_failure_kills_and_reaps_only_owned_child(self):
        for failure in ('overflow', 'timeout', 'exit', 'cancel'):
            chunks = {10: [b'x' * 65536, b'x'], 11: [b'source not found']}
            process, selector, read = self.stream_fixture(chunks, returncode=7 if failure == 'exit' else 0)
            if failure == 'exit': chunks[10] = []
            with self.subTest(failure=failure), ExitStack() as patches:
                patches.enter_context(patch.object(transport.subprocess, 'Popen', return_value=process))
                patches.enter_context(patch.object(transport.selectors, 'DefaultSelector', return_value=selector))
                patches.enter_context(patch.object(transport.os, 'read', side_effect=KeyboardInterrupt if failure == 'cancel' else read))
                if failure == 'timeout': patches.enter_context(patch.object(transport.time, 'monotonic', side_effect=[0, 1000]))
                error = {'overflow': ValueError, 'timeout': subprocess.TimeoutExpired,
                         'exit': subprocess.CalledProcessError, 'cancel': KeyboardInterrupt}[failure]
                with self.assertRaises(error): transport.run_stream(['/fake/ssh'])
                if failure == 'exit': process.kill.assert_not_called()
                else: process.kill.assert_called_once()
                process.wait.assert_called_once()
