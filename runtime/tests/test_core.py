import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import tempfile
import unittest
from t3realms.config import Config, effective_home
from t3realms.lifecycle import OwnershipError


class ConfigTests(unittest.TestCase):
    def test_home_is_explicit_absolute_private_and_unredirected(self):
        with tempfile.TemporaryDirectory(prefix='t3r-', dir='/var/tmp') as tmp:
            home = Path(tmp)
            self.assertEqual(effective_home(home), home)
            for value in (None, 'relative', str(home / 'missing')):
                with self.subTest(value=value), self.assertRaises((ValueError, OwnershipError)):
                    effective_home(value)
            alias = home / 'alias'
            alias.symlink_to(home, target_is_directory=True)
            with self.assertRaises(OwnershipError):
                effective_home(alias)
            with patch('t3realms.config.os.getuid', return_value=os.getuid() + 1):
                with self.assertRaises(OwnershipError):
                    effective_home(home)
            home.chmod(0o755)
            with self.assertRaises(OwnershipError):
                effective_home(home)

    def test_home_resolves_symlinked_ancestors_but_refuses_final_redirect(self):
        with tempfile.TemporaryDirectory(prefix='t3r-home-', dir='/var/tmp') as tmp:
            root = Path(tmp)
            actual = root / 'actual'
            actual.mkdir(mode=0o700)
            home = actual / 'data'
            home.mkdir(mode=0o700)
            alias = root / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            self.assertEqual(effective_home(alias / 'data'), home)
            final = actual / 'redirect'
            final.symlink_to(home, target_is_directory=True)
            with self.assertRaises(OwnershipError):
                effective_home(alias / 'redirect')
            home.chmod(0o755)
            with self.assertRaises(OwnershipError):
                effective_home(alias / 'data')
            home.chmod(0o700)
            with patch('t3realms.config.os.getuid', return_value=os.getuid() + 1):
                with self.assertRaises(OwnershipError):
                    effective_home(alias / 'data')

    def test_config_rejects_invalid_values(self):
        self.assertEqual(Config.from_object({}).size, '1920x1080')
        for value in ({'vm': {'unknown': 1}}, {'size': '10x20'}, {'renderer': 'auto'},
                      {'idle_ttl': True}, {'idle_ttl': float('nan')},
                      {'idle_ttl': 0}, {'idle_ttl': 10 ** 400}, {'overlay': 1}, {'cursor_theme': ''},
                      {'cursor_theme': '\0'}, []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Config.from_object(value)

from unittest.mock import patch
import json
import subprocess
from t3realms.lifecycle import (Registry, atomic_json, identity, alive, validate_record,
                                validate_environment, validate_live, stop_scope, RealmError)
from t3realms.manager import Manager
from t3realms import workspace
from support import stopped_record, cli


class RegistryWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='t3r-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.record = stopped_record(self.home)
        self.registry = Registry(self.home)

    def test_atomic_publication_and_get(self):
        path = self.registry.path(self.record['id'])
        before = path.stat().st_ino
        self.registry.put(dict(self.record, last_activity=10))
        self.assertNotEqual(before, path.stat().st_ino)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.registry.get(self.record['id'])['last_activity'], 10)
        self.assertEqual(list(self.registry.root.glob('.write-*')), [])

    def test_registry_rejects_foreign_ownership(self):
        for changes in ({'uid': os.getuid() + 1}, {'home': str(self.home / 'other')},
                        {'id': 'r-' + 'f' * 24}):
            atomic_json(self.registry.path(self.record['id']), dict(self.record, **changes))
            with self.subTest(changes=changes), self.assertRaises(OwnershipError):
                self.registry.get(self.record['id'])

    def test_ids_are_confined(self):
        for value in ('../bad', 'r-123', 'hermes-realm-' + 'a' * 32, None, 10):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.registry.get(value)

    def test_registry_receipt_symlink_and_wrong_mode_refused(self):
        path = self.registry.path(self.record['id'])
        contents = path.read_bytes()
        path.unlink()
        target = self.home / 'redirect.json'
        target.write_bytes(contents)
        path.symlink_to(target)
        with self.assertRaises(OwnershipError):
            self.registry.get(self.record['id'])
        path.unlink()
        atomic_json(path, self.record)
        path.chmod(0o644)
        with self.assertRaises(OwnershipError):
            self.registry.get(self.record['id'])

    def test_runtime_names_cannot_alias_hermes(self):
        validate_record(self.record)
        for changes in ({'scope': 'hermes-realm-' + self.record['generation'] + '.scope'},
                        {'guardian_unit': 'hermes-realm-' + self.record['generation'] + '-guard.service'},
                        {'runtime_dir': self.record['runtime_dir'].replace('/t3r-', '/hr-')},
                        {'generation': '../../bad'}, {'workspace_dir': None}):
            with self.subTest(changes=changes), self.assertRaises(OwnershipError):
                validate_record(dict(self.record, **changes))

    def test_workspace_create_validate_and_finish_deletion(self):
        root = workspace.validate(self.record)
        (root / 'home' / 'saved.txt').write_text('retained')
        deleting = workspace.begin_deletion(self.record)
        workspace.validate_deletion(deleting)
        workspace.finish_deletion(deleting)
        self.assertFalse(root.exists())
        workspace.finish_deletion(deleting)

    def test_workspace_tamper_detection(self):
        root = workspace.validate(self.record)
        atomic_json(root / 'owner.json', dict(workspace.binding(self.record), session_id='other'))
        with self.assertRaises(OwnershipError):
            workspace.validate(self.record)

    def test_deletion_detects_replaced_inode(self):
        deleting = workspace.begin_deletion(self.record)
        root = Path(self.record['workspace_dir'])
        (root / 'home').rename(root / 'old-home')
        (root / 'home').mkdir(mode=0o700)
        with self.assertRaises(OwnershipError):
            workspace.finish_deletion(deleting)
        self.assertTrue((root / 'old-home').exists())

    def test_deletion_keeps_unknown_siblings(self):
        root = Path(self.record['workspace_dir'])
        (root / 'unknown').write_text('keep')
        deleting = workspace.begin_deletion(self.record)
        with self.assertRaises(OSError):
            workspace.finish_deletion(deleting)
        self.assertEqual((root / 'unknown').read_text(), 'keep')

    def test_delete_requires_owner_stopped_and_matching_snapshot(self):
        manager = Manager(self.home)
        rid = self.record['id']
        with patch('t3realms.manager.scope_info', return_value={'ActiveState': 'inactive'}):
            with self.assertRaises(OwnershipError):
                manager.delete_snapshot(rid, session_id='other')
            snapshot = manager.delete_snapshot(rid, session_id=self.record['session_id'])
            self.registry.put(self.record)
            with self.assertRaises(OwnershipError):
                manager.delete(rid, session_id=self.record['session_id'], token=snapshot['token'])
            self.assertTrue(Path(self.record['workspace_dir']).exists())
            with self.assertRaises(OwnershipError):
                manager.delete(rid, session_id='other', token=snapshot['token'])
            with self.assertRaises(ValueError):
                manager.delete(rid, session_id=self.record['session_id'])
            running = dict(self.record, status='running', vnc_socket=self.record['runtime_dir'] + '/wayvnc.sock', vnc_port=None)
            self.registry.put(running)
            with self.assertRaises(RealmError):
                manager.delete_snapshot(rid, session_id=self.record['session_id'])
            self.registry.put(self.record)
            snapshot = manager.delete_snapshot(rid, session_id=self.record['session_id'])
            self.assertTrue(manager.delete(rid, session_id=self.record['session_id'], token=snapshot['token']))
            self.assertFalse(Path(self.record['workspace_dir']).exists())

    def test_delete_token_survives_json_double_roundtrip_and_object_change_refuses(self):
        manager = Manager(self.home)
        rid, owner = self.record['id'], self.record['session_id']
        path = self.registry.path(rid)
        os.utime(path, ns=(1792763953872330539, 1792763953872330539))
        with patch('t3realms.manager.scope_info', return_value={'ActiveState': 'inactive'}):
            snapshot = manager.delete_snapshot(rid, session_id=owner)
            encoded = json.dumps(snapshot)
            # JSON numbers in a JS caller become IEEE-754 doubles; the token stays exact.
            confirmation = json.loads(encoded, parse_int=float)
            self.assertRegex(confirmation['token'], r'^[0-9a-f]{64}$')
            self.assertNotEqual(int(confirmation['publication'][2]), snapshot['publication'][2])
            home = Path(self.record['workspace_dir']) / 'home'
            home.rename(home.with_name('old-home'))
            home.mkdir(mode=0o700)
            with self.assertRaises(OwnershipError):
                manager.delete(rid, session_id=owner, token=confirmation['token'])
            self.assertTrue(home.is_dir())
            snapshot = manager.delete_snapshot(rid, session_id=owner)
            confirmation = json.loads(json.dumps(snapshot), parse_int=float)
            home.with_name('old-home').rmdir()
            self.assertTrue(manager.delete(rid, session_id=owner, token=confirmation['token']))

    def test_owner_checks_all_cli_realm_commands(self):
        for command in ('exec', 'job', 'signal', 'shot', 'resize', 'outputs', 'windows',
                        'touch', 'driver_launcher', 'vnc_endpoint', 'stop', 'delete_snapshot', 'delete'):
            response = cli(self.home, command, {'id': self.record['id'], 'owner': 'other'})
            self.assertEqual(response['code'], 'ownership', (command, response))

    def test_live_validation_rejects_wrong_systemd_description(self):
        with patch('t3realms.lifecycle.scope_info', return_value={'ActiveState': 'active',
                   'Description': 'Hermes realm ' + self.record['generation']}):
            with self.assertRaises(OwnershipError):
                validate_live(self.record)
            with self.assertRaises(OwnershipError):
                stop_scope(self.record)

    def test_environment_rejects_host_hints_before_socket_reads(self):
        runtime = self.record['runtime_dir']
        env = {'XDG_RUNTIME_DIR': runtime, 'HOME': self.record['workspace_dir'] + '/home',
               'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus',
               'XAUTHORITY': runtime + '/Xauthority', 'XDG_CURRENT_DESKTOP': 'labwc',
               'LABWC_UPDATE_ACTIVATION_ENV': 'false', 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon',
               'CUA_DRIVER_RS_ENABLE_WAYLAND': '1', 'GTK_USE_PORTAL': '0',
               'WAYLAND_DISPLAY': 'wayland-0', 'DISPLAY': ':22'}
        for key in ('HYPRLAND_INSTANCE_SIGNATURE', 'SSH_AUTH_SOCK', 'I3SOCK', 'WAYLAND_SOCKET'):
            with self.subTest(key=key), self.assertRaises(OwnershipError):
                validate_environment(self.record, dict(env, **{key: 'host'}))

    def test_pid_start_time_and_zombie_identity(self):
        process = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'], stdin=subprocess.PIPE)
        try:
            receipt = identity(process.pid)
            self.assertTrue(alive(receipt))
            self.assertFalse(alive(dict(receipt, start_time=receipt['start_time'] + 1)))
        finally:
            process.communicate(timeout=5)
        self.assertFalse(alive(receipt))

    def test_retained_list_and_stop_do_not_remove_workspace(self):
        response = cli(self.home, 'list', {'owner': self.record['session_id']})
        self.assertEqual(response['result'][0]['owner'], self.record['session_id'])
        self.assertTrue(cli(self.home, 'stop', {'id': self.record['id']})['result'])
        self.assertTrue(Path(self.record['workspace_dir']).exists())
