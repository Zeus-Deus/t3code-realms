# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Per-conversation disposable Omarchy guests in QEMU/KVM.

A second realm kind beside :mod:`realms.manager`. Where a labwc realm separates
GUIs inside this login session, a VM realm is a separate machine: its own
kernel, disk and desktop. That is what makes `omarchy-shell` (one Hyprland and
one quickshell per session) hostable at all, and it is why breaking the guest
cannot break the host.

The guest itself is not ours. It is installed by Omarchy's own signed ISO
through the vendored ``omarchy vm`` script, and every session boots a
copy-on-write clone of one installed base image. Its overlay starts small and
grows with guest writes rather than downloading and installing another OS.

Isolation honesty, same as the labwc realm's: project files are *copied* in and
out, never mounted; the guest reaches the network through QEMU user-mode
networking unless ``plugins.realms.vm.network`` is false; the disk has no
encryption and passwordless sudo, so nothing secret may be put in it.
"""

from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from .config import Config, effective_home, vm_data_path, private_directory, validate_owner
from .vm_ssh import enroll_host_key, require_host_key, shutdown_guest, ssh_options
from .vm_setup import require_resources
from .lifecycle import (
    RealmError,
    OwnershipError,
    alive,
    identity,
    atomic_json,
    host_control_env,
    scope_info,
)


VENDORED_SCRIPT = Path(__file__).resolve().with_name("vendor") / "omarchy-vm"
# Upstream omacom/omarchy PR #10977 `bin/omarchy-vm` as vendored, before the
# local patches recorded in vendor/VENDOR.md. Checked on every launch so a
# tampered or silently upgraded copy cannot be executed.
UPSTREAM_SHA256 = "19a51517c2713e033b2f703bfa387a79a9880c1c7a918e327e1327cfde47c3b6"
# The vendored copy *with* those patches applied. Pinned in code rather than in
# a file beside the script: a checksum an attacker can rewrite pins nothing.
# Includes the synchronous installer-owned setup-stage hook.
VENDORED_SHA256 = "c54300e17274fa9be1b166c3ef96400e82b87df7d82818bfe982363bb702b3d7"

# Ports the per-session guests forward SSH on, loopback only. A realm picks the
# first free one and records it; a collision fails the launch rather than
# silently attaching to another guest.
SSH_PORT_RANGE = range(2300, 2400)

# Guest-bound environment. The host process environment holds this profile's
# API keys and desktop handles; forwarding it into a disposable guest with an
# unencrypted disk would put them on that disk. Only terminal presentation
# crosses the boundary.
FORWARDED_ENV = ("TERM", "LANG", "LC_ALL", "COLUMNS", "LINES")


class VmError(RealmError):
    pass


def _base_runtime(generation):
    return Path(f"/run/user/{os.getuid()}/t3vb-{generation[:16]}")  # windows-footgun: ok — runtime package rejects non-Linux hosts


def _generation_paths(uid, generation):
    return Path(f"/run/user/{uid}/t3v-{generation[:16]}")


class PruneError(VmError):
    """A prune that stopped part way; ``deleted`` lists the workspaces already gone."""

    def __init__(self, failed, deleted, cause):
        self.failed, self.deleted = failed, list(deleted)
        done = ("already deleted " + ", ".join(self.deleted)) if self.deleted else "nothing was deleted"
        super().__init__(f"Prune failed on {failed} ({cause}); {done}; "
                         "review again before retrying the rest")


class VmRegistry:
    """Crash-safe per-profile VM records, beside the labwc realm registry."""

    def __init__(self, home):
        self.root = private_directory(effective_home(home) / "realms")

    def lock(self, *, blocking=True):
        from .lifecycle import Registry
        return Registry(self.root.parent).lock(blocking=blocking)

    def path(self, vm_id):
        if not isinstance(vm_id, str) or not re.fullmatch(r"v-[0-9a-f]{24}", vm_id):
            raise VmError("invalid realm id")
        return self.root / (vm_id + ".json")

    def get(self, vm_id):
        try:
            from .lifecycle import private_json
            value = private_json(self.path(vm_id))
        except FileNotFoundError as exc:
            raise VmError("realm not found: " + vm_id) from exc
        if (
            value.get("id") != vm_id
            or value.get("uid") != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
            or value.get("home") != str(self.root.parent)
        ):
            raise OwnershipError("registry ownership mismatch")
        validate_vm_record(value)
        return value

    def put(self, record):
        if record.get("home") != str(self.root.parent):
            raise OwnershipError("VM registry home changed")
        validate_vm_record(record)
        atomic_json(self.path(record["id"]), record)

    def records(self):
        return [self.get(p.stem) for p in sorted(self.root.glob("v-*.json"))]

    def remove(self, vm_id):
        self.path(vm_id).unlink(missing_ok=True)


def validate_vm_record(record):
    """Every identity in the record must be derivable from its generation.

    A record is the only thing standing between ``stop`` and a systemd unit, so
    a record that names a unit, runtime directory or socket it could not have
    created is refused rather than acted on.
    """
    from .config import finite_number
    if not isinstance(record, dict): raise OwnershipError("Invalid VM record")
    incarnation = record.get('compute_generation')
    if (not isinstance(incarnation, str) or not re.fullmatch('[0-9a-f]{32}', incarnation)
            or record.get('kind') != 'omarchy-vm'
            or record.get('status') not in {'starting', 'running', 'stopping', 'stopped', 'recovery-required', 'deleting'}
            or type(record.get('ssh_port')) is not int or record['ssh_port'] not in SSH_PORT_RANGE
            or any(not finite_number(record.get(k)) for k in ('created_at', 'last_activity'))):
        raise OwnershipError('VM incarnation, kind, state or resource receipt changed')
    generation = record.get("generation", "")
    if (not isinstance(generation, str) or
        not re.fullmatch(r"[0-9a-f]{32}", generation)
        or record.get("id") != "v-" + generation[:24]
    ):
        raise OwnershipError("invalid realm generation")
    runtime = _generation_paths(os.getuid(), generation)  # windows-footgun: ok — runtime package rejects non-Linux hosts
    if (
        record.get("runtime_dir") != str(runtime)
        or record.get("unit") != f"t3code-vm-{generation}.service"
        or record.get("guardian_unit") != f"t3code-vm-{generation}-guard.service"
    ):
        raise OwnershipError("realm runtime or unit ownership mismatch")
    home = effective_home(record.get("home"))
    validate_owner(record.get("session_id"))
    from .runtime_store import runtime_reference
    if "runtime_copy" in record: runtime_reference(home, record["runtime_copy"])
    session = home / "realms" / "vm" / generation
    if (not home.is_absolute() or record.get("uid") != os.getuid()  # windows-footgun: ok — runtime package rejects non-Linux hosts
            or home.resolve() != home or record.get("session_dir") != str(session)
            or session.resolve() != session or session.is_symlink()):
        raise OwnershipError("realm profile or session ownership mismatch")
    if record.get("status") == "running" and record.get("vnc_socket") != str(
        runtime / "vnc.sock"
    ):
        raise OwnershipError("realm VNC endpoint identity changed")
    if runtime.is_symlink():
        raise OwnershipError("realm runtime is a symlink")
    if runtime.exists():
        info = runtime.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:  # windows-footgun: ok — runtime package rejects non-Linux hosts
            raise OwnershipError("realm runtime permissions changed")


def open_holders(record):
    """PIDs of this user's processes holding a file in the VM's directories.

    A second, process-level check that compute is gone, independent of systemd
    unit bookkeeping: a QEMU that escaped its unit still holds its disk open.
    Unreadable processes belong to other users and cannot hold these mode-0700
    directories' files through a path inside them.
    """
    paths = [Path(record[key]) for key in ("session_dir", "runtime_dir")]
    # Include the tombstone an interrupted removal leaves behind.
    roots = tuple(str(path) for directory in paths
                  for path in (directory, directory.with_name("." + directory.name + ".deleting")))
    holders = set()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            entries = list((proc / "fd").iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if any(target == root or target.startswith(root + "/") for root in roots):
                holders.add(int(proc.name))
                break
    return sorted(holders)


def unit_active(unit):
    # Failed observation is unknown, never permission to discard a live guest.
    return scope_info(unit).get("ActiveState") == "active"


class VmManager:
    KIND = "omarchy-vm"


    # --- vendored script ---



    def _run_script(self, arguments, *, vm_home, ssh_port=None, unit=None,
                    runtime=None, timeout=120, check=True, stdout=None, setup_job=None, before_start=None, config=None):
        script = self.script(config=config)
        if script == VENDORED_SCRIPT:
            import hashlib

            digest = hashlib.sha256(script.read_bytes()).hexdigest()
            if digest != VENDORED_SHA256:
                raise VmError("vendored omarchy-vm script does not match its pin")
        env = self._script_env(vm_home=vm_home, ssh_port=ssh_port, unit=unit, runtime=runtime, config=config)
        if before_start is not None:
            before_start()
        return subprocess.run(
            ["/bin/bash", str(script), *arguments],
            env=env,
            capture_output=stdout is None,
            stdout=stdout,
            stderr=subprocess.PIPE if stdout is not None else None,
            text=stdout is None,
            timeout=float(timeout),
            check=check,
        )

    # --- base image ---

    def base_home(self):
        from .vm_base import selected
        return selected(self.home)

    def base_status(self):
        from .setup_plan import base_present
        base = self.base_home()
        disk = base / "disk.qcow2"
        info = {"present": base_present(self.home, base=base), "path": str(disk)}
        if info["present"]:
            info["bytes"] = disk.stat().st_size
            info["built_at"] = disk.stat().st_mtime
            metadata = base / "base.json"
            if metadata.is_file():
                try:
                    info.update(json.loads(metadata.read_text(encoding="utf-8")))
                except ValueError:
                    pass
        return info



    def storage(self):
        def total(path):
            root = Path(path)
            if not root.exists():
                return 0
            return sum(
                f.stat().st_size for f in root.rglob("*") if f.is_file()
            )

        sessions = self.registry.root / "vm"
        return {
            "iso_bytes": total(self.data / "iso"),
            "base_bytes": total(self.data / "base") + total(self.data / "bases"),
            "session_bytes": total(sessions),
        }



    # --- lifecycle ---

    def list(self, owner=None):
        with self.registry.lock():
            self._reconcile_locked()
            self._expire_locked()
            return [dict(r, owner=r["session_id"]) for r in self.registry.records() if owner is None or r["session_id"] == owner]

    def _expire_locked(self, *, keep_session=None):
        """Reclaim unused stopped disks under the profile's current retention policy.

        This never retires compute. Failed observations preserve the workspace
        and do not prevent another conversation from starting. Only deletions
        begun by this policy may be retried without a fresh manual review.
        """
        import logging
        import math

        days = self.config.vm.workspace_retention_days
        if days == 0:
            return
        cutoff = time.time() - days * 86400
        for record in self.registry.records():
            if record.get("setup_base"):
                continue
            if record["session_id"] == keep_session or record.get("cleanup_required") is not False:
                continue
            status = record["status"]
            if status == "deleting":
                intent = record.get("deletion")
                if not isinstance(intent, dict) or intent.get("automatic") is not True:
                    continue
            elif status not in {"stopped", "recovery-required"}:
                continue
            stopped = record.get("stopped_at")
            last = record.get("last_activity", stopped)
            if any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not math.isfinite(value) or value <= 0 for value in (stopped, last)):
                continue
            if max(stopped, last) > cutoff:
                continue
            try:
                # Reuse the inactive-unit, open-file, ownership and tombstone
                # checks used by explicit prune; age alone authorizes nothing.
                self._delete_locked(record, discard=True, automatic=True)
            except (RealmError, OSError):
                logging.getLogger(__name__).warning(
                    "VM workspace expiry deferred for %s", record["id"], exc_info=True)
            else:
                logging.getLogger(__name__).info("Expired stopped VM workspace %s", record["id"])

    def _reconcile_locked(self):
        """Retire records whose guest is gone, and guests nobody is using.

        A VM realm costs its full ``-m`` figure in host RAM for as long as it
        runs — there is no balloon device and the guest touches all of it. A
        conversation that ends without finalizing would otherwise pin that
        memory until the user notices, so the labwc realm's ``idle_ttl`` governs
        this kind too. Reconciliation runs on every list/start, which is the
        same cadence the registry is read at.
        """
        idle_ttl = self.config.idle_ttl
        now = time.time()
        for record in self.registry.records():
            from .vm_lifetime import startup_abandoned
            if startup_abandoned(record):
                self._remove_locked(record)
                continue
            if record.get("setup_base") and record["status"] == "starting":
                continue
            if record["status"] == "stopped":
                from .vm_workspace import validate as validate_workspace
                try:
                    validate_workspace(record, allow_unlaunched=record.get("launch_pending") is True)
                except OwnershipError as exc:
                    record.update(status="recovery-required", recovery_reason=str(exc))
                    self.registry.put(record)
            elif (record["status"] == "recovery-required"
                  and record.get("cleanup_required") is False and "deletion" not in record):
                self._heal_locked(record)
            elif record["status"] == "running" and not unit_active(record["unit"]):
                self._remove_locked(record)
            elif record['status'] == 'running':
                try: self._validate_locked(record)
                except OwnershipError as exc:
                    record.update(status='recovery-required', cleanup_required=True, recovery_reason=str(exc))
                    self.registry.put(record)
                    continue
                if now - record['last_activity'] > idle_ttl: self._stop_locked(record)
            elif record["status"] == "starting":
                if time.time() - record.get("startup_at", record["created_at"]) < 35:
                    continue
                from .vm_lifetime import owner_unit
                if (scope_info(record["unit"])["ActiveState"] in {"inactive", "failed"}
                        and scope_info(owner_unit(record))["ActiveState"] in {"inactive", "failed"}):
                    self._remove_locked(record)
            elif record["status"] not in ("running", "starting", "stopped", "recovery-required", "deleting"):
                self._remove_locked(record)

    def _heal_locked(self, record):
        """Return a confirmed-retired workspace to Stopped once it verifies again.

        Recovery is a verdict on the current files, not a permanent mark: an
        earlier receipt check may have failed for a reason that no longer holds
        (receipts once recorded the boot-unstable device number). Only records
        whose retirement was confirmed are eligible, and the full stopped-state
        validation must pass with every compute unit inactive.
        """
        from .vm_workspace import validate as validate_workspace
        try:
            validate_workspace(record, allow_unlaunched=record.get("launch_pending") is True)
            if not self._compute_stopped(record):
                return
        except RealmError:
            return
        record["status"] = "stopped"
        record.pop("recovery_reason", None)
        self.registry.put(record)

    def _verifies_again(self, record):
        """Whether a recovery mark is stale: the files verify now. Read-only."""
        from .vm_workspace import validate as validate_workspace
        if (record["status"] != "recovery-required" or record.get("cleanup_required") is not False
                or "deletion" in record):
            return False
        try:
            validate_workspace(record, allow_unlaunched=record.get("launch_pending") is True)
        except RealmError:
            return False
        return True


    def _compute_stopped(self, record, units=None):
        units = self._compute_units(record) if units is None else units
        return all(info["ActiveState"] in {"inactive", "failed"} for info in units.values())


    def _retirement_failed(self, record):
        record.update(status="recovery-required", cleanup_required=True,
                      recovery_reason="Compute retirement was not confirmed; recover ownership and retry Stop")
        self.registry.put(record)



    def _free_port(self, taken):
        for port in SSH_PORT_RANGE:
            if port in taken:
                continue
            with socket.socket() as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError:
                    continue
            return port
        raise VmError("no free loopback SSH port for a VM realm")

    def _reserved_ports(self):
        # Retained data is not compute. Unknown/failed retirement still reserves
        # its endpoint even if a transient bind probe would succeed.
        return {r.get("ssh_port") for r in self.registry.records()
                if r.get("cleanup_required") is not False
                or r["status"] not in {"stopped", "recovery-required", "deleting"}}



    def _clone_base(self, session_dir, base_disk):
        """Copy-on-write overlay: share the base and store guest changes."""
        subprocess.run(
            [
                "qemu-img", "create", "-f", "qcow2",
                "-b", str(base_disk), "-F", "qcow2",
                str(session_dir / "disk.qcow2"),
            ],
            capture_output=True, text=True, timeout=60, check=True,
        )
        shutil.copyfile(
            base_disk.parent / "OVMF_VARS.4m.fd", session_dir / "OVMF_VARS.4m.fd"
        )
        for name in ("credentials", "cidata.img"):
            source = base_disk.parent / name
            if source.exists():
                shutil.copyfile(source, session_dir / name)
                os.chmod(session_dir / name, 0o600)
        from .vm_workspace import create
        record = self.registry.get("v-" + session_dir.name[:24])
        create(record)
        return record["workspace"]

    @staticmethod
    def _check_start(record, before_start):
        if before_start is not None:
            try:
                before_start(prepared=record)
            except BaseException:
                # No guest was started at these admission boundaries. Preserve
                # the cloned disk for a fresh operation, without inventing an SSH
                # pin or treating an interrupted actual boot as never launched.
                if not record.get("ssh_host_key_pinned"):
                    record["launch_pending"] = True
                raise




    def stop(self, vm_id, *, expected=None):
        with self.registry.lock():
            if not self.registry.path(vm_id).exists():
                return False
            record = self.registry.get(vm_id)
            validate_vm_record(record)
            if expected is not None and (any(record.get(key) != expected.get(key) for key in
                    ('id', 'session_id', 'generation', 'compute_generation'))
                    or record['status'] in {'stopped', 'deleting'}):
                return False
            if record["status"] == "deleting":
                raise VmError("VM deletion is in progress; retry explicit Delete")
            try:
                self._stop_locked(record)
            except BaseException:
                self._retirement_failed(record)
                raise
            return True



    def discard_snapshot(self, vm_id, *, session_id):
        """Read-only review for discarding a workspace that cannot be verified."""
        with self.registry.lock():
            record = self.registry.get(vm_id)
            if not session_id or record["session_id"] != session_id:
                raise OwnershipError("workspace belongs to another session")
            return self._discard_snapshot_locked(record)

    def _discard_snapshot_locked(self, record):
        """What an owner-confirmed discard would remove, if compute is provably gone.

        Unlike Delete this does not require the retained-file receipt to verify,
        because recovery-required data is exactly the data whose receipt does
        not. It still requires: a stopped or recovery-required record whose
        retirement was confirmed, every compute unit inactive, no process
        holding any file in the workspace or runtime directory, and a workspace
        directory of plain files owned by this user. The snapshot binds the
        exact directories and entries so any later change revokes consent.
        """
        from copy import deepcopy
        from .vm_workspace import begin_discard, validate_deletion, validate_discard

        validate_vm_record(record)
        if record["status"] not in {"stopped", "recovery-required", "deleting"}:
            raise VmError("VM is " + str(record["status"]) + "; compute is not stopped, so it is never discarded")
        if record.get("cleanup_required") is True:
            raise VmError("Compute retirement was not confirmed; run vm stop first")
        units = self._compute_units(record)
        if not self._compute_stopped(record, units):
            raise OwnershipError("VM compute is not stopped; deletion refused")
        holders = open_holders(record)
        if holders:
            raise OwnershipError("A running process still holds this VM workspace open (pid "
                                 + ", ".join(map(str, holders)) + "); deletion refused")
        candidate = deepcopy(record)
        if candidate["status"] == "deleting":
            if candidate.get("deletion", {}).get("discard") is True:
                validate_discard(candidate)
            else:
                validate_deletion(candidate)
        else:
            begin_discard(candidate)
        info = self.registry.path(record["id"]).stat()
        return {"record": record, "deletion": candidate["deletion"], "compute": units,
                "holders": holders,
                "publication": [info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns]}

    def prune_snapshot(self, *, everything=False, older_than=None, ids=None, keep=(),
                       recovery_only=False, now=None):
        """Read-only review of every workspace a bulk discard would remove.

        Never reconciles, stops or starts anything: running and starting VMs
        are reported as kept without being touched. Select with ``everything``,
        ``older_than`` (seconds since last use or stop) or exact ``ids``;
        ``keep`` IDs are always excluded. ``recovery_only`` narrows any
        selection to workspaces that cannot be resumed: recovery-required ones
        and interrupted deletions. Healthy stopped workspaces, and recovery
        marks whose files verify again (which ``list`` heals), are then kept.
        """
        if not everything and older_than is None and not ids:
            raise ValueError("Select workspaces explicitly: all, an age, or exact IDs")
        now = time.time() if now is None else now
        selected = None if not ids else set(ids)
        keep = set(keep)
        with self.registry.lock():
            delete, kept = {}, []
            records = self.registry.records()
            known = {r["id"] for r in records}
            for vm_id in sorted(((selected or set()) | keep) - known):
                kept.append({"id": vm_id, "status": "missing", "reason": "No such VM in this profile"})
            for record in records:
                if selected is not None and record["id"] not in selected:
                    continue
                last = max(record.get("last_activity") or 0, record.get("stopped_at") or 0)
                row = {"id": record["id"], "status": record["status"],
                       "session_id": record["session_id"],
                       "idle_seconds": int(now - last) if last else None}
                if record["id"] in keep:
                    kept.append(dict(row, reason="Explicitly kept"))
                    continue
                if recovery_only and record["status"] not in {"recovery-required", "deleting"}:
                    kept.append(dict(row, reason="VM is " + str(record["status"]) + ", not recovery-required"))
                    continue
                if recovery_only and self._verifies_again(record):
                    kept.append(dict(row, reason="Workspace verifies again; list returns it to stopped"))
                    continue
                if older_than is not None and (not last or now - last < older_than):
                    kept.append(dict(row, reason="Used more recently than the requested age"))
                    continue
                try:
                    delete[record["id"]] = self._discard_snapshot_locked(record)
                except RealmError as exc:
                    kept.append(dict(row, reason=str(exc)))
            return {"delete": delete, "kept": kept}

    def prune(self, expected):
        """Discard exactly the reviewed set, or nothing if any target changed."""
        with self.registry.lock():
            targets = []
            for vm_id, snapshot in sorted(expected["delete"].items()):
                if not self.registry.path(vm_id).exists():
                    raise OwnershipError("Prune target disappeared; review again: " + vm_id)
                record = self.registry.get(vm_id)
                if self._discard_snapshot_locked(record) != snapshot:
                    raise OwnershipError("Prune target changed since review; review again: " + vm_id)
                targets.append(record)
            deleted = []
            for record in targets:
                try:
                    self._delete_locked(record, discard=True)
                except (RealmError, OSError) as exc:
                    raise PruneError(record["id"], deleted, exc) from exc
                deleted.append(record["id"])
            return deleted


    def _delete_locked(self, record, *, discard=False, automatic=False):
        """Remove one record's workspace. Caller holds the lock and has authorized it."""
        from .vm_lifetime import owner_unit, remove_dropin
        from .vm_workspace import begin_deletion, remove_directory, validate_deletion

        if discard:
            # Revalidates an interrupted deletion too, never trusting its status.
            intent = self._discard_snapshot_locked(record)["deletion"]
            if record["status"] != "deleting":
                record["deletion"] = intent
        elif record["status"] == "stopped":
            begin_deletion(record)
        elif record["status"] == "deleting" and record.get("deletion", {}).get("discard") is not True:
            validate_deletion(record)
        else:
            raise VmError("Only a verified stopped VM workspace can be deleted; "
                          "use --discard for a recovery-required one")
        if automatic:
            record["deletion"]["automatic"] = True
        for unit in (record["unit"], owner_unit(record), record["guardian_unit"]):
            if scope_info(unit)["ActiveState"] not in {"inactive", "failed"}:
                raise OwnershipError("VM compute is not stopped; deletion refused")
        remove_dropin(record)
        # Publish authorization before deleting any receipt it depends on.
        record["status"] = "deleting"
        self.registry.put(record)
        for key in ("runtime_dir", "session_dir"):
            remove_directory(Path(record[key]), record["deletion"]["directories"][key])
        self.registry.remove(record["id"])

    # --- routing surface (mirrors Manager) ---




    def guest_home(self, vm_id):
        """The guest desktop user's home, read from the guest itself.

        Where a routed session starts. Asking the guest beats assuming a path:
        the user name comes from the host at install time, so it is not a
        constant we get to hardcode.
        """
        result = self.guest_run(
            vm_id, ["sh", "-c", "getent passwd 1000 | cut -d: -f6"], timeout=30)
        home = result["stdout"].strip()
        if result["returncode"] != 0 or not home.startswith("/"):
            raise VmError("could not resolve the guest user's home directory")
        return home

    def ssh_argv(self, record, *, user="root", tty=False):
        """SSH into this realm's guest, with the host's ssh config overridden.

        Every forwarding option is pinned OFF rather than left to defaults.
        ``ssh`` merges ``~/.ssh/config``, and a ``Host *`` block with
        ``ForwardAgent yes`` is a common setup: it would hand the user's
        private-key agent to a disposable guest that has passwordless sudo and
        no disk encryption, so anything running in there could authenticate as
        them. ``ForwardX11 yes`` is the same hazard pointed the other way — a
        route from the guest back to the host's display. Agent forwarding is a
        per-command, user-approved opt-in, never an ambient default.
        ``IdentitiesOnly`` keeps ssh from offering unrelated host keys.
        """
        return [
            "ssh", "-p", str(record["ssh_port"]),
            *(["-tt"] if tty else ["-T"]),
            *ssh_options(record),
            f"{user}@127.0.0.1",
        ]

    def guest_run(self, vm_id, command, *, timeout=60, user="root"):
        """One captured command in the guest, as an argv list."""
        record = self.validate(vm_id)
        if (
            not isinstance(command, (list, tuple))
            or not command
            or not all(isinstance(a, str) and "\0" not in a for a in command)
        ):
            raise ValueError("command must be a nonempty argv list")
        result = subprocess.run(
            [*self.ssh_argv(record, user=user), "--", shlex.join(command)],
            capture_output=True, text=True, timeout=timeout,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }


    def guest_user(self, vm_id):
        """Resolve the desktop account rather than uploading root-owned work."""
        result = self.guest_run(vm_id, ["id", "-nu", "1000"], timeout=30)
        user = result["stdout"].strip()
        if result["returncode"] != 0 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*\$?", user):
            raise VmError("could not resolve the guest desktop account")
        return user

    def push(self, vm_id, source, destination=None):
        """Copy a host path into the guest. Copies, never mounts."""
        from .vm_transfer import push
        return push(self, vm_id, source, destination)

    def pull(self, vm_id, source, destination):
        """Copy a guest path out. Only on an explicit request."""
        from .vm_transfer import pull
        return pull(self, vm_id, source, destination)

    def stats(self, vm_id):
        """What the guest costs, read from its own cgroup and disk."""
        record = self.registry.get(vm_id)
        cgroup = Path("/sys/fs/cgroup") / record.get("cgroup", "").lstrip("/")
        result: dict[str, int | None] = {
            "memory_bytes": None, "cpu_usec": None, "disk_bytes": None}
        try:
            result["memory_bytes"] = int(
                (cgroup / "memory.current").read_text(encoding="utf-8").strip()
            )
        except (OSError, ValueError):
            pass
        try:
            for line in (cgroup / "cpu.stat").read_text(encoding="utf-8").splitlines():
                if line.startswith("usage_usec "):
                    result["cpu_usec"] = int(line.split()[1])
        except (OSError, ValueError):
            pass
        try:
            result["disk_bytes"] = (
                Path(record["session_dir"]) / "disk.qcow2"
            ).stat().st_size
        except OSError:
            pass
        return result



    def __init__(self, home, *, config=None, vm_id=None):
        self.home = effective_home(home)
        self.registry = VmRegistry(self.home)
        self.data = vm_data_path(self.home)
        self.config = Config.from_object(config or {})
        self.operation = None
        self.setup_job = None
        if vm_id is not None:
            from .lifecycle import private_json
            self.config = Config.from_object(private_json(Path(self.record(vm_id)['session_dir']) / 'spec.json'))

    def record(self, vm_id, *, owner=None):
        with self.registry.lock():
            record = self.registry.get(vm_id)
            if owner is not None and record['session_id'] != owner:
                raise OwnershipError('VM belongs to another owner')
            return record

    def script(self, *, config=None):
        return VENDORED_SCRIPT

    def _script_env(self, *, vm_home, ssh_port=None, unit=None, runtime=None, config=None):
        config = config or self.config
        env = dict(host_control_env(), USER=Path.home().name,
                   OMARCHY_VM_HOME=str(vm_home), OMARCHY_VM_ISO_DIR=str(self.data / 'iso'),
                   OMARCHY_VM_MEMORY=str(config.vm.memory), OMARCHY_VM_CPUS=str(config.vm.cpus),
                   OMARCHY_VM_DISK_SIZE=config.vm.disk_size,
                   OMARCHY_VM_BOOT_TIMEOUT=str(config.vm.boot_timeout))
        if ssh_port is not None: env['OMARCHY_VM_SSH_PORT'] = str(ssh_port)
        if unit is not None: env['OMARCHY_VM_UNIT'] = unit.removesuffix('.service')
        if runtime is not None:
            env['OMARCHY_VM_VNC_SOCKET'] = str(runtime / 'vnc.sock')
            env['OMARCHY_VM_QMP_SOCKET'] = str(runtime / 'qmp.sock')
            if (runtime / 'ssh_known_hosts').exists():
                env['OMARCHY_VM_KNOWN_HOSTS'] = str(runtime / 'ssh_known_hosts')
        if not config.vm.network: env['OMARCHY_VM_NETDEV_EXTRA'] = ',restrict=on'
        if self.operation is not None:
            env['OMARCHY_VM_PROGRESS_PYTHON'] = sys.executable
            env['OMARCHY_VM_COMPUTE_GENERATION'] = self.operation['compute_generation']
            env['OMARCHY_VM_T3_HOOK'] = json.dumps([
                str(Path(__file__).with_name('vm_progress.py')), str(self.home),
                self.operation['id'], self.operation['compute_generation'], self.setup_job])
        return env

    def start(self, session_id, *, before_start=None):
        from .runtime_store import pinned_runtime
        from .vm_workspace import validate as validate_workspace, restore_pin
        from .vm_lifetime import install
        validate_owner(session_id)
        # Pin publication must precede the registry lock, as for regular Realms.
        with pinned_runtime(self.home) as runtime_copy:
            with self.registry.lock():
                self._reconcile_locked()
                self._expire_locked(keep_session=session_id)
                existing = [r for r in self.registry.records() if r['session_id'] == session_id]
                if existing:
                    record = existing[0]
                    if record['status'] == 'running':
                        return self._validate_locked(record, renew=True)
                    if record['status'] != 'stopped':
                        raise VmError('Retained VM workspace needs recovery; refusing a replacement')
                    frozen = validate_workspace(record, allow_unlaunched=record.get('launch_pending') is True)
                    if not self._compute_stopped(record):
                        raise VmError('VM compute is still stopping')
                    require_resources(frozen, Path(record['session_dir']))
                    runtime = Path(record['runtime_dir'])
                    if runtime.exists(): shutil.rmtree(runtime)
                    runtime.mkdir(mode=0o700)
                    if not record.get('launch_pending'): restore_pin(record)
                    for key in ('invocation_id', 'owner_invocation_id', 'guardian_invocation_id', 'cgroup', 'supervisor'):
                        record.pop(key, None)
                    record.update(compute_generation=uuid.uuid4().hex, ssh_port=self._free_port(self._reserved_ports()))
                else:
                    frozen = self.config
                    if not self.base_status()['present']:
                        raise VmError('Omarchy base image is missing. A person must review and approve VM setup in T3 Code.')
                    registered = {r['session_dir'] for r in self.registry.records()}
                    from .vm_workspace import _tombstone, validate_deletion, validate_discard
                    for retained in self.registry.records():
                        if retained['status'] != 'deleting':
                            continue
                        try:
                            if retained.get('deletion', {}).get('discard'):
                                validate_discard(retained)
                            else:
                                validate_deletion(retained)
                        except (OwnershipError, OSError):
                            continue
                        registered.add(str(_tombstone(Path(retained['session_dir']))))
                    if any(str(p) not in registered for p in (self.registry.root / 'vm').glob('*')):
                        raise OwnershipError('Unregistered VM workspace needs explicit recovery; refusing fresh allocation')
                    require_resources(frozen, self.data)
                    port = self._free_port(self._reserved_ports())
                    generation = uuid.uuid4().hex
                    runtime = _generation_paths(os.getuid(), generation)
                    runtime.mkdir(mode=0o700)
                    private_directory(self.registry.root / 'vm')
                    session = self.registry.root / 'vm' / generation
                    session.mkdir(mode=0o700)
                    record = {'id': 'v-' + generation[:24], 'session_id': session_id, 'kind': self.KIND,
                              'generation': generation, 'compute_generation': uuid.uuid4().hex,
                              'uid': os.getuid(), 'home': str(self.home), 'runtime_dir': str(runtime),
                              'session_dir': str(session), 'unit': f't3code-vm-{generation}.service',
                              'guardian_unit': f't3code-vm-{generation}-guard.service',
                              'status': 'starting', 'created_at': time.time(), 'last_activity': time.time(),
                              'ssh_port': port, 'memory': frozen.vm.memory,
                              'network': frozen.vm.network, 'base_disk': str(self.base_home() / 'disk.qcow2'),
                              'launch_pending': True}
                    self.registry.put(record)
                    try:
                        atomic_json(session / 'spec.json', asdict(frozen))
                        record['workspace'] = self._clone_base(session, Path(record['base_disk']))
                    except BaseException:
                        record.update(status='recovery-required', cleanup_required=False, stopped_at=time.time(),
                                      recovery_reason='Overlay preparation interrupted; review Discard before retrying')
                        self.registry.put(record)
                        raise
                record.update(status='starting', cleanup_required=True, runtime_copy=str(runtime_copy),
                              python_executable=sys.executable, idle_ttl=self.config.idle_ttl,
                              size=frozen.size, last_activity=time.time(), startup_at=time.time(), startup_process=identity(os.getpid()))
                self.registry.put(record)
                atomic_json(runtime / 'vm.json', record)
            # Release the publication and registry locks before systemd and SSH waits.
        self.operation = record
        try:
            if before_start is not None: before_start(prepared=record)
            install(record)
            with self.registry.lock():
                current = self._starting(record)
                from .vm_lifetime import owner_unit
                info = scope_info(owner_unit(record))
                current.update(owner_invocation_id=info['InvocationID'], supervisor=record.get('supervisor'))
                self.registry.put(current)
            self._run_script(['launch'], vm_home=record['session_dir'], ssh_port=record['ssh_port'],
                             unit=record['unit'], runtime=runtime, config=frozen,
                             timeout=frozen.vm.boot_timeout + 30)
            with self.registry.lock(): record = self._starting(record)
            enroll_host_key(record)
            record = self._retain_startup_pin(record)
            self._wait_for_desktop(record, frozen)
            # Socket ownership is checked again for every takeover route.
            os.chmod(runtime / 'vnc.sock', 0o600)
            with self.registry.lock():
                current = self._starting(record)
                current.update(workspace=record['workspace'], status='running', ssh_host_key_pinned=True,
                               vnc_socket=str(runtime / 'vnc.sock'), qmp_socket=str(runtime / 'qmp.sock'),
                               last_activity=time.time())
                current.pop('launch_pending', None)
                self.registry.put(current)
                return current
        except BaseException:
            self.stop(record['id'], expected=record)
            raise
        finally:
            self.operation = None

    def _starting(self, expected):
        current = self.registry.get(expected['id'])
        if (current['compute_generation'] != expected['compute_generation']
                or current['session_id'] != expected['session_id'] or current['status'] != 'starting'):
            raise OwnershipError('VM startup cancelled or incarnation changed')
        return current

    def _retain_startup_pin(self, expected):
        from .vm_workspace import _file, retain_pin, validate as validate_workspace
        import hashlib
        with self.registry.lock():
            record = self._starting(expected)
            if not record['workspace'].get('pin'):
                validate_workspace(record, allow_unlaunched=True)
                source = require_host_key(record)
                pin = _file(source)
                contents = source.read_bytes()
                if hashlib.sha256(contents).hexdigest() != pin['sha256']:
                    raise OwnershipError('VM enrolled SSH pin changed during retention')
                destination = Path(record['session_dir']) / 'ssh_known_hosts'
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    # Bind the destination before writing, so an abrupt exit
                    # after fsync can recover this exact inode and enrolled key.
                    record['pin_enrollment'] = {'inode': os.fstat(stream.fileno()).st_ino, 'sha256': pin['sha256']}
                    self.registry.put(record)
                    stream.write(contents)
                    stream.flush()
                    os.fsync(stream.fileno())
            else:
                validate_workspace(record)
            retain_pin(record)
            self._recover_pin_locked(record)
            record['ssh_host_key_pinned'] = True
            record.pop('launch_pending', None)
            self.registry.put(record)
            return record

    def _recover_pin_locked(self, record):
        intent = record.get('pin_enrollment')
        if intent is None:
            return
        from .vm_workspace import _file, validate as validate_workspace
        path = Path(record['session_dir']) / 'ssh_known_hosts'
        pin = _file(path)
        if (not isinstance(intent, dict) or intent != {key: pin[key] for key in ('inode', 'sha256')}
                or path.stat().st_mode & 0o777 != 0o600):
            raise OwnershipError('VM retained SSH pin differs from its enrolled identity')
        record['workspace']['pin'] = pin
        record['ssh_host_key_pinned'] = True
        record.pop('launch_pending', None)
        validate_workspace(record)
        with path.open('rb') as stream:
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        record.pop('pin_enrollment')

    def _compute_units(self, record):
        from .vm_lifetime import owner_unit
        return {unit: scope_info(unit) for unit in (record['unit'], owner_unit(record), record['guardian_unit'])}

    def _validate_locked(self, record, *, renew=False):
        from .vm_lifetime import validate_owner
        from .lifecycle import NotRunningError
        if record['status'] != 'running': raise NotRunningError('VM is not running')
        info = scope_info(record['unit'])
        if (info['ActiveState'] != 'active' or info.get('InvocationID') != record.get('invocation_id')
                or info.get('ControlGroup') != record.get('cgroup')):
            raise OwnershipError('VM unit is not the owned live invocation')
        validate_owner(record)
        require_host_key(record)
        if renew:
            record['last_activity'] = time.time(); self.registry.put(record)
        return record

    def validate(self, vm_id, *, renew=False):
        with self.registry.lock(): return self._validate_locked(self.registry.get(vm_id), renew=renew)

    def touch(self, vm_id):
        return self.validate(vm_id, renew=True)

    def _stop_locked(self, record):
        # A quick best-effort guest poweroff precedes forced systemd retirement;
        # the latter still checks the owned invocation and bounds shutdown.
        if record['status'] == 'running':
            try:
                self._validate_locked(record)
                subprocess.run([*self.ssh_argv(record), '--', 'poweroff'], env=host_control_env(),
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=2)
            except (OwnershipError, OSError, subprocess.SubprocessError): pass
        self._remove_locked(record)

    def _remove_locked(self, record):
        from .vm_lifetime import retire, remove_dropin
        from .vm_workspace import validate as validate_workspace
        validate_vm_record(record)
        try:
            retire(record); remove_dropin(record)
        except BaseException:
            self._retirement_failed(record); raise
        record.update(status='stopped', stopped_at=time.time(), cleanup_required=False)
        record.pop('recovery_reason', None)
        try:
            self._recover_pin_locked(record)
            validate_workspace(record, allow_unlaunched=record.get('launch_pending') is True)
        except (OwnershipError, OSError) as exc:
            record.update(status='recovery-required', recovery_reason=str(exc))
        self.registry.put(record)

    def stop_owner(self, owner):
        validate_owner(owner)
        for record in self.registry.records():
            if record['session_id'] == owner: self.stop(record['id'])
        return True

    def delete_snapshot(self, vm_id, *, session_id, discard=False):
        with self.registry.lock():
            record = self.registry.get(vm_id)
            if record['session_id'] != session_id: raise OwnershipError('VM belongs to another owner')
            snapshot = self._discard_snapshot_locked(record) if discard else self._delete_snapshot_locked(record)
            from .manager import Manager
            return dict(snapshot, token=Manager._delete_token(snapshot))

    def _delete_snapshot_locked(self, record):
        from copy import deepcopy
        from .vm_workspace import begin_deletion, validate_deletion
        if record['status'] not in {'stopped', 'deleting'}:
            raise VmError('Only stopped VM workspaces can be deleted; explicitly review Discard for needs recovery')
        units = self._compute_units(record)
        if not self._compute_stopped(record, units) or open_holders(record):
            raise OwnershipError('VM compute or an open workspace is not stopped; deletion refused')
        candidate = deepcopy(record)
        if candidate['status'] == 'deleting': validate_deletion(candidate)
        else: begin_deletion(candidate)
        info = self.registry.path(record['id']).stat()
        return {'record': record, 'deletion': candidate['deletion'], 'compute': units,
                'publication': [info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns]}

    def delete(self, vm_id, *, session_id, token, discard=False):
        import hmac
        from .manager import Manager
        with self.registry.lock():
            record = self.registry.get(vm_id)
            if record['session_id'] != session_id: raise OwnershipError('VM belongs to another owner')
            if not isinstance(token, str) or not re.fullmatch('[0-9a-f]{64}', token):
                raise ValueError('a delete confirmation token is required')
            snapshot = self._discard_snapshot_locked(record) if discard else self._delete_snapshot_locked(record)
            if not hmac.compare_digest(Manager._delete_token(snapshot), token):
                raise OwnershipError('Delete confirmation target changed; review again')
            self._delete_locked(record, discard=discard)
            return True

    def _rpc(self, vm_id, **request):
        import struct
        from .lifecycle import identity, RPC_RESPONSE_LIMIT_BYTES, private_json
        record = self.validate(vm_id, renew=True)
        endpoint = Path(record['runtime_dir']) / 'control'
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(10); connection.connect(str(endpoint))
            pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid() or identity(pid) != private_json(Path(record['runtime_dir']) / 'supervisor.json'):
                raise OwnershipError('VM command endpoint was replaced')
            request['client_process'] = identity(os.getpid())
            connection.sendall(json.dumps(request).encode() + b'\n')
            with connection.makefile('rb') as stream: response = json.loads(stream.readline(RPC_RESPONSE_LIMIT_BYTES))
        if 'error' in response:
            from .errors import coded_error
            raise coded_error(response.get('code', 'failed'), response['error'])
        return response['result']

    def exec(self, vm_id, command, *, cwd=None):
        if (not isinstance(command, (list, tuple)) or not command
                or any(not isinstance(arg, str) or '\0' in arg for arg in command)):
            raise ValueError('command must be a nonempty argv list')
        if cwd is not None and (not isinstance(cwd, str) or not Path(cwd).is_absolute() or '\0' in cwd):
            raise ValueError('cwd must be an absolute guest path')
        return self._rpc(vm_id, op='exec', command=list(command), cwd=cwd)

    def job(self, vm_id, job_id):
        return self._rpc(vm_id, op='job', job_id=job_id)

    def signal(self, vm_id, job_id, number):
        from .errors import signal_number
        return self._rpc(vm_id, op='signal', job_id=job_id, signal=signal_number(number))

    def windows(self, vm_id):
        self.validate(vm_id)
        # No SSH probe on every status poll. CUA provides the guest's app inventory.
        return {'count': None}

    def resize(self, vm_id, size):
        from .config import parse_size
        from .vm_launch import guest_script
        parse_size(size)
        record = self.validate(vm_id, renew=True)
        self._desktop_resize(record, size)
        with self.registry.lock():
            current = self.registry.get(vm_id)
            if current['compute_generation'] != record['compute_generation']: raise OwnershipError('VM restarted during resize')
            current['size'] = size; self.registry.put(current); return current

    def _desktop_resize(self, record, size):
        from .vm_launch import guest_script
        def run(command):
            return subprocess.run([*self.ssh_argv(record), '--', guest_script(command, '/')],
                                  env=host_control_env(), capture_output=True, text=True, timeout=5, check=True)
        monitors = json.loads(run(['hyprctl', '-j', 'monitors']).stdout)
        if (not isinstance(monitors, list) or not monitors or not isinstance(monitors[0], dict)
                or not isinstance(monitors[0].get('name'), str)
                or not re.fullmatch('[A-Za-z0-9_.:-]{1,100}', monitors[0]['name'])):
            raise VmError('Guest desktop has no usable monitor')
        result = run(['hyprctl', 'keyword', 'monitor', monitors[0]['name'] + ',' + size + '@60,auto,1'])
        if "keyword can't work with non-legacy parsers" in result.stdout:
            # Lua Hyprland returns exit 0 for rejected legacy keywords.
            result = run(['hyprctl', 'eval', 'hl.monitor({ output = ' + json.dumps(monitors[0]['name'])
                          + ', mode = ' + json.dumps(size) + ', position = "auto", scale = 1 })'])
        if result.stdout.strip() != 'ok':
            raise VmError('Guest monitor resize was not applied: ' + result.stdout.strip()[:400])

    def _wait_for_desktop(self, record, config):
        deadline = time.monotonic() + config.vm.boot_timeout
        while True:
            with self.registry.lock(): self._starting(record)
            try:
                self._desktop_resize(record, config.size)
                return
            except (OSError, ValueError, VmError, subprocess.SubprocessError) as exc:
                if time.monotonic() >= deadline:
                    raise VmError('Guest Hyprland desktop did not become ready before its boot deadline') from exc
            time.sleep(.5)

    def outputs(self, vm_id):
        return self.guest_run(vm_id, ['hyprctl', '-j', 'monitors'], timeout=10)

    def shot(self, vm_id, *, format='png', quality=None, scale=1):
        import hashlib
        from .capture import capture_options, asset_path, dimensions
        from .vm_launch import guest_shell_init
        options = capture_options(format, quality, scale)
        record = self.validate(vm_id, renew=True)
        target = asset_path(self.home, 'assets/shot-' + uuid.uuid4().hex + ('.png' if format == 'png' else '.jpg'))
        command = ['grim', '-t', options['format'], '-s', str(scale)]
        if quality is not None: command += ['-q', str(quality)]
        command.append('-')
        script = 'runuser -u "$(id -nu 1000)" -- bash -c ' + shlex.quote(guest_shell_init() + 'exec ' + shlex.join(command))
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            # run_stream bounds pixels on disk before the 4 MiB host image limit.
            from .vm_transfer import run_stream
            from .vm_transfer_archive import LimitedWriter
            with os.fdopen(fd, 'wb') as sink:
                run_stream([*self.ssh_argv(record), '--', script], output_file=LimitedWriter(sink, 4 * 1024 * 1024), timeout=10)
            data = target.read_bytes(); width, height = dimensions(data, format)
            self.validate(vm_id)
            return {'path': str(target.relative_to(self.home)), 'mimeType': 'image/png' if format == 'png' else 'image/jpeg',
                    'width': width, 'height': height, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        except BaseException:
            target.unlink(missing_ok=True); raise

    def vnc_endpoint(self, vm_id, *, owner=None):
        self.record(vm_id, owner=owner)
        record = self.validate(vm_id)
        from .lifecycle import validate_sockets
        path = Path(record['runtime_dir']) / 'vnc.sock'
        validate_sockets(record, [path], mode=0o600)
        return {'path': str(path)}

    def doctor(self, vm_id=None):
        from .vm_setup import doctor
        return doctor(self.home, self.config)

    def install_base(self, *, progress=None, job_id=None):
        from .vm_setup import install_base
        return install_base(self, progress=progress, job_id=job_id)


def _installed_iso(iso_dir):
    isos = sorted(Path(iso_dir).glob("omarchy-*.iso"))
    return isos[-1].name if isos else None


def _iso_version(name):
    """``omarchy-4.0.3.iso`` -> ``4.0.3``; None when there is no ISO recorded."""
    if not isinstance(name, str):
        return None
    match = re.fullmatch(r"omarchy-(.+)\.iso", name)
    return match.group(1) if match else None


def _reason(exc):
    output = getattr(exc, "stderr", None) or getattr(exc, "stdout", None) or ""
    return (output.strip().splitlines() or [str(exc)])[-1][:400]
