# Vendored Omarchy VM launcher

`omarchy-vm` originates from [omacom/omarchy PR #10977](https://github.com/omacom/omarchy/pull/10977),
`bin/omarchy-vm`, and was adapted by Hermes Realms at **da5cdd35339878f983fd11182eb1f0f3f8d63040**.
The upstream [MIT license](https://github.com/omacom/omarchy/blob/master/LICENSE) names David Heinemeier Hansson.
The T3 port owns its copy and has no runtime dependency on Hermes. MIT notices are in
[LICENSE](LICENSE) and the plugin's [NOTICE.md](../../../NOTICE.md).

- Upstream unpatched SHA-256: `19a51517c2713e033b2f703bfa387a79a9880c1c7a918e327e1327cfde47c3b6`.
- Hermes adapted SHA-256: `51a412e77243e8a7a24e1a3d316fc18160d233d64c6b2605f086b8611abeb015`.
- Executed T3 SHA-256: `c54300e17274fa9be1b166c3ef96400e82b87df7d82818bfe982363bb702b3d7` (`t3realms.vm_manager.VENDORED_SHA256`). The runtime verifies this
  in-code pin before **every** invocation and invokes the checked file through `/bin/bash`;
  immutable runtime snapshots intentionally store ordinary files as mode 0600.

The stock signed Omarchy release ISO installs the base. No custom OS image is built,
hosted, bundled or borrowed from Hermes. The signer is
`40DFB630FF42BCFFB047046CF0134EE680CAC571`; fresh and cached ISOs are signature-verified.

Inherited Hermes patches:

1. Per-session unit, QMP/VNC sockets, and a shared plugin-local ISO directory through
   `OMARCHY_VM_UNIT`, `OMARCHY_VM_QMP_SOCKET`, `OMARCHY_VM_VNC_SOCKET`, `OMARCHY_VM_ISO_DIR`.
2. Always headless: `-display none`, software framebuffer and VNC over a private Unix
   socket. No SDL window or TCP VNC listener on the physical desktop.
3. No implicit package installation: check `qemu-full edk2-ovmf mtools`; missing packages
   are reported to a person. T3 has no Polkit/package-install fallback.
4. Optional `OMARCHY_VM_NETDEV_EXTRA=,restrict=on` for restricted outbound networking.
5. Explicit existing SSH identity, ambient config disabled, agent/X11 forwarding off.
6. Literal stable `install --version X.Y.Z`, never a silent fallback to latest.
7. CIDATA FAT12 via mtools `mformat`/`mcopy`; stock installer kernel defaults remain intact
   (no forced `linux`/`linux-omarchy` override).

T3 local patches:

1. `OMARCHY_VM_CPUS` and `OMARCHY_VM_BOOT_TIMEOUT` honor reviewed resource settings.
2. Every QEMU unit has the exact `T3 Code VM <compute_generation>` description. A T3
   guardian is armed before QEMU via a generation-specific systemd drop-in. It survives
   short plugin calls, observes interrupted startup and idle expiry, and owns shell jobs.
3. Synchronous `launched`, `downloading`, `verifying`, `preparing` hooks use `-I -B` and
   the immutable T3 runtime. The launch hook publishes the observed systemd invocation
   before the script begins its SSH readiness wait. No stdout parsing invents progress.
4. A retained SSH host-key pin also applies to the vendor's boot-readiness probe, with
   StrictHostKeyChecking=yes, a generation-local known-hosts file and no global file.
   Bootstrap policy is used only for a new owned install/launch before enrollment.

Only `install --version ...` and `launch` are invoked by T3. The script's standalone
SSH/push/pull/remove/agent commands are not exposed. T3 uses its own pinned SSH,
conflict-safe archive transfer and typed workspace-deletion flows.

After changing this script, update `VENDORED_SHA256`, run the default tests, then seek
explicit approval for the gated native VM install/boot qualification. Never modify a live
base, ISO, Hermes runtime or existing workspace to qualify a change.
