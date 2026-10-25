# Realms in detail

The [README](../README.md) covers what most people need. This page is the reference for
setup, the panel, the Omarchy VM, sharing between agents and recovery.

## Install and setup

Setup checks the packages listed in the README. When you approve, it downloads the pinned
cua-driver 0.23.2 release from GitHub, verifies its checksums and installs it into the
plugin's own data directory. On Arch Linux (`ID=arch`) hosts with `pacman` and `pkexec`,
your approval can also request native Polkit authorization for the exact packages and
command shown in the review. Other distributions, or a missing `pkexec`, remain explicit
blockers. Realms never changes host SSH keys or KVM permissions.

Setup reviews include exact missing prerequisites, installable Arch packages, the full
command and explicit blockers. The approved command uses `pkexec` and a root-side
30-minute timeout around `pacman -S --needed --noconfirm -- <packages>`. The review ID
binds those arguments and the driver/VM plan; a changed plan requires a fresh review.
Progress reports the package stage while native Polkit prompts on the server machine.
Cancellation prevents subsequent phases but lets an elevated package transaction finish
safely before reporting cancellation. Completed packages and verified downloads remain.

When an agent hits `setup_required`, Realms remembers its owner, requesting thread, kind
and time, never its command. A person-approved setup job attaches that pending request.
A client setup-job poll or thread-status poll that observes successful setup sends one
short prompt to that same requesting thread. The agent must reevaluate the current task
and authorization. Manual setup without a pending request creates no turn. If prerequisites
were completed outside the plugin, approving the now-ready review can also confirm success.

Requests expire after one hour. Off, switching kind, human takeover, failed/cancelled or
interrupted setup invalidate the continuation. Missing project permission for `threads.send`
or an uncertain send leaves setup successful without an automatic retry. Setup/status results
show whether manual continuation is needed and identify the requesting thread; ask that agent
to continue manually. Expired requests also need a manual instruction. Delivery is recorded before sending, so an interrupted worker does
not replay an ambiguous attempt. Subagents share one pending request per owner and kind;
the first requesting thread receives that prompt. The backend does not check conversation
idleness; the T3 host decides whether to queue the message or refuse it.

## The Realm panel

- **Agent can use it** off stops the agent using the Realm. The desktop, its workspace and
  your view stay. The agent cannot turn it back on; you can.
- **Stop** ends the desktop and keeps its workspace. Save app work first.
- **Watch** shows periodic captures of the desktop (about one or two per second while the
  panel is visible). It is view-only. Pause it with the button on the screen.
- **Take control** lets you use the pointer and keyboard in the Realm. The agent's input and
  captures pause until you **Hand back**. Losing the connection is not a handback; use Hand
  back even after a failed viewer connection. Agents can continue unrelated ordinary work.

The **Realms** page lists every Realm on the environment, stops them, and deletes a stopped
Realm's retained workspace after you type a confirmation. Deleting is separate from Stop.

An idle Realm stops after the configured idle time (30 minutes by default); its workspace is
kept. Watching and your input while in control count as activity. Deleting or archiving a
thread does not delete its Realm's workspace; remove it from the Realms page.

## Omarchy VM

VM setup needs `qemu-full`, `edk2-ovmf`, `mtools`, OpenSSH, socat, jq, openssl, curl,
GnuPG with Omarchy's signing keyring, a working systemd user manager, `/dev/kvm` access,
and an existing `~/.ssh/id_ed25519` key pair. The review reports every missing tool,
firmware file, package, key pair or access prerequisite. On Arch with pacman and pkexec, setup can install only the exact reviewed packages after your
approval and native Polkit authorization. SSH key creation/replacement, KVM access, signing
keyring initialization and systemd-user repairs remain manual blockers; setup never changes
host permissions or compositor config.
The pinned vendored `omarchy-vm` installs the exact reviewed release from Omarchy's
GPG-verified ISO (signer `40DFB630FF42BCFFB047046CF0134EE680CAC571`). Its digest is
checked before every invocation; see [vendor provenance](runtime/t3realms/vendor/VENDOR.md).

The review lists the ISO (about 5 GiB), optional pinned GUI driver download (at most
64 MiB), destinations, virtual disk capacity, RAM, CPUs and network mode. A fresh default
install requires 46 GiB free disk (40 GiB capacity plus 6 GiB headroom); actual sparse disk
usage depends on guest writes. The ISO and stopped base are shared only within this
plugin's data directory. Per-thread overlays use that base; no Hermes images, ISOs or
profiles are reused. Setup is a detached cancellable job. Cancelling preserves completed
shared downloads/driver files and retains interrupted base work for explicit recovery.

VM terminal commands receive the guest environment and run as its desktop user. Only
presentation environment crosses; API credentials, host display/bus handles, SSH agents,
private keys and X11 are not forwarded. SSH uses a per-generation host-key pin retained
with the disk and verified on resume. Initial enrollment is trust on first use during the
owned launch; it is not an out-of-band identity proof against a hostile same-UID host.
Computer use runs the pinned driver inside the guest. Screenshots and watch frames return
through T3; takeover uses the private VM VNC socket. Human control excludes agent input.

The guest disk is **unencrypted** and has **passwordless sudo**. Keep tokens and personal
files out. Networking defaults to enabled; QEMU user networking can reach host loopback
services through `10.0.2.2`. Turn off **VM unrestricted networking** for `restrict=on`.
A VM is not a promise of unlimited containment.

Stop retains the overlay. Verified stopped disks expire after 14 days without use on the
next list/start; **Stopped VM disk retention** sets the current policy (`0` keeps them).
Running/starting guests, open files and uncertain retirement are preserved. A changed or
incomplete disk/spec/pin becomes **needs recovery**; fresh allocation will not replace it.
If compute retirement or cleanup is unconfirmed, a person must inspect ownership/permissions
and retry **Stop** before reconnecting or considering deletion. If compute is verified stopped
but retained files failed verification, preserve/recover data with a person; GUI Repair and
On cannot repair those files. Use person-reviewed typed **Discard** only if the person chooses
to delete that data, or recovery-only prune. Delete and Discard bind the exact record, compute state and file receipts with an opaque token.

`realm-files` examples (paths are literal, including wildcard characters):

```json
{"action":"push","source":"/host/project","destination":"/home/guest/project"}
{"action":"pull","source":"/home/guest/project","destination":"/host/fresh-export"}
{"action":"status","jobId":"<returned jobId>"}
{"action":"cancel","jobId":"<returned jobId>"}
```

Pull requires an explicit host destination. Existing destination directories are containers;
check `data.result.destination` in the successful job. Push directories select the exact
guest path. Identical entries remain untouched and additions merge; different bytes, types
or link targets fail as conflicts. No overwrites, glob expansion, implicit sync or mounts.
Transfers are limited to 8 GiB of archive data and 100,000 entries. Copies are not crash-atomic;
inspect partial work after interruption. Export changed guest work into a fresh location
and reconcile it with your ordinary host project.

## Sharing between agents

A Realm belongs to an owner thread. Verified subagents, including nested subagents, share
the parent's Realm, kind, preferences, human control, driver session and jobs. Forks keep
their own Realm. A subagent's status identifies the parent it shares from. Older hosts
without verified lineage keep one Realm per thread. A host that explicitly reports unresolved
lineage gets a retryable refusal instead of allocating a separate Realm. Retry status after
two seconds and ask the person to inspect lineage if it remains unresolved. The plugin uses only host-verified
caller/target lineage, never a parent or owner id from the request.
A person using a T3 client operates the environment and can manage any thread's Realm.
Setup, deleting workspaces and taking control always need a person. Subagents should omit
thread overrides or use their own caller thread; ownership selects the parent automatically.
Coordinate parallel subagents: they share one screen, and lifecycle changes affect everyone.

## Recovering a Realm call

Inspect `realm` status for the latest start attempt, current guest-driver preparation and
cleanup/recovery cause. Pending jobs suggest a two-second status interval. Failed boot and
staging attempts remain visible: ordinary tools do not silently start another attempt.
After inspecting the cause, explicitly request **On** for one new boot or **Repair** for
one new driver preparation. After GUI Repair, take a fresh capture before any input.

A lost command or GUI reply can mean the action already landed. Do not replay it blindly.
Use Realm status, terminal results or an allowed shot to diagnose; report repeated failures
and continue unrelated ordinary work. Recently acknowledged terminal job IDs remain in
status for polling/signalling, including after a cancelled foreground wait. Native job
results still expire; a retained ID is not proof that the process is still running.

Oversize captures are withheld and removed. Request a smaller watch-frame scale or a GUI
zoom region. Results stay below the host's 128 KB JSON limit and each image below 4 MiB
(8 MiB total). Neither recovery nor a refusal requires disabling or removing the plugin.

## Compared with Hermes Realms

| Hermes Realms | Here |
|---|---|
| Regular Realm (labwc) | Supported. Same native runtime, adapted to a plugin-owned data directory. |
| `/realm on/off/stop/status/size/repair/shot` | `realm` action and the Realm panel. |
| `terminal(target="realm")` | `realm-terminal` action. Native provider shells are not redirected. |
| `computer_use` routed to the Realm | `realm-computer` action (pinned cua-driver over MCP, contained with bubblewrap). Provider-native computer tools are not redirected. |
| Setup consent, progress and cancel | Exact reviewed plan; detached cancellable setup, including supported Arch packages through native Polkit authorization. |
| Off vs stop, retained workspaces, typed delete | Supported. |
| View-only watch | Periodic captures through the T3 connection, so it works remotely. Not a VNC stream. |
| Human takeover with agent exclusion | Supported through the Realm's private VNC socket on the server; input travels over the T3 connection. |
| Session badges / footer item | Thread status contribution. |
| Omarchy VM kind, push/pull | Supported by the backend: per-thread overlays, guest SSH/CUA, explicit conflict-safe transfers. |
| Sub-agents sharing the parent's Realm | Supported when the host supplies verified subagent lineage; nested subagents share, forks remain separate. |
| Setup continuation (resume the agent after setup) | One retry prompt to the requesting thread after person-approved successful setup, subject to the project’s `threads.send` grant. No old command is replayed. |
| Legacy permission review | Not applicable: there are no earlier T3 Realms. |
