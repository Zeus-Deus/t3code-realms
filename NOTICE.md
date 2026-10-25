# Notices

T3 Code Realms is derived in part from Hermes Realms 0.2.0
(https://github.com/Zeus-Deus/hermes-realms, commit da5cdd3), Copyright (c) 2026 Zeus-Deus,
MIT License. The regular-Realm and Omarchy VM runtime under `runtime/t3realms` is an adapted copy of its
stdlib-only lifecycle, desktop worker, workspace, driver containment installer, VM workspace/SSH/CUA and selected-copy transfer modules,
re-homed to a plugin-owned data directory with no Hermes dependencies.

The pinned cua-driver 0.23.2 binary is downloaded on explicit setup consent from
https://github.com/trycua/cua/releases and is not redistributed in this package.

`runtime/t3realms/vendor/omarchy-vm` is derived from omacom/omarchy PR #10977,
MIT License, Copyright (c) David Heinemeier Hansson. The MIT license is included
in `runtime/t3realms/vendor/LICENSE`. Hermes Realms adaptations at da5cdd3 are
Copyright (c) 2026 Zeus-Deus (MIT). `vendor/VENDOR.md` records upstream and
Hermes digests and T3 local patches; the executed digest is pinned in
`vm_manager.py` and checked before every invocation. No guest image or ISO is
redistributed. Omarchy's own signed release ISO is downloaded only on setup consent.
