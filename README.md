# T3 Code Realms

Realms gives each T3 Code thread an optional private Linux desktop for testing GUI and
desktop software. The agent opens, clicks and screenshots apps inside the Realm, never on
your screen, pointer or clipboard. Its ordinary work (shell, files, git) stays where it was.

A Realm is a lightweight private labwc/Wayland desktop with Xwayland on the T3 server's
machine. It separates windows, pointer, keyboard, clipboard and session buses from your
desktop, but shares the machine's kernel, files and network. **It is not a VM or a sandbox
for hostile code.**

This is a port of [Hermes Realms](https://github.com/Zeus-Deus/hermes-realms) 0.2.0 to the
T3 Code plugin host. See [NOTICE.md](NOTICE.md).

## Requirements

The T3 server's machine (not the device you browse from):

- Linux x86-64 with a working systemd user manager.
- `labwc`, `Xwayland`, `wayvnc`, `grim`, `wlr-randr`, `bubblewrap`, `dbus-daemon`/`gdbus`,
  and AT-SPI (`at-spi-bus-launcher`, `at-spi2-registryd`).
- Python 3.11+ (standard library only).
- A T3 Code build whose plugin host reports verified callers, a plugin data directory,
  image results and thread status (plugin API 1 with those additions).

Realms never runs `sudo` or system package installers. Missing packages are reported as an
explicit blocker in setup.

## Install

In **Settings → Plugins**, install this directory, review it and consent. (A Git install
works once the repository has a published commit.) Grant `ui`, `storage` and `settings`. Then open **Realms** from the command
palette and review setup: it checks the packages above and, when you approve, downloads the
pinned cua-driver 0.23.2 release from GitHub, verifies its checksums and installs it into
the plugin's own data directory. Nothing global changes.

## Using it

Ask the agent to test something visually. Agents see three tools through `t3_plugin_list`
and call them with `t3_plugin_invoke`:

| Action | What it does |
|---|---|
| `realm` | `on`, `off`, `status`, `size`, `stop`, `repair`, `shot`, `watch` for this thread's Realm. |
| `realm-terminal` | Run a command inside the Realm (background for GUI apps), poll or signal jobs. |
| `realm-computer` | Computer use through the pinned GUI driver: screenshots, accessibility trees, click, type, keys, scroll, drag. |

A thread with a Realm shows a compact status beside it (**Realm live**, **Realm starting**,
**Realm · you have control**). Activating it, or **Realm** in the thread menu, opens the
Realm panel:

- **Turn off** stops the agent using the Realm. The desktop, its workspace and your view stay.
  The agent cannot turn it back on; you can.
- **Stop** ends the desktop and keeps its workspace. Save app work first.
- **Watch** shows periodic captures of the desktop (about one or two per second while the
  panel is visible). It is view-only.
- **Take control** lets you use the pointer and keyboard in the Realm. The agent's input and
  captures pause until you **Hand back**. Losing the connection is not a handback.

The **Realms** page lists every Realm on the environment, stops them, and deletes a stopped
Realm's retained workspace after you type a confirmation. Deleting is separate from Stop.

An idle Realm stops after the configured idle time (30 minutes by default); its workspace is
kept. Watching and your input while in control count as activity. Deleting or archiving a
thread does not delete its Realm's workspace; remove it from the Realms page.

## Ownership

A Realm belongs to one thread. An agent can only reach its own thread's Realm: the plugin
uses the identity the T3 host verified for the caller, never a thread id from the request.
A person using a T3 client operates the environment and can manage any thread's Realm.
Setup, deleting workspaces and taking control always need a person.

## Hermes Realms → T3 Code Realms

| Hermes Realms | Here |
|---|---|
| Regular Realm (labwc) | Supported. Same native runtime, adapted to a plugin-owned data directory. |
| `/realm on/off/stop/status/size/repair/shot` | `realm` action and the Realm panel. |
| `terminal(target="realm")` | `realm-terminal` action. Native provider shells are not redirected. |
| `computer_use` routed to the Realm | `realm-computer` action (pinned cua-driver over MCP, contained with bubblewrap). Provider-native computer tools are not redirected. |
| Setup consent, progress and cancel | Setup review in the panel and page, bound to the reviewed plan; detached job with status and cancel. |
| Off vs stop, retained workspaces, typed delete | Supported. |
| View-only watch | Periodic captures through the T3 connection, so it works remotely. Not a VNC stream. |
| Human takeover with agent exclusion | Supported through the Realm's private VNC socket on the server; input travels over the T3 connection. |
| Session badges / footer item | Thread status contribution. |
| Omarchy VM kind, push/pull | Not yet. Asking for it returns an explicit error. |
| Sub-agents sharing the parent's Realm | Not yet: each T3 thread, including a delegated child thread, gets its own Realm. T3 does not yet expose a verified parent identity to plugins. |
| Setup continuation (resume the agent after setup) | Not yet. Tell the agent to retry after setup. |
| Legacy permission review | Not applicable: there are no earlier T3 Realms. |

## Development

```sh
node --test tests/                                              # plugin logic and protocols
cd runtime && python3 -I -B -m unittest discover -s tests -v    # native runtime, no desktops started
```

Native tests that start real desktops are gated behind `T3REALMS_NATIVE=1` and must only
run in an approved disposable environment.

## License

Original code: [MIT](LICENSE). See [NOTICE.md](NOTICE.md) for derived and downloaded components.
