// Realm semantics on top of the native runtime: who may do what to which thread's desktop.
//
// Identity comes only from the host's verified `invocation.caller`. An agent acts on its own
// thread's Realm; `context.threadId` is a requested target and must agree with it. A person
// using a client operates the environment and may manage any thread's Realm.
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { RealmError } from "./runtime.mjs";
import { hostEscape } from "./hostGuard.mjs";

export const DRIVER = Object.freeze({
  version: "0.23.2",
  archiveSha256: "478e010d2b0426de9d8a07eb839802daa92137b33cb8affb93b991e91d76ce7e",
  url: "https://github.com/trycua/cua/releases/download/cua-driver-rs-v0.23.2/cua-driver-rs-0.23.2-linux-x86_64.tar.gz",
});

/** GUI driver tools an agent may call. Configuration, updates, recordings and installers stay out. */
export const COMPUTER_TOOLS = new Set([
  "bring_to_front",
  "browser_click",
  "browser_dialog",
  "browser_navigate",
  "browser_pointer",
  "browser_prepare",
  "browser_type",
  "click",
  "clipboard_read",
  "clipboard_write",
  "double_click",
  "drag",
  "end_session",
  "get_accessibility_tree",
  "get_browser_state",
  "get_cursor_position",
  "get_desktop_state",
  "get_screen_size",
  "get_session",
  "get_window_state",
  "health_report",
  "hotkey",
  "invoke_menu",
  "kill_app",
  "launch_app",
  "list_apps",
  "list_sessions",
  "list_windows",
  "mouse_button_down",
  "mouse_button_up",
  "mouse_drag",
  "move_cursor",
  "press_key",
  "right_click",
  "scroll",
  "set_value",
  "set_window_frame",
  "start_session",
  "type_text",
  "verify_state",
  "zoom",
]);

const DRIVER_MISSING = "verified cua-driver";
// Leaves room inside the host's 30 s invocation deadline for the calls around the wait.
const START_WAIT_MS = 12_000;
const COMMAND_WAIT_MAX_MS = 20_000;
const POLL_MS = 250;
const MAX_ASSETS = 40;
const MAX_INPUT_EVENTS = 64;
const MAX_TEXT_RESULT = 60_000;
// The host rejects results over 128 KB; JSON escaping and UTF-8 make characters a poor proxy.
const RESULT_BUDGET_BYTES = 100_000;
const INPUT_RENEW_MS = 30_000;

const jsonBytes = (value) => Buffer.byteLength(JSON.stringify(value));
/** Shrink the longest strings in `data` from the middle until the result fits the host budget. */
export function fitResult(result, fields) {
  const data = { ...result.data };
  let truncated = false;
  for (let round = 0; round < 40 && jsonBytes({ ...result, data }) > RESULT_BUDGET_BYTES; round++) {
    const field = fields
      .filter((name) => typeof data[name] === "string")
      .sort((a, b) => jsonBytes(data[b]) - jsonBytes(data[a]))[0];
    if (!field) break;
    const text = data[field];
    const keep = Math.floor(text.length * 0.6);
    const omitted = text.length - keep;
    data[field] = `${text.slice(0, Math.ceil(keep / 2))}\n… ${omitted} characters omitted …\n${text.slice(text.length - Math.floor(keep / 2))}`;
    truncated = true;
  }
  return truncated ? { ...result, data: { ...data, truncated: true } } : result;
}

const ownership = (message) => new RealmError("ownership", message);
const invalid = (message) => new RealmError("invalid_input", message);
const sleep = (ms, signal) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(new RealmError("cancelled", "The request was cancelled."));
      },
      { once: true },
    );
  });
const abortable = (promise, signal) =>
  new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new RealmError("cancelled", "The request was cancelled."));
    const abort = () => reject(new RealmError("cancelled", "The request was cancelled."));
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
const ownerKey = (threadId) => `thread:${threadId}`;
const threadOf = (owner) => (typeof owner === "string" && owner.startsWith("thread:") ? owner.slice(7) : null);
const threadIdPattern = /^[^\s]{1,200}$/;

/** Resolve who is asking and which thread's Realm they mean. */
export function principal(invocation, input = {}) {
  const caller = invocation?.caller;
  if (!caller || typeof caller.kind !== "string")
    throw ownership("This T3 Code server does not report a verified caller. Update T3 Code to use Realms.");
  if (caller.kind === "agent") {
    if (typeof caller.threadId !== "string")
      throw ownership("Realms belong to T3 threads. This agent is not running in a thread, so it has no Realm.");
    const requested = invocation.context?.threadId;
    if (requested !== undefined && requested !== caller.threadId)
      throw ownership("An agent can only use its own thread's Realm.");
    return { kind: "agent", threadId: caller.threadId };
  }
  if (caller.kind === "client") {
    const threadId = invocation.context?.threadId ?? input.threadId;
    if (threadId !== undefined && (typeof threadId !== "string" || !threadIdPattern.test(threadId)))
      throw invalid("Unknown thread.");
    return { kind: "user", threadId };
  }
  throw ownership("Background handlers cannot control Realms.");
}

const requireThread = (who) => {
  if (!who.threadId) throw invalid("Open a thread to use its Realm.");
  return who.threadId;
};
const requireUser = (who, what) => {
  if (who.kind !== "user") throw ownership(`${what} needs a person in T3 Code; an agent cannot do it.`);
};

export function createRealms({ runtime, storage, settings, dataDirectory, connectCua, connectRfb, now = () => Date.now() }) {
  const cuaSessions = new Map();
  // The driver's MCP endpoint is a proxy to a `serve` daemon on the Realm's private socket.
  // The daemon runs as a job inside the Realm's own scope, so it ends with the Realm.
  // Its job id is kept in plugin storage so a restarted worker can still stop it.
  const cuaPending = new Map();
  const rfbClients = new Map();
  const locks = new Map();
  let doctorCache;

  const locked = async (key, task) => {
    const previous = locks.get(key) ?? Promise.resolve();
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    const chained = previous.then(() => current);
    locks.set(key, chained);
    await previous;
    try {
      return await task();
    } finally {
      release();
      if (locks.get(key) === chained) locks.delete(key);
    }
  };

  const config = async () => {
    const size = (await settings.get("size")) ?? "1920x1080";
    const minutes = Number((await settings.get("idleMinutes")) ?? 30);
    const renderer = (await settings.get("renderer")) ?? "gles2";
    return {
      size: String(size),
      idle_ttl: Number.isFinite(minutes) && minutes > 0 ? minutes * 60 : 1800,
      renderer: String(renderer),
    };
  };

  const preference = async (threadId) => (await storage.get(`thread:${threadId}`)) ?? null;
  const setPreference = (threadId, value) => storage.set(`thread:${threadId}`, { ...value, updatedAt: new Date(now()).toISOString() });
  // Control belongs to one desktop incarnation; a restarted Realm starts uncontrolled.
  const control = async (record) => {
    const held = (await storage.get(`control:${record.id}`)) ?? null;
    if (held && held.generation !== record.generation) {
      await storage.delete(`control:${record.id}`);
      return null;
    }
    return held;
  };
  const lastInputRenewal = new Map();

  const doctor = async ({ fresh = false, signal } = {}) => {
    if (!fresh && doctorCache && now() - doctorCache.at < 15_000) return doctorCache.value;
    const value = await runtime.call("doctor", {}, { signal });
    doctorCache = { at: now(), value };
    return value;
  };
  const setupSummary = (report) => ({
    ready: report.ready === true,
    missing: report.missing ?? [],
    driver: report.driver ?? null,
    message: report.message ?? (report.ready ? "Ready" : "Setup required"),
  });
  const requireSetup = async (signal) => {
    const report = await doctor({ signal });
    if (report.ready !== true) {
      doctorCache = undefined;
      throw new RealmError(
        "setup_required",
        `${report.message ?? "Realms setup is not complete."} A person must open Realms setup in T3 Code (command palette: "Realms") and approve it; never substitute the physical desktop.`,
      );
    }
  };

  const records = async (owner, signal) => runtime.call("list", owner ? { owner } : {}, { signal });
  const current = async (owner, signal) => {
    const all = await records(owner, signal);
    return (
      all.find((record) => record.status === "running") ??
      all.find((record) => record.status === "starting") ??
      all.filter((record) => record.status === "stopped").sort((a, b) => (b.last_activity ?? 0) - (a.last_activity ?? 0))[0] ??
      all[0] ??
      null
    );
  };
  const activeStartJob = async (owner, signal) =>
    (await runtime.call("job_list", { owner }, { signal })).find(
      (job) => job.kind === "start" && (job.state === "queued" || job.state === "running"),
    ) ?? null;

  const dropSessions = (realmId) => {
    cuaSessions.get(realmId)?.session.close();
    cuaSessions.delete(realmId);
  };
  const stopDriverDaemon = async (record, signal) => {
    const daemon = await storage.get(`driver:${record.id}`);
    await storage.delete(`driver:${record.id}`);
    if (!daemon || daemon.generation !== record.generation) return;
    await runtime
      .call("signal", { id: record.id, owner: record.owner ?? record.session_id, job_id: daemon.jobId, signal: 15 }, { signal })
      .catch(() => undefined);
  };
  const dropControlConnection = (realmId) => {
    rfbClients.get(realmId)?.close();
    rfbClients.delete(realmId);
  };

  const agentAllowed = async (who) => {
    if (who.kind !== "agent") return;
    const pref = await preference(who.threadId);
    if (pref?.mode === "off")
      throw new RealmError(
        "disabled",
        pref.setBy === "user"
          ? "Realm use is turned off for this thread by the user. Ordinary tools still work; ask them to turn the Realm on from its panel if a private desktop is needed."
          : "Realm use is off for this thread. Turn it on with action \"on\" first.",
      );
  };
  const agentNotControlled = async (who, record) => {
    if (who.kind === "agent") await notControlled(record);
  };
  const notControlled = async (record) => {
    const held = await control(record);
    if (held)
      throw new RealmError(
        "human_control",
        "A person has taken control of this Realm. Wait for them to hand it back. Do not use shell screenshots or other input tools to work around this.",
      );
  };

  const waitForJob = async (jobId, waitMs, signal) => {
    const deadline = now() + waitMs;
    for (;;) {
      const job = await runtime.call("job_status", { job_id: jobId }, { signal });
      if (!["queued", "running"].includes(job.state) || now() >= deadline) return job;
      await sleep(POLL_MS, signal);
    }
  };

  /** Start or reuse this thread's desktop. Never substitutes another thread's or the host's. */
  const ensureRunning = async (threadId, { signal, waitMs = START_WAIT_MS } = {}) => {
    const owner = ownerKey(threadId);
    const record = await current(owner, signal);
    if (record?.status === "running") {
      await runtime.call("touch", { id: record.id, owner }, { signal });
      return { record };
    }
    await requireSetup(signal);
    const job = (await activeStartJob(owner, signal)) ?? {
      job_id: (await runtime.call("job_start", { kind: "start", owner, input: { config: await config() } }, { signal })).job_id,
    };
    const result = await waitForJob(job.job_id, waitMs, signal);
    if (result.state === "succeeded") {
      const started = await current(owner, signal);
      if (started?.status !== "running") throw new RealmError("failed", "The Realm stopped right after starting.");
      return { record: started };
    }
    if (result.state === "queued" || result.state === "running") return { starting: result };
    throw new RealmError(result.code ?? "failed", `The Realm could not start: ${result.error ?? result.state}.`);
  };
  const requireRunning = async (threadId, signal) => {
    const record = await current(ownerKey(threadId), signal);
    if (record?.status !== "running")
      throw new RealmError("not_running", "This thread's Realm is not running. Nothing falls back to the host desktop.");
    return record;
  };
  const runningForAgent = async (who, signal) => {
    await agentAllowed(who);
    // A start decision races a person's Stop or a sibling call without the thread lock.
    const started = await locked(who.threadId, () => ensureRunning(who.threadId, { signal }));
    if (!started.record)
      throw new RealmError("starting", `The Realm is still starting (job ${started.starting.job_id}). Check status again shortly.`);
    return started.record;
  };

  const pruneAssets = async () => {
    const directory = path.join(dataDirectory, "assets");
    const entries = await fs.readdir(directory, { withFileTypes: true }).catch(() => []);
    const files = await Promise.all(
      entries
        .filter((entry) => entry.isFile() && /^(cua|shot)-/.test(entry.name))
        .map(async (entry) => ({ name: entry.name, mtime: (await fs.stat(path.join(directory, entry.name))).mtimeMs })),
    );
    files.sort((a, b) => b.mtime - a.mtime);
    await Promise.all(files.slice(MAX_ASSETS).map((file) => fs.rm(path.join(directory, file.name), { force: true })));
  };
  const writeAsset = async (prefix, data, mimeType) => {
    const directory = path.join(dataDirectory, "assets");
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const name = `${prefix}-${randomUUID()}.${mimeType === "image/png" ? "png" : "jpg"}`;
    await fs.writeFile(path.join(directory, name), data, { mode: 0o600 });
    await pruneAssets();
    return path.join("assets", name);
  };

  const describeRealm = async (record) => {
    if (!record) return null;
    const held = await control(record);
    let windows = null;
    if (record.status === "running") {
      windows =
        (await runtime.call("windows", { id: record.id, owner: record.owner ?? record.session_id }).catch(() => ({ count: null })))
          .count ?? null;
    }
    return {
      id: record.id,
      state: record.status === "running" ? "live" : record.status,
      size: record.size ?? null,
      windowCount: windows,
      createdAt: record.created_at ?? null,
      lastActivity: record.last_activity ?? null,
      idleTtlSeconds: record.idle_ttl ?? null,
      controlledBy: held ? "user" : null,
      error: record.error ?? record.cleanup_note ?? null,
    };
  };

  const status = async (who, { signal } = {}) => {
    const threadId = requireThread(who);
    const owner = ownerKey(threadId);
    const [pref, record, job, report] = await Promise.all([
      preference(threadId),
      current(owner, signal),
      activeStartJob(owner, signal),
      doctor({ signal }).catch((error) => ({ ready: false, message: error.message })),
    ]);
    return {
      threadId,
      mode: pref?.mode ?? "unset",
      offBy: pref?.mode === "off" ? (pref.setBy ?? null) : null,
      kind: "realm",
      setup: setupSummary(report),
      realm: await describeRealm(record),
      starting: job ? { jobId: job.job_id, progress: job.progress ?? null } : null,
    };
  };

  const summary = (state) => {
    const realm = state.realm;
    const mode = state.mode === "off" ? "Realm off" : state.mode === "realm" ? "Realm on" : "Realm available";
    if (!state.setup.ready) return `${mode} · setup required`;
    if (state.starting) return `${mode} · starting`;
    if (!realm) return `${mode} · not started`;
    const windows = realm.windowCount === null ? "" : ` (${realm.windowCount} window${realm.windowCount === 1 ? "" : "s"})`;
    return `${mode} · ${realm.state}${windows}${realm.controlledBy ? " · user in control" : ""}`;
  };

  /** The compact thread status: quiet unless this thread uses a Realm. Cheap enough to poll. */
  const badge = async (who, { signal } = {}) => {
    const threadId = requireThread(who);
    const owner = ownerKey(threadId);
    const [pref, all, jobs] = await Promise.all([
      preference(threadId),
      records(owner, signal),
      runtime.call("job_list", { owner }, { signal }),
    ]);
    const live = all.find((record) => record.status === "running");
    const starting = jobs.some((job) => job.kind === "start" && ["queued", "running"].includes(job.state));
    const agentUse = pref?.mode === "off" ? "Agent use is off" : "Agent can use it";
    if (live) {
      if (await control(live))
        return { label: "Realm · you have control", tone: "warning", detail: "The agent is paused until you hand control back." };
      return { label: pref?.mode === "off" ? "Realm live · agent off" : "Realm live", tone: "success", detail: `${live.size ?? ""} desktop. ${agentUse}.`.trim() };
    }
    if (starting) return { label: "Realm starting", tone: "info", detail: "Starting this thread's private desktop." };
    if (pref?.mode === "realm") {
      const report = await doctor({ signal }).catch(() => ({ ready: false }));
      if (report.ready !== true) return { label: "Realm setup needed", tone: "warning", detail: "Open the Realm panel to review setup." };
      return all.length
        ? { label: "Realm stopped", tone: "neutral", detail: "Workspace kept. It starts again when needed." }
        : { label: "Realm on", tone: "neutral", detail: "Starts when the agent needs a desktop." };
    }
    if (pref?.mode === "off") return { label: "Realm off", tone: "neutral", detail: "Agent use is off for this thread." };
    return null;
  };

  const on = (who, input, { signal } = {}) =>
    locked(requireThread(who), async () => {
      if (input.kind !== undefined && input.kind !== "realm")
        throw new RealmError(
          "unsupported",
          input.kind === "omarchy-vm"
            ? "The Omarchy VM kind is not available in T3 Code Realms yet. Use the regular Realm."
            : "Unknown Realm kind.",
        );
      const pref = await preference(who.threadId);
      if (who.kind === "agent" && pref?.mode === "off" && pref.setBy === "user") await agentAllowed(who);
      await requireSetup(signal);
      await setPreference(who.threadId, { mode: "realm", kind: "realm", setBy: who.kind });
      const started = await ensureRunning(who.threadId, { signal });
      return status(who, { signal });
    });

  const off = (who, { signal } = {}) =>
    locked(requireThread(who), async () => {
      const pref = await preference(who.threadId);
      // An agent's off cannot replace a person's, or it could then turn the Realm back on.
      if (!(who.kind === "agent" && pref?.mode === "off" && pref.setBy === "user"))
        await setPreference(who.threadId, { mode: "off", kind: "realm", setBy: who.kind });
      const record = await current(ownerKey(who.threadId), signal);
      // Off revokes agent use only; the desktop, its workspace and anyone watching stay.
      if (record) {
        dropSessions(record.id);
        await stopDriverDaemon(record, signal);
      }
      return status(who, { signal });
    });

  const stop = (who, { signal } = {}) =>
    locked(requireThread(who), async () => {
      const owner = ownerKey(who.threadId);
      const job = await activeStartJob(owner, signal);
      await agentAllowed(who);
      const record = await current(owner, signal);
      if (record) await agentNotControlled(who, record);
      if (job) await runtime.call("job_cancel", { job_id: job.job_id }, { signal });
      if (record) {
        dropSessions(record.id);
        dropControlConnection(record.id);
        await storage.delete(`control:${record.id}`);
      }
      await runtime.call("stop_owner", { owner }, { signal });
      return status(who, { signal });
    });

  const resize = (who, input, { signal } = {}) =>
    locked(requireThread(who), async () => {
      if (typeof input.size !== "string") throw invalid("Give the size as WIDTHxHEIGHT, for example 1600x900.");
      await agentAllowed(who);
      const record = await requireRunning(who.threadId, signal);
      await agentNotControlled(who, record);
      dropControlConnection(record.id);
      await runtime.call("resize", { id: record.id, owner: ownerKey(who.threadId), size: input.size }, { signal });
      return status(who, { signal });
    });

  const repair = async (who, { signal } = {}) => {
    const record = await requireRunning(requireThread(who), signal);
    await agentAllowed(who);
    await agentNotControlled(who, record);
    dropSessions(record.id);
    await stopDriverDaemon(record, signal);
    return {
      message: "GUI driver connection reset. The next computer action reconnects; take a fresh capture and check the app is where you left it. Nothing was replayed.",
    };
  };

  const capture = async (record, { quality, scale, signal }) => {
    const shot = await runtime.call(
      "shot",
      { id: record.id, owner: record.owner ?? record.session_id, format: "jpeg", quality, scale },
      { signal },
    );
    await pruneAssets();
    return shot;
  };

  const shot = async (who, { signal } = {}) => {
    const threadId = requireThread(who);
    await agentAllowed(who);
    const record = await requireRunning(threadId, signal);
    if (who.kind === "agent") await notControlled(record);
    const result = await capture(record, { quality: 85, scale: 1, signal });
    return {
      message: `Captured this thread's Realm (${result.width}x${result.height}).`,
      data: { realmId: record.id, width: result.width, height: result.height, sha256: result.sha256 },
      images: [{ path: result.path, mimeType: result.mimeType }],
    };
  };

  const terminal = async (who, input, { signal } = {}) => {
    const threadId = requireThread(who);
    const owner = ownerKey(threadId);
    if (input.jobId !== undefined) {
      if (typeof input.jobId !== "string") throw invalid("jobId must be a string.");
      await agentAllowed(who);
      const record = await requireRunning(threadId, signal);
      await agentNotControlled(who, record);
      if (input.signal !== undefined) {
        const signals = { INT: 2, TERM: 15, KILL: 9, HUP: 1 };
        if (!(input.signal in signals)) throw invalid("signal must be INT, TERM, KILL or HUP.");
        await runtime.call("signal", { id: record.id, owner, job_id: input.jobId, signal: signals[input.signal] }, { signal });
      }
      return commandResult(await runtime.call("job", { id: record.id, owner, job_id: input.jobId }, { signal }));
    }
    const command = input.command;
    if (typeof command !== "string" || !command.trim() || command.length > 16_000)
      throw invalid("command must be a nonempty shell command.");
    const refusal = hostEscape(command);
    if (refusal) throw new RealmError("host_escape", refusal);
    if (input.cwd !== undefined && (typeof input.cwd !== "string" || !path.isAbsolute(input.cwd)))
      throw invalid("cwd must be an absolute path.");
    const record = await runningForAgent(who, signal);
    await agentNotControlled(who, record);
    const job = await runtime.call(
      "exec",
      { id: record.id, owner, argv: ["/bin/sh", "-c", command], ...(input.cwd ? { cwd: input.cwd } : {}) },
      { signal },
    );
    if (who.kind === "agent" && (await control(record))) {
      await runtime.call("signal", { id: record.id, owner, job_id: job.job_id, signal: 9 }, { signal }).catch(() => undefined);
      throw new RealmError(
        "human_control",
        "A person took control as this command started; it was killed. It may already have affected the desktop.",
      );
    }
    if (input.background === true)
      return {
        message: `Started in this thread's Realm as job ${job.job_id}. Poll it with jobId; results are kept for five minutes after exit.`,
        data: { jobId: job.job_id, pid: job.pid, background: true },
      };
    const waitMs = Math.min(COMMAND_WAIT_MAX_MS, Math.max(1, Number(input.timeoutSeconds ?? 15)) * 1000);
    const deadline = now() + waitMs;
    for (;;) {
      const state = await runtime.call("job", { id: record.id, owner, job_id: job.job_id }, { signal });
      if (state.returncode !== null && state.returncode !== undefined) return commandResult(state);
      if (now() >= deadline)
        return {
          message: `Still running as job ${job.job_id}. Poll it with jobId, or run GUI apps with background: true.`,
          data: { jobId: job.job_id, running: true },
        };
      await sleep(POLL_MS, signal);
    }
  };
  const commandResult = (state) => {
    const finished = state.returncode !== null && state.returncode !== undefined;
    return fitResult({
      message: finished ? `Exited with code ${state.returncode}.` : `Job ${state.job_id} is still running.`,
      data: {
        jobId: state.job_id,
        running: !finished,
        ...(finished ? { exitCode: state.returncode } : {}),
        ...(state.stdout !== undefined ? { stdout: state.stdout } : {}),
        ...(state.stderr !== undefined ? { stderr: state.stderr } : {}),
        ...(state.stdout_truncated || state.stderr_truncated ? { truncated: true } : {}),
      },
    }, ["stdout", "stderr"]);
  };

  const ensureDriverDaemon = async (record, launcher, signal) => {
    const owner = record.owner ?? record.session_id;
    const known = await storage.get(`driver:${record.id}`);
    if (known?.generation === record.generation) {
      const state = await runtime.call("job", { id: record.id, owner, job_id: known.jobId }, { signal }).catch(() => null);
      if (state && (state.returncode === null || state.returncode === undefined)) return;
    }
    // After a plugin restart a daemon may already serve this socket; a second one exits, which is harmless.
    const job = await runtime.call("exec", { id: record.id, owner, argv: [launcher.path, "serve"] }, { signal });
    await storage.set(`driver:${record.id}`, { generation: record.generation, jobId: job.job_id });
  };
  // One connection attempt per Realm generation; concurrent callers wait for it.
  const cuaFor = (record, signal) => {
    const existing = cuaSessions.get(record.id);
    if (existing && existing.generation === record.generation && !existing.session.closed)
      return Promise.resolve(existing.session);
    let pending = cuaPending.get(record.id);
    if (!pending || pending.generation !== record.generation) {
      pending = {
        generation: record.generation,
        promise: connectCuaFor(record).finally(() => {
          if (cuaPending.get(record.id) === pending) cuaPending.delete(record.id);
        }),
      };
      cuaPending.set(record.id, pending);
    }
    return signal ? abortable(pending.promise, signal) : pending.promise;
  };
  const connectCuaFor = async (record) => {
    const signal = undefined;
    dropSessions(record.id);
    const launcher = await runtime.call(
      "driver_launcher",
      { id: record.id, owner: record.owner ?? record.session_id },
      { signal },
    );
    await ensureDriverDaemon(record, launcher, signal);
    let lastError;
    for (let attempt = 0; attempt < 20; attempt++) {
      const session = connectCua(launcher);
      try {
        await session.ready;
        cuaSessions.set(record.id, { generation: record.generation, session });
        return session;
      } catch (error) {
        session.close();
        lastError = error;
        if (!/no Cua Driver daemon listening/i.test(String(error?.message))) break;
        await sleep(POLL_MS, signal);
      }
    }
    throw new RealmError("driver_unavailable", lastError?.message ?? "The Realm GUI driver did not start.");
  };

  const computer = async (who, input, { signal } = {}) => {
    const startedAt = now();
    const threadId = requireThread(who);
    const tool = input.tool;
    if (typeof tool !== "string") throw invalid('Give a tool name, or "list" to see the available GUI tools.');
    if (tool !== "list" && !tool.startsWith("describe:") && !COMPUTER_TOOLS.has(tool))
      throw invalid(`"${tool}" is not an available Realm GUI tool. Use tool "list".`);
    if (input.arguments !== undefined && (typeof input.arguments !== "object" || input.arguments === null || Array.isArray(input.arguments)))
      throw invalid("arguments must be an object.");
    const record = await runningForAgent(who, signal);
    await agentNotControlled(who, record);
    const session = await cuaFor(record, signal);
    // Control can be taken while the driver connection is prepared; check again just before input.
    await agentNotControlled(who, record);
    if (tool === "list" || tool.startsWith("describe:")) {
      const tools = (await session.listTools({ signal })).filter((entry) => COMPUTER_TOOLS.has(entry.name));
      if (tool === "list")
        return {
          message: `${tools.length} GUI tools act only on this thread's Realm. Use "describe:<name>" for a tool's arguments.`,
          data: { tools: tools.map((entry) => ({ name: entry.name, description: String(entry.description ?? "").split("\n")[0].slice(0, 300) })) },
        };
      const name = tool.slice("describe:".length);
      const entry = tools.find((candidate) => candidate.name === name);
      if (!entry) throw invalid(`"${name}" is not an available Realm GUI tool.`);
      return { data: { name, description: String(entry.description ?? "").slice(0, 8_000), inputSchema: entry.inputSchema ?? {} } };
    }
    const epoch = (await control(record)) ?? null;
    // A cold call may already have spent part of the host's 30 s deadline starting the Realm.
    const timeoutMs = Math.max(5_000, Math.min(25_000, 27_000 - (now() - startedAt)));
    const result = await session.call(tool, input.arguments ?? {}, { signal, timeoutMs });
    if (who.kind === "agent" && JSON.stringify((await control(record)) ?? null) !== JSON.stringify(epoch))
      throw new RealmError(
        "human_control",
        "A person took control while this ran. The action may already have reached the desktop; its result was withheld. Wait for them to hand control back.",
      );
    const texts = [];
    const images = [];
    let imageBytes = 0;
    for (const part of result.content ?? []) {
      if (part.type === "text") texts.push(String(part.text));
      else if (part.type === "image" && images.length < 4 && ["image/png", "image/jpeg"].includes(part.mimeType)) {
        const bytes = Buffer.from(String(part.data), "base64");
        // The host refuses a result whose images exceed 8 MiB in total, so stay under it.
        if (bytes.length > 4 * 1024 * 1024 || imageBytes + bytes.length > 7 * 1024 * 1024) {
          texts.push("An image was too large to return and was dropped; use zoom for a smaller region.");
          continue;
        }
        imageBytes += bytes.length;
        images.push({ path: await writeAsset("cua", bytes, part.mimeType), mimeType: part.mimeType });
      }
    }
    let structured = result.structuredContent;
    if (structured !== undefined && JSON.stringify(structured).length > MAX_TEXT_RESULT) structured = undefined;
    // Structured output usually repeats the text; drop it first when the result is too large.
    const base = {
      message: result.isError ? `${tool} failed in this thread's Realm.` : `${tool} ran in this thread's Realm.`,
      data: { isError: result.isError === true, text: texts.join("\n") },
      ...(images.length ? { images } : {}),
    };
    const withStructured = structured === undefined ? base : { ...base, data: { ...base.data, structured } };
    return fitResult(jsonBytes(withStructured) <= RESULT_BUDGET_BYTES ? withStructured : base, ["text"]);
  };

  // Human control: the person drives the Realm through its private display socket while
  // agent input and captures are paused. Losing the connection is not a handback.
  const takeControl = (who, { signal } = {}) =>
    locked(requireThread(who), async () => {
      requireUser(who, "Taking control");
      const record = await requireRunning(who.threadId, signal);
      const held = await control(record);
      await storage.set(`control:${record.id}`, {
        controller: "user",
        generation: record.generation,
        since: held?.since ?? new Date(now()).toISOString(),
        epoch: (held?.epoch ?? 0) + 1,
      });
      dropSessions(record.id);
      await rfbFor(record, signal);
      return status(who, { signal });
    });
  const handBack = (who, { signal } = {}) =>
    locked(requireThread(who), async () => {
      requireUser(who, "Handing control back");
      const record = await current(ownerKey(who.threadId), signal);
      if (record) {
        dropControlConnection(record.id);
        await storage.delete(`control:${record.id}`);
      }
      return status(who, { signal });
    });
  const rfbFor = async (record, signal) => {
    const existing = rfbClients.get(record.id);
    if (existing && !existing.closed && existing.generation === record.generation) return existing;
    dropControlConnection(record.id);
    const endpoint = await runtime.call(
      "vnc_endpoint",
      { id: record.id, owner: record.owner ?? record.session_id },
      { signal },
    );
    const client = await connectRfb(endpoint.path);
    client.generation = record.generation;
    rfbClients.set(record.id, client);
    return client;
  };
  const sendInput = async (who, input, { signal } = {}) => {
    requireUser(who, "Controlling the Realm");
    const record = await requireRunning(requireThread(who), signal);
    if (!(await control(record))) throw new RealmError("not_controlled", "Take control first.");
    const events = Array.isArray(input.events) ? input.events : [];
    if (events.length === 0 || events.length > MAX_INPUT_EVENTS) throw invalid(`Send 1 to ${MAX_INPUT_EVENTS} input events.`);
    const client = await rfbFor(record, signal);
    for (const event of events) {
      if (event?.type === "pointer" && [event.x, event.y, event.buttons].every(Number.isFinite))
        client.pointer(event.x, event.y, event.buttons);
      else if (event?.type === "key" && Number.isInteger(event.keysym) && typeof event.down === "boolean")
        client.key(event.keysym, event.down);
      else throw invalid("Unknown input event.");
    }
    // A person driving the desktop is activity even when no frames are requested.
    if ((lastInputRenewal.get(record.id) ?? -Infinity) + INPUT_RENEW_MS <= now()) {
      lastInputRenewal.set(record.id, now());
      await runtime.call("touch", { id: record.id, owner: record.owner ?? record.session_id }, { signal });
    }
    return { data: { sent: events.length, size: client.size } };
  };

  const frame = async (who, input, { signal } = {}) => {
    requireUser(who, "Watching");
    const record = await requireRunning(requireThread(who), signal);
    const scale = Math.min(1, Math.max(0.1, Number(input.scale ?? 0.5)));
    const shot = await capture(record, { quality: 60, scale, signal });
    return {
      data: { realmId: record.id, width: shot.width, height: shot.height, size: record.size, controlledBy: (await control(record)) ? "user" : null },
      images: [{ path: shot.path, mimeType: shot.mimeType }],
    };
  };

  // Setup is reviewed and confirmed by a person. The confirmation names the exact plan it saw.
  const setupPlan = async (signal) => {
    const report = await doctor({ fresh: true, signal });
    const plan = {
      platform: report.platform ?? null,
      arch: report.arch ?? null,
      // The driver is what setup installs; everything else is a system prerequisite.
      missing: (report.missing ?? []).filter((name) => name !== DRIVER_MISSING),
      systemdUser: report.systemd_user ?? null,
      driver: {
        version: DRIVER.version,
        url: DRIVER.url,
        archiveSha256: DRIVER.archiveSha256,
        destination: report.driver?.path ?? path.join(dataDirectory, "bin", "cua-driver"),
        installed: report.driver?.verified === true,
      },
    };
    const reviewId = createHash("sha256").update(JSON.stringify(plan)).digest("hex").slice(0, 32);
    return { ...plan, ready: report.ready === true, message: report.message ?? null, reviewId };
  };
  const setupReview = async (who, { signal } = {}) => {
    requireUser(who, "Reviewing Realms setup");
    const plan = await setupPlan(signal);
    const jobs = await runtime.call("job_list", {}, { signal });
    return { data: { ...plan, job: jobs.find((job) => job.kind === "driver_install") ?? null } };
  };
  const setupStart = async (who, input, { signal } = {}) => {
    requireUser(who, "Approving Realms setup");
    const plan = await setupPlan(signal);
    if (input.reviewId !== plan.reviewId)
      throw new RealmError("changed", "The setup plan changed since you reviewed it. Review it again.");
    if (plan.missing.length > 0)
      throw new RealmError(
        "blocked",
        `Install these system packages with your package manager first: ${plan.missing.join(", ")}. Realms never runs sudo or system installers.`,
      );
    if (plan.driver.installed) return { message: "The pinned GUI driver is already installed and verified.", data: plan };
    const job = await runtime.call("job_start", { kind: "driver_install", input: {} }, { signal });
    doctorCache = undefined;
    return { message: "Installing the pinned GUI driver.", data: { jobId: job.job_id } };
  };
  const jobStatus = async (who, input, { signal } = {}) => {
    requireUser(who, "Checking setup");
    const job = await runtime.call("job_status", { job_id: String(input.jobId) }, { signal });
    if (!["queued", "running"].includes(job.state)) doctorCache = undefined;
    return { data: job };
  };
  const jobCancel = async (who, input, { signal } = {}) => {
    requireUser(who, "Cancelling setup");
    return { data: await runtime.call("job_cancel", { job_id: String(input.jobId) }, { signal }) };
  };

  // Environment-wide management for the Realms page.
  const list = async (who, { signal } = {}) => {
    requireUser(who, "Listing Realms");
    const [all, report] = await Promise.all([
      records(undefined, signal),
      doctor({ signal }).catch((error) => ({ ready: false, message: error.message })),
    ]);
    const realms = await Promise.all(
      all.map(async (record) => ({ threadId: threadOf(record.owner ?? record.session_id), ...(await describeRealm(record)) })),
    );
    realms.sort((a, b) => (a.state === "live" ? -1 : 0) - (b.state === "live" ? -1 : 0) || (b.lastActivity ?? 0) - (a.lastActivity ?? 0));
    return { data: { realms, setup: setupSummary(report) } };
  };
  const ownedRecord = async (input, signal) => {
    if (typeof input.realmId !== "string") throw invalid("Choose a Realm.");
    const record = (await records(undefined, signal)).find((candidate) => candidate.id === input.realmId);
    if (!record) throw new RealmError("not_found", "That Realm no longer exists.");
    return record;
  };
  const stopById = async (who, input, { signal } = {}) => {
    requireUser(who, "Stopping a Realm");
    const record = await ownedRecord(input, signal);
    const threadId = threadOf(record.owner ?? record.session_id);
    return threadId ? stop({ kind: "user", threadId }, { signal }) : runtime.call("stop", { id: record.id }, { signal });
  };
  const deleteReview = async (who, input, { signal } = {}) => {
    requireUser(who, "Deleting a workspace");
    const record = await ownedRecord(input, signal);
    const owner = record.owner ?? record.session_id;
    const snapshot = await runtime.call("delete_snapshot", { id: record.id, owner }, { signal });
    return { data: { realmId: record.id, owner, phrase: `delete ${record.id}`, snapshot, token: snapshot.token } };
  };
  const deleteWorkspace = async (who, input, { signal } = {}) => {
    requireUser(who, "Deleting a workspace");
    const record = await ownedRecord(input, signal);
    if (input.phrase !== `delete ${record.id}`) throw invalid(`Type "delete ${record.id}" to confirm.`);
    const owner = record.owner ?? record.session_id;
    if (typeof input.token !== "string") throw invalid("Review the workspace again before deleting it.");
    await runtime.call("delete", { id: record.id, owner, token: input.token }, { signal });
    await storage.delete(`control:${record.id}`);
    return { message: "Workspace deleted." };
  };

  const dispose = () => {
    for (const id of [...cuaSessions.keys()]) dropSessions(id);
    for (const id of [...rfbClients.keys()]) dropControlConnection(id);
  };

  return {
    status,
    badge,
    summary,
    on,
    off,
    stop,
    resize,
    repair,
    shot,
    terminal,
    computer,
    takeControl,
    handBack,
    sendInput,
    frame,
    setupReview,
    setupStart,
    jobStatus,
    jobCancel,
    list,
    stopById,
    deleteReview,
    deleteWorkspace,
    dispose,
  };
}
