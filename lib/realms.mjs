// Realm semantics on top of the native runtime: who may do what to which thread's desktop.
//
// Identity comes only from the host's verified `invocation.caller`. An agent acts on its own
// owner's Realm (the verified subagent ancestor, when supplied); `context.threadId` is a requested target and must agree with it. A person
// using a client operates the environment and may manage any thread's Realm.
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { RealmError } from "./runtime.mjs";
import { createSetupContinuation } from "./setupContinuation.mjs";
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

// Leaves room inside the host's 30 s invocation deadline for the calls around the wait.
const START_WAIT_MS = 12_000;
const COMMAND_WAIT_MAX_MS = 20_000;
const POLL_MS = 250;
// The pinned driver installs within this wait, so the agent's own call carries on and starts the Realm.
const AUTO_INSTALL_WAIT_MS = 12_000;
const AUTO_INSTALL_KEY = "auto-install-v1";
const REMOVE_PHRASE = "remove everything";
const SETUP_JOBS = new Set(["setup", "vm_setup", "driver_install"]);
const ACTIVE_RECORDS = new Set(["running", "starting", "stopping"]);
const KIND_LABELS = { realm: "Desktop Realm", "omarchy-vm": "Omarchy VM" };
const jobIsActive = (job) => job.state === "queued" || job.state === "running";
const kindJobName = (kind) => (kind === "omarchy-vm" ? "vm_setup" : "setup");
const setupBlockers = (plan) => [...new Set([...(plan.blockers ?? plan.missing ?? []), ...(plan.resources?.blockers ?? [])])];
const MAX_ASSETS = 40;
const MAX_INPUT_EVENTS = 64;
const MAX_TEXT_RESULT = 60_000;
// The host rejects results over 128 KB; JSON escaping and UTF-8 make characters a poor proxy.
const RESULT_BUDGET_BYTES = 100_000;
const INPUT_RENEW_MS = 30_000;
const IMAGE_LIMIT = 4 * 1024 * 1024;
const checkSignal = (signal) => { if (signal?.aborted) throw new RealmError("cancelled", "The Realm request was cancelled before admission. Inspect status before deciding on a new request."); };

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
  if (jsonBytes({ ...result, data }) > RESULT_BUDGET_BYTES)
    return { message: "Realm result details exceeded the host budget and were withheld. Inspect status/job progress; do not replay uncertain input.",
      data: { ...(data.job_id ? { jobId: data.job_id } : {}), ...(data.jobId ? { jobId: data.jobId } : {}), state: data.state, truncated: true } };
  return truncated ? { ...result, data: { ...data, truncated: true } } : result;
}

const ownership = (message) => new RealmError("ownership", message);
const invalid = (message) => new RealmError("invalid_input", message);
const sleep = (ms, signal) => new Promise((resolve, reject) => {
  checkSignal(signal);
  const abort = () => { clearTimeout(timer); reject(new RealmError("cancelled", "The Realm wait was cancelled. Inspect status before a new request.")); };
  const timer = setTimeout(() => { signal?.removeEventListener("abort", abort); resolve(); }, ms);
  signal?.addEventListener("abort", abort, { once: true });
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
// Host storage keys allow only [a-zA-Z0-9._-] and 128 characters; thread and Realm ids are opaque.
const storageKey = (kind, id) => `${kind}.${createHash("sha256").update(id).digest("hex")}`;
const preferenceKey = (threadId) => storageKey("thread", threadId);
const controlKey = (realmId) => storageKey("control", realmId);
const driverKey = (realmId) => storageKey("driver", realmId);
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
      throw ownership("This Realm call must use your own thread as caller context. Omit the thread override or use your own thread; verified subagent ownership automatically selects the parent shared Realm.");
    if (caller.lineage === "unresolved")
      throw new RealmError("lineage_unresolved", "Verified Realm lineage is unresolved; no Realm was allocated. Retry realm status after 2 seconds. If it remains unresolved, ask the person to inspect thread lineage in T3 Code.");
    const owner = caller.subagentOf ?? caller.threadId;
    return { kind: "agent", threadId: owner, ...(owner !== caller.threadId ? { sourceThreadId: caller.threadId, sharedFrom: owner } : {}) };
  }
  if (caller.kind === "client") {
    const threadId = invocation.context?.threadId ?? input.threadId;
    if (threadId !== undefined && (typeof threadId !== "string" || !threadIdPattern.test(threadId)))
      throw invalid("Unknown thread.");
    const owner = threadId !== undefined && invocation.context?.threadId === threadId ? (invocation.context?.subagentOf ?? threadId) : threadId;
    return { kind: "user", threadId: owner, ...(owner !== threadId ? { sourceThreadId: threadId, sharedFrom: owner } : {}) };
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

export function createRealms({ runtime, storage, settings, dataDirectory, connectCua, connectRfb, sendThread, cards = false, now = () => Date.now() }) {
  const cuaSessions = new Map();
  // The driver's MCP endpoint is a proxy to a `serve` daemon on the Realm's private socket.
  // The daemon runs as a job inside the Realm's own scope, so it ends with the Realm.
  // Its job id is kept in plugin storage so a restarted worker can still stop it.
  const cuaPending = new Map();
  const driverRetiring = new Map();
  const rfbClients = new Map();
  const locks = new Map();
  let doctorCache;
  let disposed = false;

  const locked = async (key, task, signal) => {
    const previous = locks.get(key) ?? Promise.resolve();
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    const chained = previous.then(() => current);
    locks.set(key, chained);
    await previous;
    try {
      checkSignal(signal);
      return await task();
    } finally {
      release();
      if (locks.get(key) === chained) locks.delete(key);
    }
  };

  let configCache;
  const config = async ({ fresh = false } = {}) => {
    if (!fresh && configCache && now() - configCache.at < 5_000) return configCache.value;
    const keys = ["size", "idleMinutes", "renderer", "vmMemory", "vmCPUs", "vmDiskSize", "vmNetwork", "vmRetentionDays", "vmRelease"];
    const values = await Promise.all(keys.map((key) => settings.get(key)));
    const [size, minutes, renderer, memory, cpus, disk, network, retention, release] = values;
    const value = { size: String(size ?? "1920x1080"), idle_ttl: Number(minutes ?? 30) * 60,
      renderer: String(renderer ?? "gles2"), vm: { memory: memory ?? 3072, cpus: cpus ?? 2,
        disk_size: disk ?? "40G", network: network ?? true, workspace_retention_days: retention ?? 14,
        release: release ?? "4.0.4" } };
    configCache = { at: now(), value };
    return value;
  };
  const selectedKind = async (threadId, requested) => {
    const kind = requested ?? (threadId ? (await preference(threadId))?.kind : undefined) ?? "realm";
    if (!["realm", "omarchy-vm"].includes(kind)) throw invalid("kind must be realm or omarchy-vm.");
    return kind;
  };

  const preference = async (threadId) => {
    const stored = await storage.get(preferenceKey(threadId));
    if (!stored || typeof stored !== "object" || Array.isArray(stored)) return null;
    return { ...stored, kind: ["realm", "omarchy-vm"].includes(stored.kind) ? stored.kind : "realm" };
  };
  const setPreference = (threadId, value) => storage.set(preferenceKey(threadId), { ...value, updatedAt: new Date(now()).toISOString() });
  // Control belongs to one desktop incarnation; a restarted Realm starts uncontrolled.
  const control = async (record) => {
    const held = (await storage.get(controlKey(record.id))) ?? null;
    if (held && held.generation !== (record.compute_generation ?? record.generation)) {
      await storage.delete(controlKey(record.id));
      return null;
    }
    return held;
  };
  const lastInputRenewal = new Map();

  const doctor = async ({ fresh = false, signal, kind = "realm" } = {}) => {
    if (!fresh && doctorCache?.kind === kind && now() - doctorCache.at < 15_000) return doctorCache.value;
    const value = await runtime.call("doctor", { config: { ...await config(), kind } }, { signal });
    doctorCache = { at: now(), value, kind };
    return value;
  };
  const setupSummary = (report) => ({
    ready: report.ready === true,
    missing: report.missing ?? [],
    driver: report.driver ?? null,
    message: report.message ?? (report.ready ? "Ready" : "Setup required"),
  });
  const requireSetup = async (signal, kind = "realm", who) => {
    const report = await doctor({ signal, kind });
    if (report.ready === true) return;
    doctorCache = undefined;
    if (who?.kind === "agent") return provision(who, kind, signal);
    throw new RealmError(
      "setup_required",
      `${report.message ?? "Realms setup is not complete."} A person must complete setup in the Realm panel to inspect prerequisites/blockers; never substitute the physical desktop.`,
    );
  };

  const autoInstall = async () => (await storage.get(AUTO_INSTALL_KEY)) !== false;
  const setupJobs = async (signal) => (await runtime.call("job_list", {}, { signal }))
    .filter((job) => SETUP_JOBS.has(job.kind)).sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0));
  // One card per setup attempt, however many calls hit it. Storage failing costs only the card.
  const setupCard = async (who, kind, attempt, summary) => {
    if (!cards) return undefined;
    const key = storageKey("setup-card", `${who.sourceThreadId ?? who.threadId}:${kind}`);
    if (await storage.get(key) === attempt) return undefined;
    await storage.set(key, attempt);
    return { viewId: "setup", summary: summary.slice(0, 1000), data: { kind } };
  };
  const personCan = (action) => cards
    ? `A card in this conversation lets a person ${action}.`
    : `A person can ${action} in the Realm panel: Realm in the thread menu.`;
  const setupStop = async (who, kind, code, message, { attempt, summary, jobId }) => {
    const error = new RealmError(code, `${message} Never substitute the physical desktop.`);
    error.setupKind = kind;
    error.setupJobId = jobId;
    error.card = await setupCard(who, kind, attempt, summary).catch(() => undefined);
    return error;
  };
  /** Everything without root installs itself; what needs a person becomes a card in the agent's chat. */
  const provision = async (who, kind, signal) => {
    const label = KIND_LABELS[kind];
    // Listing jobs first reconciles dead ones, so the plan's halt includes them.
    const jobs = await setupJobs(signal);
    const plan = await setupPlan(signal, kind);
    if (plan.ready) return;
    let job = jobs.find(jobIsActive);
    if (!job) {
      const blockers = setupBlockers(plan);
      const attempt = plan.reviewId;
      if (blockers.length)
        throw await setupStop(who, kind, "setup_required", `The ${label} can't be set up yet: ${blockers.join("; ")}. A person must fix this on the machine running T3 Code. Continue other work and tell them what you need.`,
          { attempt, summary: `${label} needs a person: ${blockers.join("; ")}` });
      if (plan.packages?.length)
        throw await setupStop(who, kind, "setup_required", `The ${label} needs system packages (${plan.packages.join(", ")}), which need a person's password. ${personCan("install them")} Continue other work and tell them what you need.`,
          { attempt, summary: `${label} needs system packages: ${plan.packages.join(", ")}` });
      // A cancelled or failed install stays stopped until a person retries it.
      if (plan.halt)
        throw await setupStop(who, kind, "setup_required", `${label} setup ${plan.halt.state === "failed" ? `failed: ${plan.halt.error ?? "unknown error"}` : "was cancelled by a person"}. ${personCan("retry it")} It won't restart by itself.`,
          { attempt: plan.halt.job_id, summary: `${label} setup ${plan.halt.state}.` });
      if (!await autoInstall())
        throw await setupStop(who, kind, "setup_required", `Automatic installs are turned off. ${personCan(`approve the ${label}`)} Continue other work and tell them what you need.`,
          { attempt, summary: `${label} is waiting for approval.` });
      try {
        job = await runtime.call("job_start", { kind: kindJobName(kind), input: { config: { ...await config(), kind }, review_id: plan.reviewId, unattended: true } }, { signal });
      } catch (error) {
        if (error.code !== "busy") throw error;
        job = (await setupJobs(signal)).find(jobIsActive);
        if (!job) throw error;
      }
    }
    const result = await waitForJob(job.job_id, kind === "realm" ? AUTO_INSTALL_WAIT_MS : 0, signal);
    if (result.state === "succeeded") {
      doctorCache = undefined;
      if ((await doctor({ fresh: true, signal, kind })).ready === true) return;
    }
    if (jobIsActive(result))
      throw await setupStop(who, kind, "preparing", kind === "omarchy-vm"
        ? `The ${label} is being prepared in the background: about a 5 GiB download and a 15–30 minute install. Nothing needs doing. Use kind "realm" for work in the meantime, and you'll get a message here when it's ready.`
        : `The ${label} is still installing. Call realm status after a few seconds.`,
      { attempt: job.job_id, summary: `Preparing the ${label}.`, jobId: job.job_id });
    throw await setupStop(who, kind, "setup_required", `${label} setup didn't finish: ${result.error ?? result.code ?? "it did not verify ready"}. ${personCan("retry it")}`,
      { attempt: job.job_id, summary: `${label} setup didn't finish.` });
  };

  const continuations = createSetupContinuation({
    storage, locked, now, sendThread,
    authorized: async (entry) => {
      const pref = await preference(entry.ownerThreadId);
      if (pref?.mode === "off" || (!entry.unattended && await selectedKind(entry.ownerThreadId) !== entry.kind)) return false;
      const record = await current(ownerKey(entry.ownerThreadId));
      return !record || !await control(record);
    },
    ready: async (kind) => (await doctor({ fresh: true, kind })).ready === true,
    jobStatus: (jobId) => runtime.call("job_status", { job_id: jobId }),
  });
  const observeContinuation = async (who, job) => {
    try { return await continuations.observe(who, job) ?? []; }
    catch (error) { return [{ state: "unavailable", manualContinuationRequired: true,
      message: `Automatic continuation could not be checked: ${String(error.message).slice(0, 500)}. After setup is ready, ask the agent to continue manually in the requesting thread. No old command was replayed.` }]; }
  };
  const invalidateContinuation = async (threadId, options) => { try { await continuations.invalidate(threadId, options); } catch { /* Optional notification bookkeeping cannot prevent an authoritative revocation. */ } };
  const settleContinuation = async (...args) => { try { await continuations.settle(...args); } catch { /* A stale entry can only cost one extra prompt. */ } };
  const approveContinuation = async (...args) => { try { await continuations.approve(...args); } catch { /* Setup remains successful; observation exposes the manual continuation fallback. */ } };
  const agentRequest = async (who, task) => {
    try { return await task(); }
    catch (error) {
      if (who.kind === "agent" && error instanceof RealmError && ["setup_required", "preparing"].includes(error.code) && !error.continuationSaved) {
        error.continuationSaved = true;
        const kind = error.setupKind ?? await selectedKind(who.threadId);
        try {
          await continuations.record(who, kind);
          if (error.setupJobId) await continuations.approve(kind, error.setupJobId, { unattended: true });
        } catch (warning) {
          const wrapped = new RealmError(error.code, `${error.message} Automatic setup-resume notification could not be saved: ${String(warning.message).slice(0, 500)}. A person must complete Realms setup, then ask the agent to continue manually.`);
          wrapped.card = error.card;
          wrapped.continuationSaved = true;
          throw wrapped;
        }
      }
      throw error;
    }
  };

  const records = async (owner, signal) => runtime.call("list", { ...(owner ? { owner } : {}), config: await config() }, { signal });
  const current = async (owner, signal, kind) => {
    kind ??= await selectedKind(threadOf(owner));
    const all = (await records(owner, signal)).filter((r) => (r.kind ?? "realm") === kind);
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
  const stopDriverDaemon = (record, signal) => {
    if (driverRetiring.has(record.id)) return driverRetiring.get(record.id);
    const retiring = (async () => {
      if (record.kind !== "omarchy-vm") {
        try {
          const result = await runtime.call("driver_stop", { id: record.id, owner: record.owner ?? record.session_id,
            incarnation: record.compute_generation ?? record.generation }, { signal });
          if (result?.retired !== true) throw new Error("Native retirement was not confirmed");
          await storage.delete(driverKey(record.id));
          await storage.delete(storageKey("driver-cleanup", threadOf(record.owner ?? record.session_id)));
          return;
        } catch (error) {
          throw new RealmError("driver_unavailable", `Realm GUI-driver retirement is unconfirmed: ${error.message}. A person must Stop this Realm before reconnecting; the workspace is retained. Do not replay uncertain input.`);
        }
      }
      const daemon = await storage.get(driverKey(record.id));
      if (!daemon || daemon.generation !== (record.compute_generation ?? record.generation)) return;
      await runtime.call("signal", { id: record.id, owner: record.owner ?? record.session_id,
        job_id: daemon.jobId, signal: 15 }, { signal }).catch(() => undefined);
      if (record.kind === "omarchy-vm") {
        const deadline = now() + 20_000;
        for (;;) {
          const state = await runtime.call("job", { id: record.id, owner: record.owner ?? record.session_id,
            job_id: daemon.jobId }, { signal });
          if (state.returncode !== null && state.returncode !== undefined) {
            if (state.returncode !== 0) throw new RealmError("driver_unavailable", "Guest driver retirement was not confirmed. Stop this VM before reconnecting; do not replay input.");
            break;
          }
          if (now() >= deadline) throw new RealmError("busy", "The guest driver is still retiring. Retry Repair before reconnecting.");
          await sleep(POLL_MS, signal);
        }
      }
      await storage.delete(driverKey(record.id));
    })();
    driverRetiring.set(record.id, retiring);
    return retiring.finally(() => {
      if (driverRetiring.get(record.id) === retiring) driverRetiring.delete(record.id);
    });
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
          : "Realm use is off for this thread. Turn it on with action \"on\" only if another private test is needed; there is nothing to exit for ordinary work.",
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
        `This Realm call is paused by a person-controlled hold on ${record.id}, shared owner ${threadOf(record.owner ?? record.session_id)}. Do not inspect or drive this Realm through alternate tools. Ask the person to click Hand back in the Realm panel, including if their takeover connection failed or closed; retries cannot release the hold.`,
      );
  };

  const authorityKey = (threadId) => storageKey("authority", threadId);
  const revoke = async (threadId, code, message) => {
    await storage.set(authorityKey(threadId), { epoch: randomUUID(), code, message });
    for (const [id, pending] of cuaPending) if (pending.owner === threadId) {
      pending.revoked = { code, message };
      pending.controller.abort();
      cuaPending.delete(id);
    }
  };
  const admission = async (who, record) => {
    if (disposed) throw new RealmError("cancelled", "This Realm worker was disposed. Make a fresh status request through the current worker.");
    await agentAllowed(who);
    await agentNotControlled(who, record);
    return (await storage.get(authorityKey(who.threadId)))?.epoch ?? null;
  };
  const admitted = async (who, record, epoch, signal) => {
    checkSignal(signal);
    await agentAllowed(who);
    await agentNotControlled(who, record);
    const token = await storage.get(authorityKey(who.threadId));
    if (disposed) throw new RealmError("cancelled", "This Realm worker was disposed. Request status through the current worker.");
    if (token && token.epoch !== epoch) throw new RealmError(token.code, `${token.message} Any result from the previous request was withheld. Input may already have landed; do not replay it. Inspect status and take a fresh capture after access is restored.`);
    const live = await current(ownerKey(who.threadId), signal);
    if (!live || live.status !== "running" || live.id !== record.id || (live.compute_generation ?? live.generation) !== (record.compute_generation ?? record.generation))
      throw new RealmError("changed", "This Realm compute or selected kind changed during the call. Its result was withheld. Inspect status and take a fresh capture before a new request; do not replay uncertain input.");
    await agentAllowed(who);
    await agentNotControlled(who, record);
    const finalToken = await storage.get(authorityKey(who.threadId));
    if (finalToken && finalToken.epoch !== epoch) throw new RealmError(finalToken.code, `${finalToken.message} Previous results were withheld; inspect status and take a fresh capture. Do not replay uncertain input.`);
  };
  // A VM keeps this flag while compute is allocated; only retired/failed states imply uncertainty.
  const cleanupUnconfirmed = (record) => record?.cleanup_required === true &&
    !(record.kind === "omarchy-vm" && ["starting", "running", "stopping"].includes(record.status));
  const recoveryStep = (record) => cleanupUnconfirmed(record) || record?.status === "cleanup_failed"
    ? "Compute retirement/cleanup is unconfirmed. A person must inspect ownership/cleanup permissions and retry Stop; do not reconnect or discard."
    : "Preserve and recover retained data with a person. GUI Repair/on cannot fix these files; use reviewed Discard only if the person chooses to delete them.";
  const requireRecoverable = (record) => {
    if (record && (cleanupUnconfirmed(record) || ["recovery-required", "cleanup_failed", "deleting"].includes(record.status)))
      throw new RealmError("recovery_required", `This Realm requires recovery: ${record.recovery_reason ?? record.error ?? record.cleanup_note ?? record.status}. ${recoveryStep(record)}`);
  };
  const latestJob = async (owner, kind, signal, match = () => true) =>
    (await runtime.call("job_list", { owner }, { signal })).filter((job) => job.kind === kind && match(job)).reverse()
      .sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0)).at(0) ?? null;
  const startFailure = (job) => new RealmError(job.code ?? "failed", `This Realm start job ${job.job_id} ${job.state}: ${job.error ?? job.state}. No requested command was launched. Inspect/report this cause; use realm action "on" only after deciding to request one new start.`);
  const jobSummary = (job) => job ? { jobId: job.job_id, state: job.state, code: job.code ?? null,
    error: String(job.error ?? "").slice(0, 2000) || null,
    progress: jsonBytes(job.progress ?? null) < 4000 ? job.progress ?? null : { message: "Progress details shortened; inspect the job." },
    retryAfterSeconds: ["queued", "running"].includes(job.state) ? 2 : null,
    nextStep: ["queued", "running"].includes(job.state) ? "Call realm status after 2 seconds." : job.state === "succeeded" ? "Take a fresh capture before input." : "Inspect/report this cause; explicitly request on for a new boot or repair for new driver preparation." } : null;
  const retainJob = async (key, job) => {
    const summary = jobSummary(job);
    const previous = await storage.get(key);
    if (JSON.stringify(previous) !== JSON.stringify(summary)) await storage.set(key, summary);
    return job;
  };
  const retainedJob = async (key, owner, kind, signal, match) => {
    const job = await latestJob(owner, kind, signal, match);
    if (job) return retainJob(key, job);
    const cached = await storage.get(key);
    if (!cached) return null;
    const retained = { ...cached, job_id: cached.jobId };
    if (["queued", "running"].includes(retained.state)) {
      retained.state = "failed"; retained.code = "outcome_unknown";
      retained.error = "Native job history no longer contains this pending attempt; its outcome is unknown. Inspect current Realm state before one explicit retry.";
      await retainJob(key, retained);
    }
    return retained;
  };
  const startKey = (threadId, kind) => storageKey("start-attempt", `${threadId}:${kind}`);
  const latestStart = (owner, kind, signal) => retainedJob(startKey(threadOf(owner), kind), owner, "start", signal,
    (job) => (job.input?.config?.kind ?? "realm") === kind);
  const stagingKey = (record) => storageKey("driver-preparation", `${record.id}:${record.compute_generation ?? record.generation}`);
  const stagingJob = (record, signal) => record?.kind === "omarchy-vm" ? retainedJob(stagingKey(record), record.owner ?? record.session_id, "vm_driver", signal,
    (job) => job.input?.id === record.id && job.input?.incarnation === (record.compute_generation ?? record.generation)) : null;

  const waitForJob = async (jobId, waitMs, signal) => {
    const deadline = now() + waitMs;
    for (;;) {
      const job = await runtime.call("job_status", { job_id: jobId }, { signal });
      if (!["queued", "running"].includes(job.state) || now() >= deadline) return job;
      await sleep(POLL_MS, signal);
    }
  };

  /** Start or reuse this thread's desktop. Never substitutes another thread's or the host's. */
  const ensureRunning = async (threadId, { signal, waitMs = START_WAIT_MS, retry = false, who } = {}) => {
    const owner = ownerKey(threadId);
    const kind = await selectedKind(threadId);
    const record = await current(owner, signal, kind);
    requireRecoverable(record);
    if (record?.status === "running") {
      await runtime.call("touch", { id: record.id, owner }, { signal });
      return { record };
    }
    await requireSetup(signal, kind, who);
    if (who?.kind === "agent") await settleContinuation(threadId, kind);
    const previous = await latestStart(owner, kind, signal);
    if (!retry && previous && !["queued", "running", "succeeded"].includes(previous.state)) throw startFailure(previous);
    const active = await activeStartJob(owner, signal);
    if (active?.input?.config?.kind && active.input.config.kind !== kind) {
      await runtime.call("job_cancel", { job_id: active.job_id }, { signal });
      return { starting: active };
    }
    const job = active ?? {
      job_id: (await runtime.call("job_start", { kind: "start", owner, input: { config: { ...await config(), kind } } }, { signal })).job_id,
    };
    const result = await waitForJob(job.job_id, waitMs, signal);
    await retainJob(startKey(threadId, kind), result);
    if (result.state === "succeeded") {
      const started = await current(owner, signal);
      if (started?.status !== "running") throw new RealmError("failed", "The Realm stopped right after starting.");
      return { record: started };
    }
    if (result.state === "queued" || result.state === "running") return { starting: result };
    throw startFailure(result);
  };
  const requireRunning = async (threadId, signal) => {
    const record = await current(ownerKey(threadId), signal);
    requireRecoverable(record);
    if (record?.status !== "running")
      throw new RealmError("not_running", 'This thread\'s Realm is not running. Inspect realm status; use action "on" for a new start if a private desktop is still needed. Nothing falls back to the host desktop.');
    return record;
  };
  const runningForAgent = async (who, signal) => {
    await agentAllowed(who);
    // A start decision races a person's Stop or a sibling call without the thread lock.
    const started = await agentRequest(who, () => locked(who.threadId, async () => {
      checkSignal(signal);
      await agentAllowed(who);
      return ensureRunning(who.threadId, { signal, who });
    }));
    if (!started.record)
      throw new RealmError("starting", `The Realm is still starting (job ${started.starting.job_id}). Call realm status after 2 seconds; wait while this job is pending, and inspect a terminal failure before explicitly retrying on.`);
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
    if (record.status !== "running" || cuaSessions.get(record.id)?.generation !== (record.compute_generation ?? record.generation)) dropSessions(record.id);
    if (record.status !== "running") dropControlConnection(record.id);
    let windows = null;
    if (record.status === "running") {
      windows =
        (await runtime.call("windows", { id: record.id, owner: record.owner ?? record.session_id }).catch(() => ({ count: null })))
          .count ?? null;
    }
    return {
      id: record.id,
      kind: record.kind ?? "realm",
      needsRecovery: cleanupUnconfirmed(record) || ["recovery-required", "cleanup_failed"].includes(record.status),
      cleanupRequired: cleanupUnconfirmed(record) || record.status === "cleanup_failed",
      nextStep: cleanupUnconfirmed(record) || ["recovery-required", "cleanup_failed"].includes(record.status) ? recoveryStep(record) : null,
      controlConnection: held ? held.connection === "failed" ? "failed" : rfbClients.get(record.id)?.closed === false ? "connected" : "disconnected" : null,
      controlConnectionError: held?.connectionError ?? null,
      recoveryReason: typeof record.recovery_reason === "string" ? record.recovery_reason.slice(0, 1000) : null,
      memoryMiB: record.memory ?? null,
      network: record.network ?? null,
      state: record.status === "running" ? "live" : record.status,
      size: record.size ?? null,
      windowCount: windows,
      createdAt: record.created_at ?? null,
      lastActivity: record.last_activity ?? null,
      idleTtlSeconds: record.idle_ttl ?? null,
      controlledBy: held ? "user" : null,
      error: String(record.error ?? record.cleanup_note ?? "").slice(0, 1000) || null,
    };
  };

  const status = async (who, { signal } = {}) => {
    const continuation = await observeContinuation(who);
    const threadId = requireThread(who);
    const owner = ownerKey(threadId);
    const kind = await selectedKind(threadId);
    let runtimeFailure = null;
    const [pref, record, job, report] = await Promise.all([
      preference(threadId),
      current(owner, signal).catch((error) => {
        runtimeFailure = { code: error.code ?? "runtime_unavailable", error: String(error.message).slice(0, 2000),
          nextStep: "Ask the person to inspect the reported runtime/cleanup problem, then retry exact Stop for the affected Realm. Ordinary provider tools are unaffected; continue other work." };
        return null;
      }),
      activeStartJob(owner, signal),
      doctor({ signal, kind }).catch((error) => ({ ready: false, message: error.message })),
    ]);
    const setupJob = report.ready === true ? null : (await setupJobs(signal).catch(() => [])).find(jobIsActive) ?? null;
    const startAttempt = await latestStart(owner, kind, signal);
    const driverPreparation = await stagingJob(record, signal);
    const driverCleanup = await storage.get(storageKey("driver-cleanup", threadId));
    return {
      runtimeFailure,
      driverCleanup: record && record.status !== "stopped" && driverCleanup?.incarnation === (record.compute_generation ?? record.generation) ? driverCleanup : null,
      continuation,
      startAttempt: jobSummary(startAttempt),
      driverPreparation: jobSummary(driverPreparation),
      terminalJobs: await terminalReceipts(record),
      threadId: who.sourceThreadId ?? threadId,
      ownerThreadId: threadId,
      sharedFrom: who.sharedFrom ?? null,
      mode: pref?.mode ?? "unset",
      offBy: pref?.mode === "off" ? (pref.setBy ?? null) : null,
      kind,
      setup: { ...setupSummary(report), job: setupJob ? { jobId: setupJob.job_id, kind: setupJob.kind, state: setupJob.state, progress: setupJob.progress ?? null } : null },
      realm: await describeRealm(record),
      starting: job ? { jobId: job.job_id, progress: job.progress ?? null } : null,
    };
  };

  const baseSummary = (state) => {
    const realm = state.realm;
    const label = state.kind === "omarchy-vm" ? " · omarchy realm" : "";
    const mode = (state.mode === "off" ? "Realm off" : state.mode === "realm" ? "Realm on" : "Realm available") + label;
    if (state.runtimeFailure) return `${mode} · runtime failed: ${state.runtimeFailure.error}. ${state.runtimeFailure.nextStep}`;
    if (state.driverCleanup) return `${mode} · driver cleanup failed: ${state.driverCleanup.error}. ${state.driverCleanup.nextStep}`;
    if (!state.setup.ready) return `${mode} · ${state.setup.job ? "preparing in the background" : "setup required"}`;
    if (realm?.needsRecovery) return `${mode} · ${realm.state}: ${realm.nextStep} Cause: ${realm.recoveryReason ?? realm.error ?? "unknown"}`;
    if (state.starting) return `${mode} · starting (call status after 2 seconds)`;
    if (state.startAttempt && !["queued", "running", "succeeded"].includes(state.startAttempt.state) && realm?.state !== "live") return `${mode} · start ${state.startAttempt.state}: ${state.startAttempt.error ?? state.startAttempt.code}. ${state.startAttempt.nextStep}`;
    if (state.driverPreparation && !["queued", "running", "succeeded"].includes(state.driverPreparation.state)) return `${mode} · driver ${state.driverPreparation.state}: ${state.driverPreparation.error}. ${state.driverPreparation.nextStep}`;
    if (!realm) return `${mode} · not started`;
    const windows = realm.windowCount === null ? "" : ` (${realm.windowCount} window${realm.windowCount === 1 ? "" : "s"})`;
    return `${mode} · ${realm.state}${windows}${realm.controlledBy ? " · user in control" : ""}`;
  };

  const summary = (state) => baseSummary(state) + (state.sharedFrom ? ` · shared from ${state.sharedFrom}` : "");

  /** The compact thread status: quiet unless this thread uses a Realm. Cheap enough to poll. */
  const badge = async (who, opts = {}) => {
    await observeContinuation(who);
    const value = await baseBadge(who, opts);
    if (!value) return value;
    const shared = who.sharedFrom ? ` Shared from ${who.sharedFrom}.` : "";
    return { ...value, detail: `${value.detail ?? ""}`.slice(0, 300 - shared.length) + shared };
  };
  const baseBadge = async (who, { signal } = {}) => {
    const threadId = requireThread(who);
    const owner = ownerKey(threadId);
    const [pref, all, jobs] = await Promise.all([
      preference(threadId),
      records(owner, signal),
      runtime.call("job_list", { owner }, { signal }),
    ]);
    for (const record of all) if (record.status !== "running" || cuaSessions.get(record.id)?.generation !== (record.compute_generation ?? record.generation)) dropSessions(record.id);
    const failed = jobs.filter((job) => job.kind === "start").sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0))[0];
    const live = all.find((record) => record.status === "running");
    const starting = jobs.some((job) => job.kind === "start" && ["queued", "running"].includes(job.state));
    const agentUse = pref?.mode === "off" ? "Agent use is off" : "Agent can use it";
    if (live) {
      if (await control(live))
        return { label: "You have control", tone: "warning", detail: "Agent access to this Realm is paused. Hand back restores it, including after a failed viewer connection. Ordinary work can continue." };
      return { label: pref?.mode === "off" ? "Live · agent off" : "Live", tone: "success", detail: `${live.size ?? ""} desktop. ${agentUse}.`.trim() };
    }
    const recovery = all.find((record) => cleanupUnconfirmed(record) || ["recovery-required", "cleanup_failed"].includes(record.status));
    if (recovery) return { label: "Needs recovery", tone: "warning", detail: `${recoveryStep(recovery)} Cause: ${recovery.recovery_reason ?? recovery.error ?? recovery.status}` };
    if (failed && !["queued", "running", "succeeded"].includes(failed.state)) return { label: "Start failed", tone: "warning", detail: `${failed.error ?? failed.state}. Inspect status; explicitly request On after deciding to retry.` };
    if (starting) return { label: "Starting", tone: "info", detail: "Starting this thread's private desktop." };
    if (pref?.mode === "realm") {
      const report = await doctor({ signal, kind: pref.kind ?? "realm" }).catch(() => ({ ready: false }));
      if (report.ready !== true) {
        if ((await setupJobs(signal).catch(() => [])).some(jobIsActive))
          return { label: "Preparing", tone: "info", detail: "Installing what this Realm needs." };
        return { label: "Setup needed", tone: "warning", detail: "Open the Realm panel to review setup." };
      }
      return all.length
        ? { label: "Stopped", tone: "neutral", detail: "Workspace kept. It starts again when needed." }
        : { label: "On", tone: "neutral", detail: "Starts when the agent needs a desktop." };
    }
    if (pref?.mode === "off") return { label: "Off", tone: "neutral", detail: "Agent use is off for this thread." };
    return null;
  };

  const on = (who, input, { signal } = {}) =>
    agentRequest(who, () => locked(requireThread(who), async () => {
      checkSignal(signal);
      const kind = await selectedKind(who.threadId, input.kind);
      const pref = await preference(who.threadId);
      if (who.kind === "agent" && pref?.mode === "off" && pref.setBy === "user") await agentAllowed(who);
      const old = await current(ownerKey(who.threadId), signal);
      if (old) await agentNotControlled(who, old);
      // Persist a requested kind even when setup is still required, so its panel offers the right review.
      if (pref?.kind !== kind) {
        await revoke(who.threadId, "changed", "This Realm kind changed. Inspect status before a fresh request.");
        await invalidateContinuation(who.threadId, { keepUnattended: true });
        const pending = await activeStartJob(ownerKey(who.threadId), signal);
        if (pending) await runtime.call("job_cancel", { job_id: pending.job_id }, { signal });
        if (old?.status === "running" || old?.status === "starting") {
          const job = await activeStartJob(ownerKey(who.threadId), signal);
          if (job) await runtime.call("job_cancel", { job_id: job.job_id }, { signal });
          dropSessions(old.id); dropControlConnection(old.id);
          await runtime.call("stop", { id: old.id, owner: ownerKey(who.threadId) }, { signal });
        }
      }
      await setPreference(who.threadId, { mode: "realm", kind, setBy: who.kind });
      await requireSetup(signal, kind, who);
      await ensureRunning(who.threadId, { signal, retry: true, who });
      if (who.kind === "agent") await settleContinuation(who.threadId, kind);
      return status(who, { signal });
    }));

  const off = (who, { signal } = {}) =>
    locked(requireThread(who), async () => {
      checkSignal(signal);
      await invalidateContinuation(who.threadId);
      checkSignal(signal);
      await revoke(who.threadId, "disabled", "Agent access to this Realm was turned Off. Ask the person to turn it On if a private test is still needed.");
      const pref = await preference(who.threadId);
      // An agent's off cannot replace a person's, or it could then turn the Realm back on.
      if (!(who.kind === "agent" && pref?.mode === "off" && pref.setBy === "user"))
        await setPreference(who.threadId, { mode: "off", kind: pref?.kind ?? "realm", setBy: who.kind });
      const record = await current(ownerKey(who.threadId), signal).catch(() => null);
      // Off revokes agent use only; the desktop, its workspace and anyone watching stay.
      if (record) {
        dropSessions(record.id);
        try { await stopDriverDaemon(record, signal); }
        catch (error) {
          await storage.set(storageKey("driver-cleanup", who.threadId), { state: "failed", code: error.code ?? "driver_unavailable",
            realmId: record.id, incarnation: record.compute_generation ?? record.generation,
            error: String(error.message).slice(0, 2000), nextStep: "A person must Stop this Realm before reconnecting its GUI driver. Workspace retained; continue ordinary work." });
        }
      }
      return status(who, { signal });
    });

  const stop = (who, { signal } = {}) =>
    locked(requireThread(who), async () => {
      checkSignal(signal);
      const owner = ownerKey(who.threadId);
      const job = await activeStartJob(owner, signal);
      await agentAllowed(who);
      const record = await current(owner, signal);
      if (record) await agentNotControlled(who, record);
      await revoke(who.threadId, "changed", "This Realm was stopped. Inspect status before a fresh request.");
      if (job) await runtime.call("job_cancel", { job_id: job.job_id }, { signal });
      if (record) {
        dropSessions(record.id);
        dropControlConnection(record.id);
        await storage.delete(controlKey(record.id));
      }
      await runtime.call("stop_owner", { owner }, { signal });
      return status(who, { signal });
    });

  const resize = (who, input, { signal } = {}) =>
    locked(requireThread(who), async () => {
      checkSignal(signal);
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
    await revoke(who.threadId, "changed", "This Realm GUI connection was repaired. Take a fresh capture.");
    dropSessions(record.id);
    await stopDriverDaemon(record, signal);
    const staging = await stagingJob(record, signal);
    if (staging && !["queued", "running", "succeeded"].includes(staging.state)) {
      const retried = await runtime.call("job_start", { kind: "vm_driver", owner: record.owner ?? record.session_id,
        input: { id: record.id, incarnation: record.compute_generation ?? record.generation } }, { signal });
      await retainJob(stagingKey(record), { job_id: retried.job_id, state: "queued" });
    }
    return {
      message: "GUI driver connection reset. The next computer action reconnects; take a fresh capture and check the app is where you left it. Nothing was replayed.",
    };
  };

  const assetFilename = (relative) => {
    if (typeof relative !== "string" || path.isAbsolute(relative) || path.dirname(relative) !== "assets" || !/^shot-[^/]+\.(jpg|jpeg|png)$/.test(path.basename(relative)))
      throw new RealmError("failed", "The Realm capture returned an invalid asset path. Ask the person to inspect the capture runtime.");
    return path.join(dataDirectory, relative);
  };
  const discardAsset = async (relative) => fs.rm(assetFilename(relative), { force: true });
  const capture = async (record, { quality, scale, signal }) => {
    const shot = await runtime.call(
      "shot",
      { id: record.id, owner: record.owner ?? record.session_id, format: "jpeg", quality, scale },
      { signal },
    );
    const filename = assetFilename(shot.path);
    const bytes = await fs.stat(filename).then((info) => info.size).catch((error) => {
      if (error.code === "ENOENT") return Number(shot.bytes ?? 0);
      throw error;
    });
    if (bytes > IMAGE_LIMIT) {
      await discardAsset(shot.path);
      throw new RealmError("image_too_large", "This Realm capture exceeds 4 MiB and was withheld. Request a smaller frame scale or use computer zoom for a smaller region, then take a fresh capture.");
    }
    await pruneAssets();
    return shot;
  };

  const shot = async (who, { signal } = {}) => {
    const threadId = requireThread(who);
    await agentAllowed(who);
    const record = await requireRunning(threadId, signal);
    const epoch = await admission(who, record);
    const result = await capture(record, { quality: 85, scale: 1, signal });
    try { await admitted(who, record, epoch, signal); }
    catch (error) { await discardAsset(result.path); throw error; }
    return {
      message: `Captured this thread's Realm (${result.width}x${result.height}).`,
      data: { realmId: record.id, width: result.width, height: result.height, sha256: result.sha256 },
      images: [{ path: result.path, mimeType: result.mimeType }],
    };
  };

  const terminalKey = (record) => storageKey("terminal", record.id);
  const terminalReceipts = async (record) => {
    if (!record) return [];
    const receipts = await storage.get(terminalKey(record));
    return (Array.isArray(receipts) ? receipts : []).filter((entry) => entry.incarnation === (record.compute_generation ?? record.generation)).slice(-20);
  };
  const rememberTerminal = (record, job) => locked(terminalKey(record), async () => {
    const entries = await terminalReceipts(record);
    const receipt = { jobId: job.job_id, incarnation: record.compute_generation ?? record.generation,
      nextStep: "Inspect using realm-terminal {jobId}; signal TERM only if you intend to end that job. Do not replay an uncertain command." };
    await storage.set(terminalKey(record), [...entries.filter((entry) => entry.jobId !== job.job_id), receipt].slice(-20));
  });
  const terminal = async (who, input, { signal } = {}) => {
    const threadId = requireThread(who);
    const owner = ownerKey(threadId);
    if (input.jobId !== undefined) {
      if (typeof input.jobId !== "string") throw invalid("jobId must be a string.");
      await agentAllowed(who);
      const record = await requireRunning(threadId, signal);
      const epoch = await admission(who, record);
      await admitted(who, record, epoch, signal);
      if (input.signal !== undefined) {
        const signals = { INT: 2, TERM: 15, KILL: 9, HUP: 1 };
        if (!(input.signal in signals)) throw invalid("signal must be INT, TERM, KILL or HUP.");
        await runtime.call("signal", { id: record.id, owner, job_id: input.jobId, signal: signals[input.signal] }, { signal });
      }
      const result = await runtime.call("job", { id: record.id, owner, job_id: input.jobId }, { signal });
      await admitted(who, record, epoch, signal);
      return commandResult(result);
    }
    const command = input.command;
    if (typeof command !== "string" || !command.trim() || command.length > 16_000)
      throw invalid("command must be a nonempty shell command.");

    if (input.cwd !== undefined && (typeof input.cwd !== "string" || !path.isAbsolute(input.cwd)))
      throw invalid("cwd must be an absolute path.");
    const record = await runningForAgent(who, signal);
    const refusal = record.kind === "omarchy-vm" ? null : hostEscape(command);
    if (refusal) throw new RealmError("host_escape", refusal);
    const epoch = await admission(who, record);
    await admitted(who, record, epoch, signal);
    let job;
    try { job = await runtime.call(
      "exec",
      { id: record.id, owner, argv: ["/bin/sh", "-c", command], ...(input.cwd ? { cwd: input.cwd } : {}) },
      { signal },
    ); } catch (error) {
      throw new RealmError(error.code ?? "failed", `This realm-terminal result is unknown: the command may already have started. Do not resubmit it blindly. Inspect Realm status and current command outputs; if admission has no job ID, report this uncertainty. Cause: ${error.message}`);
    }
    await rememberTerminal(record, job);
    try { await admitted(who, record, epoch, signal); }
    catch (error) {
      if (error.code === "human_control" || error.code === "disabled" || error.code === "changed")
        await runtime.call("signal", { id: record.id, owner, job_id: job.job_id, signal: 9 }, {}).catch(() => undefined);
      throw new RealmError(error.code ?? "failed", `${error.message} The admitted job ${job.job_id} may already have affected the Realm. Inspect it with realm-terminal {jobId:"${job.job_id}"} when access is restored; cancellation is not proof of retirement.`);
    }
    if (input.background === true)
      return {
        message: `Started in this thread's Realm as job ${job.job_id}. Poll it with jobId; results are kept for five minutes after exit.`,
        data: { jobId: job.job_id, pid: job.pid, background: true },
      };
    const waitMs = Math.min(COMMAND_WAIT_MAX_MS, Math.max(1, Number(input.timeoutSeconds ?? 15)) * 1000);
    const deadline = now() + waitMs;
    try { for (;;) {
      const state = await runtime.call("job", { id: record.id, owner, job_id: job.job_id }, { signal });
      await admitted(who, record, epoch, signal);
      if (state.returncode !== null && state.returncode !== undefined) return commandResult(state);
      if (now() >= deadline)
        return {
          message: `Still running as job ${job.job_id}. Poll it with jobId, or run GUI apps with background: true.`,
          data: { jobId: job.job_id, running: true },
        };
      await sleep(POLL_MS, signal);
    } } catch (error) {
      throw new RealmError(error.code ?? "failed", `${error.message} Realm job ${job.job_id} was admitted and may still be running. Its ID remains in realm status. Inspect realm-terminal {jobId:"${job.job_id}"}; do not blindly replay the command.`);
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
    const known = await storage.get(driverKey(record.id));
    if (known?.generation === (record.compute_generation ?? record.generation)) {
      const state = await runtime.call("job", { id: record.id, owner, job_id: known.jobId }, { signal }).catch(() => null);
      if (state && (state.returncode === null || state.returncode === undefined)) return;
      if (record.kind === "omarchy-vm" && (!state || state.returncode !== 0))
        throw new RealmError("driver_unavailable", "The previous guest driver did not confirm retirement. Stop this VM before reconnecting.");
    }
    const job = await runtime.call("exec", { id: record.id, owner, argv: [launcher.path, "serve"] }, { signal });
    const state = await runtime.call("job", { id: record.id, owner, job_id: job.job_id }, { signal });
    if (state.returncode !== null && state.returncode !== undefined)
      throw new RealmError("driver_unavailable", `The newly requested Realm driver exited; its identity was not adopted: ${String(state.stderr ?? state.returncode).slice(0, 1000)}. Use Repair once to retire the owned daemon/socket, then take a fresh capture. If retirement cannot be confirmed, ask the person to Stop this Realm before reconnecting.`);
    await storage.set(driverKey(record.id), { generation: record.compute_generation ?? record.generation, jobId: job.job_id });
  };
  // One connection attempt per Realm generation; concurrent callers wait for it.
  const checkPending = (pending) => {
    if (pending.revoked) throw new RealmError(pending.revoked.code, pending.revoked.message);
    if (disposed) throw new RealmError("cancelled", "This Realm worker was disposed; request status through the current worker.");
  };
  const cuaFor = (record, signal) => {
    const existing = cuaSessions.get(record.id);
    if (existing && existing.generation === (record.compute_generation ?? record.generation) && !existing.session.closed)
      return Promise.resolve(existing.session);
    let pending = cuaPending.get(record.id);
    if (!pending || pending.generation !== (record.compute_generation ?? record.generation)) {
      pending = { generation: record.compute_generation ?? record.generation, owner: threadOf(record.owner ?? record.session_id), controller: new AbortController() };
      pending.promise = connectCuaFor(record, pending).finally(() => {
        if (cuaPending.get(record.id) === pending) cuaPending.delete(record.id);
      });
      cuaPending.set(record.id, pending);
    }
    return signal ? abortable(pending.promise, signal) : pending.promise;
  };
  const connectCuaFor = async (record, pending) => {
    const signal = pending.controller.signal;
    try {
      await driverRetiring.get(record.id);
      checkPending(pending);
      dropSessions(record.id);
      const staging = await stagingJob(record, signal);
      if (staging && !["queued", "running", "succeeded"].includes(staging.state))
        throw new RealmError(staging.code ?? "driver_unavailable", `Guest GUI-driver preparation ${staging.state}: ${staging.error ?? staging.state}. No requested GUI input was sent. Inspect this cause, then request one realm repair to prepare again. Realm terminal/shot remain available.`);
      const launcher = await runtime.call("driver_launcher", { id: record.id, owner: record.owner ?? record.session_id }, { signal });
      checkPending(pending);
      if (launcher.starting) throw new RealmError("starting", `Preparing the guest GUI driver (job ${launcher.starting.job_id}). Call realm status after 2 seconds; wait while driverPreparation is pending, inspect failures before one explicit Repair, and take a fresh capture before new input.`);
      await locked(pending.owner, async () => {
        checkPending(pending);
        await ensureDriverDaemon(record, launcher, signal);
        checkPending(pending);
      }, signal);
      let lastError;
      for (let attempt = 0; attempt < 20; attempt++) {
        checkPending(pending);
        const session = connectCua(launcher);
        try {
          await session.ready;
          checkPending(pending);
          const known = await storage.get(driverKey(record.id));
          const state = known ? await runtime.call("job", { id: record.id, owner: record.owner ?? record.session_id, job_id: known.jobId }, { signal }) : null;
          checkPending(pending);
          if (!state || state.returncode !== null && state.returncode !== undefined) {
            if (known) await storage.delete(driverKey(record.id));
            throw new RealmError("driver_unavailable", "Realm driver identity was not adopted: its serve job exited or is unknown. Native retirement is unconfirmed. Use Repair once to retire the actual owned daemon/socket, then take a fresh capture. If that fails, ask the person to Stop this Realm before reconnecting.");
          }
          cuaSessions.set(record.id, { generation: record.compute_generation ?? record.generation, session });
          return session;
        } catch (error) {
          session.close();
          checkPending(pending);
          lastError = error;
          if (!/no Cua Driver daemon listening/i.test(String(error?.message))) break;
          await sleep(POLL_MS, signal);
        }
      }
      throw new RealmError("driver_unavailable", lastError?.message ?? "The Realm GUI driver did not start.");
    } catch (error) {
      checkPending(pending);
      throw error;
    }
  };

  const guiFailure = (error) => {
    if (!["timeout", "cancelled", "driver_unavailable", "driver_error"].includes(error.code)) return error;
    return new RealmError(error.code, `${error.message} Only this Realm GUI connection failed. Input may already have landed; do not replay uncertain input. Diagnose with Realm status/terminal or an allowed shot; try one realm action "repair", then take a fresh capture. If failure repeats, report its cause and continue unrelated work. If retirement is unconfirmed, a person must Stop this Realm before reconnecting.`);
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
    const cleanup = await storage.get(storageKey("driver-cleanup", who.threadId));
    if (cleanup?.incarnation === (record.compute_generation ?? record.generation))
      throw new RealmError("driver_unavailable", `${cleanup.error} ${cleanup.nextStep}`);
    const authorityEpoch = await admission(who, record);
    let session;
    try { session = await cuaFor(record, signal); }
    catch (error) { throw guiFailure(error); }
    await admitted(who, record, authorityEpoch, signal);
    if (tool === "list" || tool.startsWith("describe:")) {
      const tools = (await session.listTools({ signal })).filter((entry) => COMPUTER_TOOLS.has(entry.name));
      await admitted(who, record, authorityEpoch, signal);
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
    let result;
    try { result = await session.call(tool, input.arguments ?? {}, { signal, timeoutMs }); }
    catch (error) { throw guiFailure(error); }
    await admitted(who, record, authorityEpoch, signal);
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
    try { await admitted(who, record, authorityEpoch, signal); }
    catch (error) { await Promise.all(images.map((asset) => fs.rm(path.join(dataDirectory, asset.path), { force: true }))); throw error; }
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
      checkSignal(signal);
      requireUser(who, "Taking control");
      await invalidateContinuation(who.threadId);
      const record = await requireRunning(who.threadId, signal);
      const held = await control(record);
      await revoke(who.threadId, "human_control", "A person took control of this Realm. Ask them to click Hand back when finished.");
      await storage.set(controlKey(record.id), {
        controller: "user",
        generation: record.compute_generation ?? record.generation,
        since: held?.since ?? new Date(now()).toISOString(),
        epoch: (held?.epoch ?? 0) + 1,
      });
      dropSessions(record.id);
      try {
        await rfbFor(record, signal);
      } catch (error) {
        const held = await control(record);
        if (held) await storage.set(controlKey(record.id), { ...held, connection: "failed", connectionError: String(error.message).slice(0, 1000) });
        throw new RealmError(error.code ?? "failed", `${error.message} The person-controlled Realm hold remains. Click Hand back to restore agent access, even after a failed viewer connection.`);
      }
      return status(who, { signal });
    });
  const handBack = (who, { signal } = {}) =>
    locked(requireThread(who), async () => {
      checkSignal(signal);
      requireUser(who, "Handing control back");
      const record = await current(ownerKey(who.threadId), signal);
      if (record) {
        await revoke(who.threadId, "human_control", "A person took control and handed back this Realm during the old request. Take a fresh capture.");
        dropControlConnection(record.id);
        await storage.delete(controlKey(record.id));
      }
      return status(who, { signal });
    });
  const rfbFor = async (record, signal) => {
    const existing = rfbClients.get(record.id);
    if (existing && !existing.closed && existing.generation === (record.compute_generation ?? record.generation)) return existing;
    dropControlConnection(record.id);
    const endpoint = await runtime.call(
      "vnc_endpoint",
      { id: record.id, owner: record.owner ?? record.session_id },
      { signal },
    );
    const client = await connectRfb(endpoint.path);
    client.generation = record.compute_generation ?? record.generation;
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

  // Setup started from a client is confirmed by a person; the confirmation names the exact plan it saw.
  const setupPlan = async (signal, kind = "realm") => runtime.call("setup_plan", { config: { ...await config({ fresh: true }), kind } }, { signal });
  const setupReview = async (who, input = {}, { signal } = {}) => {
    requireUser(who, "Reviewing Realms setup");
    const kind = await selectedKind(who.threadId, input.kind);
    const plan = await setupPlan(signal, kind);
    const jobs = await runtime.call("job_list", {}, { signal });
    return { data: { ...plan, job: jobs.find((job) => job.kind === (kind === "omarchy-vm" ? "vm_setup" : "setup")) ?? null } };
  };
  const setupStart = async (who, input, { signal } = {}) => {
    requireUser(who, "Approving Realms setup");
    const kind = await selectedKind(who.threadId, input.kind);
    const plan = await setupPlan(signal, kind);
    if (input.reviewId !== plan.reviewId)
      throw new RealmError("changed", "The setup plan changed since you reviewed it. Review it again.");
    const blockers = plan.blockers ?? plan.missing;
    if (blockers.length > 0) throw new RealmError("blocked", blockers.join("; "));
    if (plan.ready) {
      await approveContinuation(kind);
      // A person has explicitly observed successful setup, including setup completed externally.
      const continuation = await observeContinuation(who);
      return { message: "Realms setup is ready.", data: { ...plan, continuation } };
    }
    const job = await runtime.call("job_start", { kind: kind === "omarchy-vm" ? "vm_setup" : "setup",
      input: { config: { ...await config(), kind }, review_id: plan.reviewId } }, { signal });
    await approveContinuation(kind, job.job_id);
    doctorCache = undefined;
    return { message: "Preparing the reviewed Realm setup. Package installation may request native Polkit authorization.", data: { jobId: job.job_id, kind } };
  };
  const jobStatus = async (who, input, { signal } = {}) => {
    requireUser(who, "Checking setup");
    const job = await runtime.call("job_status", { job_id: String(input.jobId) }, { signal });
    if (!["queued", "running"].includes(job.state)) doctorCache = undefined;
    const continuation = await observeContinuation(who, job);
    return { data: { ...job, continuation } };
  };
  const jobCancel = async (who, input, { signal } = {}) => {
    requireUser(who, "Cancelling setup");
    const job = await runtime.call("job_cancel", { job_id: String(input.jobId) }, { signal });
    const continuation = await observeContinuation(who, { ...job, job_id: String(input.jobId), state: "cancelled" });
    return { data: { ...job, continuation } };
  };

  /** The chat card's view of setup. Cancelling or retrying goes through the same person-only handlers. */
  const setupState = async (who, input = {}, { signal } = {}) => {
    requireUser(who, "Checking setup");
    const kind = await selectedKind(undefined, input.kind);
    const [plan, jobs] = await Promise.all([setupPlan(signal, kind), setupJobs(signal)]);
    const base = { kind, label: KIND_LABELS[kind], reviewId: plan.reviewId };
    if (plan.ready) {
      const blocked = (await observeContinuation(who)).filter((entry) => entry.manualContinuationRequired).at(-1);
      return { data: { ...base, phase: "ready", resumeBlocked: Boolean(blocked), resumeMessage: blocked?.message ?? null } };
    }
    const active = jobs.find(jobIsActive);
    if (active) {
      const stage = typeof active.progress === "string" ? active.progress : active.progress?.stage ?? null;
      const download = active.kind === "vm_setup" && stage === "installing" ? await runtime.call("vm_download", {}, { signal }).catch(() => null) : null;
      return { data: { ...base, phase: "installing", jobId: active.job_id, stage, download, message: active.progress?.message ?? null } };
    }
    const blockers = setupBlockers(plan);
    if (blockers.length) return { data: { ...base, phase: "blocked", blockers } };
    // A retry approves the current plan, so the card must show any packages that plan now has.
    if (plan.halt) return { data: { ...base, phase: plan.halt.state, error: plan.halt.error ?? null, packages: plan.packages ?? [], command: plan.command ?? null } };
    if (plan.packages?.length) return { data: { ...base, phase: "packages", packages: plan.packages, command: plan.command ?? null } };
    return { data: { ...base, phase: "approve" } };
  };
  /** Cards have no composer to fill, so a refused message comes back for the person to send. */
  const nudgeAgent = async (who, text) => {
    const threadId = who.sourceThreadId ?? requireThread(who);
    try {
      if (!sendThread) throw new Error("unavailable");
      await sendThread({ threadId, idempotencyKey: `realm-nudge-${randomUUID()}`, text });
    } catch {
      return { message: "Realms can't message this thread.", data: { sent: false, text } };
    }
    await settleContinuation(who.threadId);
    return { message: "The agent was asked to continue.", data: { sent: true } };
  };
  const continueAgent = async (who) => {
    requireUser(who, "Continuing the agent");
    return nudgeAgent(who, "Realm setup is finished. Please continue if the test is still needed; inspect current state first and don't replay old input.");
  };
  const useDesktop = async (who, _input, { signal } = {}) => {
    requireUser(who, "Choosing a Realm kind");
    // The switch sticks even if Desktop itself needs setup; its panel then offers that review.
    await on(who, { kind: "realm" }, { signal }).catch((error) => { if (error.code !== "setup_required") throw error; });
    return nudgeAgent(who, "Use the Desktop Realm instead of the Omarchy VM and continue. Inspect current state first.");
  };

  const components = async (who, _input, { signal } = {}) => {
    requireUser(who, "Listing installed components");
    return { data: { ...await runtime.call("components", {}, { signal }), autoInstall: await autoInstall() } };
  };
  const setAutoInstall = async (who, input) => {
    requireUser(who, "Changing automatic installs");
    if (typeof input.enabled !== "boolean") throw invalid("enabled must be true or false.");
    await storage.set(AUTO_INSTALL_KEY, input.enabled);
    return { data: { autoInstall: input.enabled } };
  };
  const removeComponent = async (who, input, { signal } = {}) => {
    requireUser(who, "Removing a component");
    if (!["driver", "vm"].includes(input.component)) throw invalid("Choose a component to remove.");
    const summary = await runtime.call("component_remove", { component: input.component }, { signal });
    doctorCache = undefined;
    return { message: "Removed.", data: { ...summary, autoInstall: await autoInstall() } };
  };
  const removeEverything = async (who, input, { signal } = {}) => {
    requireUser(who, "Removing everything");
    if (input.phrase !== REMOVE_PHRASE) throw invalid(`Type "${REMOVE_PHRASE}" to confirm.`);
    const busy = (await records(undefined, signal)).filter((record) => ACTIVE_RECORDS.has(record.status)).length;
    if (busy) throw new RealmError("busy", `Stop ${busy === 1 ? "the running Realm" : `${busy} running Realms`} first.`);
    const job = await runtime.call("job_start", { kind: "teardown", input: { config: await config() } }, { signal });
    return { message: "Removing everything Realms installed.", data: { jobId: job.job_id } };
  };

  // Environment-wide management for the Realms page.
  const list = async (who, input = {}, { signal } = {}) => {
    requireUser(who, "Listing Realms");
    const [all, report] = await Promise.all([
      records(undefined, signal),
      doctor({ signal }).catch((error) => ({ ready: false, message: error.message })),
    ]);
    const offset = Number.isInteger(input.offset) && input.offset >= 0 ? input.offset : 0;
    all.sort((a, b) => (a.status === "running" ? -1 : 0) - (b.status === "running" ? -1 : 0) || (b.last_activity ?? 0) - (a.last_activity ?? 0));
    const realms = await Promise.all(
      all.slice(offset, offset + 100).map(async (record) => ({ threadId: threadOf(record.owner ?? record.session_id), ...(await describeRealm(record)) })),
    );
    realms.sort((a, b) => (a.state === "live" ? -1 : 0) - (b.state === "live" ? -1 : 0) || (b.lastActivity ?? 0) - (a.lastActivity ?? 0));
    const data = { realms, setup: setupSummary(report), total: all.length, nextOffset: null };
    while (realms.length > 1 && jsonBytes({ data }) > RESULT_BUDGET_BYTES) realms.pop();
    data.nextOffset = offset + realms.length < all.length ? offset + realms.length : null;
    return { data };
  };
  const ownedRecord = async (input, signal) => {
    if (typeof input.realmId !== "string") throw invalid("Choose a Realm.");
    const record = (await records(undefined, signal)).find((candidate) => candidate.id === input.realmId);
    if (!record) throw new RealmError("not_found", "That Realm no longer exists.");
    return record;
  };
  const stopById = async (who, input, { signal } = {}) => {
    requireUser(who, "Stopping a Realm");
    let selected;
    try { selected = await ownedRecord(input, signal); }
    catch (error) {
      if (typeof input.realmId !== "string" || ["invalid_input", "not_found", "ownership", "cancelled"].includes(error.code)) throw error;
      // Only a verified person reaches here. The native Stop resolves and validates the exact record;
      // it does not need the unavailable owner-wide inventory or permission to guess a start job.
      checkSignal(signal);
      return runtime.call("stop", { id: input.realmId }, { signal });
    }
    const owner = selected.owner ?? selected.session_id;
    return locked(threadOf(owner), async () => {
      checkSignal(signal);
      const record = await ownedRecord(input, signal);
      const pending = await activeStartJob(owner, signal);
      const prepared = pending?.result ?? pending?.progress;
      const same = pending && (pending.input?.config?.kind ?? "realm") === (record.kind ?? "realm") &&
        (prepared?.id ?? prepared?.realm_id) === record.id &&
        (prepared?.compute_generation ?? prepared?.generation) === (record.compute_generation ?? record.generation);
      if (same) await runtime.call("job_cancel", { job_id: pending.job_id }, { signal });
      if (record.status !== "stopped") await revoke(threadOf(owner), "changed", "This Realm compute was stopped. Inspect status before a fresh request.");
      dropSessions(record.id); dropControlConnection(record.id);
      await storage.delete(controlKey(record.id));
      return runtime.call("stop", { id: record.id, owner }, { signal });
    }, signal);
  };
  const deleteReview = async (who, input, { signal } = {}) => {
    requireUser(who, "Deleting a workspace");
    const record = await ownedRecord(input, signal);
    const owner = record.owner ?? record.session_id;
    const discard = input.discard === true;
    if (discard && record.kind !== "omarchy-vm") throw invalid("Discard is only for VM recovery.");
    const snapshot = await runtime.call("delete_snapshot", { id: record.id, owner, ...(discard ? { discard: true } : {}) }, { signal });
    return { data: { realmId: record.id, owner, phrase: `${discard ? "discard" : "delete"} ${record.id}`, discard, snapshot, token: snapshot.token } };
  };
  const deleteWorkspace = async (who, input, { signal } = {}) => {
    requireUser(who, "Deleting a workspace");
    const record = await ownedRecord(input, signal);
    const discard = input.discard === true;
    const phrase = `${discard ? "discard" : "delete"} ${record.id}`;
    if (input.phrase !== phrase) throw invalid(`Type "${phrase}" to confirm.`);
    const owner = record.owner ?? record.session_id;
    if (typeof input.token !== "string") throw invalid("Review the workspace again before deleting it.");
    await runtime.call("delete", { id: record.id, owner, token: input.token, ...(discard ? { discard: true } : {}) }, { signal });
    await storage.delete(controlKey(record.id));
    return { message: "Workspace deleted." };
  };

  const files = async (who, input, { signal } = {}) => {
    const threadId = requireThread(who);
    await agentAllowed(who);
    const record = await requireRunning(threadId, signal);
    await agentNotControlled(who, record);
    const epoch = await admission(who, record);
    if (record.kind !== "omarchy-vm") throw new RealmError("unsupported", "File transfer requires an Omarchy VM; regular Realms already share host files.");
    const owner = ownerKey(threadId);
    await runtime.call("touch", { id: record.id, owner }, { signal });
    if (input.jobId !== undefined) {
      const job = await runtime.call("job_status", { job_id: String(input.jobId) }, { signal });
      if (job.owner !== owner) throw ownership("This transfer belongs to another thread. Use a job ID returned to this shared owner.");
      if (job.kind !== "transfer") throw invalid(`This is a ${job.kind === "vm_driver" ? "driver preparation" : job.kind} job, not a transfer. Use realm status for driver/start diagnostics; only transfer jobs can be polled or cancelled with realm-files.`);
      await admitted(who, record, epoch, signal);
      if (input.action === "cancel") await runtime.call("job_cancel", { job_id: job.job_id }, { signal });
      const message = ["failed", "cancelled"].includes(job.state)
        ? `Only this Realm transfer ${job.state}: ${String(job.error ?? job.code ?? job.state).slice(0, 2000)}. Inspect its cause and source/destination; preserve existing work and resolve conflicts or choose a new destination before one explicit retry. Do not blindly replay it.`
        : job.state === "succeeded"
          ? "Realm transfer succeeded. Use the returned destination."
          : "Realm transfer is pending. Poll this jobId for its final result before retrying or using its destination.";
      return fitResult({ message, data: job }, []);
    }
    if (!["push", "pull"].includes(input.action)) throw invalid("action must be push, pull, status or cancel.");
    const explicit = (value) => typeof value === "string" && path.isAbsolute(value) && !value.includes("\0") && value.length <= 4096;
    if (!explicit(input.source)) throw invalid("source must be an explicit absolute path; wildcards are literal characters.");
    if ((input.action === "pull" || input.destination !== undefined) && !explicit(input.destination))
      throw invalid("destination must be an explicit absolute path (required for pull).");
    await admitted(who, record, epoch, signal);
    const job = await runtime.call("job_start", { kind: "transfer", owner,
      input: { id: record.id, incarnation: record.compute_generation ?? record.generation, direction: input.action,
        source: input.source, ...(input.destination === undefined ? {} : { destination: input.destination }) } }, { signal });
    try { await admitted(who, record, epoch, signal); }
    catch (error) {
      await runtime.call("job_cancel", { job_id: job.job_id }, {}).catch(() => undefined);
      throw new RealmError(error.code ?? "changed", `${error.message} Transfer ${job.job_id} cancellation was requested. Inspect partial additions and do not replay it blindly.`);
    }
    return { message: "Transfer started. Poll with jobId; use the returned destination. Existing different entries are never overwritten.", data: { jobId: job.job_id } };
  };
  const pruneReview = async (who, _input = {}, { signal } = {}) => {
    requireUser(who, "Pruning recovery workspaces");
    return { data: await runtime.call("vm_prune_review", { config: await config() }, { signal }) };
  };
  const pruneRecovery = async (who, input, { signal } = {}) => {
    requireUser(who, "Pruning recovery workspaces");
    if (input.phrase !== "discard recovery workspaces" || typeof input.token !== "string") throw invalid('Review first, then type "discard recovery workspaces".');
    return { data: await runtime.call("vm_prune", { config: await config(), token: input.token }, { signal }) };
  };

  const dispose = () => {
    disposed = true;
    for (const pending of cuaPending.values()) { pending.revoked = { code: "cancelled", message: "This Realm worker was disposed; request status through the current worker." }; pending.controller.abort(); }
    cuaPending.clear();
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
    shot: (who, ...args) => agentRequest(who, () => shot(who, ...args)),
    terminal: (who, ...args) => agentRequest(who, () => terminal(who, ...args)),
    files: (who, ...args) => agentRequest(who, () => files(who, ...args)),
    pruneReview,
    pruneRecovery,
    computer: (who, ...args) => agentRequest(who, () => computer(who, ...args)),
    takeControl,
    handBack,
    sendInput,
    frame,
    setupReview,
    setupStart,
    jobStatus,
    jobCancel,
    setupState,
    continueAgent,
    useDesktop,
    components,
    setAutoInstall,
    removeComponent,
    removeEverything,
    list,
    stopById,
    deleteReview,
    deleteWorkspace,
    dispose,
  };
}
