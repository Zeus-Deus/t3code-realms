import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createRealms, principal } from "../lib/realms.mjs";
import { RealmError } from "../lib/runtime.mjs";

const agent = (threadId, context) => ({ caller: { kind: "agent", threadId }, ...(context ? { context } : {}) });
const client = (threadId) => ({ caller: { kind: "client" }, ...(threadId ? { context: { threadId } } : {}) });

/** An in-memory stand-in for the native runtime's JSON CLI contract. */
function fakeRuntime({ ready = true } = {}) {
  const state = { ready, records: new Map(), jobs: new Map(), calls: [], next: 1, sessions: [], serves: 0, daemonJobs: new Map() };
  const record = (owner) => [...state.records.values()].filter((entry) => entry.owner === owner);
  const call = async (command, input = {}) => {
    state.calls.push([command, input]);
    switch (command) {
      case "doctor":
        return { ready: state.ready, missing: state.ready ? [] : ["labwc", "verified cua-driver"], message: state.ready ? "Ready" : "Install labwc", driver: { verified: state.ready } };
      case "setup_plan": {
        if (input.config.kind === "omarchy-vm") return { kind: "omarchy-vm", ready: true, missing: [], reviewId: "vm-plan", driver: { installed: true } };
        return { kind: "realm", ready: state.ready, missing: state.ready ? [] : ["labwc"],
          blockers: state.ready ? [] : ["labwc"], packages: [], reviewId: state.ready ? "ready-plan" : "blocked-plan", driver: { installed: state.ready } };
      }
      case "stop":
        state.records.get(input.id).status = "stopped"; return true;
      case "list":
        return [...state.records.values()].filter((entry) => !input.owner || entry.owner === input.owner);
      case "job_list":
        return [...state.jobs.values()].filter((job) => !input.owner || job.owner === input.owner);
      case "job_start": {
        const job_id = `job-${state.next++}`;
        state.jobs.set(job_id, { job_id, kind: input.kind, owner: input.owner, state: "succeeded", input: input.input });
        if (input.kind === "start") {
          const id = `r-${String(state.next++).padStart(24, "0")}`;
          state.records.set(id, { id, owner: input.owner, status: "running", generation: "g1", kind: input.input.config.kind ?? "realm", size: input.input.config.size });
        }
        return { job_id };
      }
      case "job_status":
        return state.jobs.get(input.job_id);
      case "job_cancel":
        return { cancelled: true };
      case "touch":
      case "resize":
        return true;
      case "windows":
        return { count: 1 };
      case "stop_owner":
        for (const entry of record(input.owner)) entry.status = "stopped";
        return true;
      case "driver_stop":
        for (const [jobId, job] of state.daemonJobs) if (job.id === input.id) {
          job.returncode = 0;
          state.calls.push(["signal", { id: input.id, owner: input.owner, job_id: jobId, signal: 15 }]);
        }
        return { retired: true };
      case "exec":
        if (input.argv[1] === "serve") {
          const job_id = `serve-${++state.serves}`;
          state.daemonJobs.set(job_id, { id: input.id, returncode: null });
          return { job_id, pid: 43 };
        }
        return { job_id: "cmd-1", pid: 42 };
      case "job":
        if (state.daemonJobs.has(input.job_id)) return { job_id: input.job_id, returncode: state.daemonJobs.get(input.job_id).returncode };
        return { job_id: input.job_id, returncode: 0, stdout: "hi\n", stderr: "" };
      case "signal":
        if (state.daemonJobs.has(input.job_id)) state.daemonJobs.get(input.job_id).returncode = 0;
        return true;
      case "shot":
        return { path: "assets/shot-1.jpg", mimeType: "image/jpeg", width: 10, height: 10, sha256: "x" };
      case "vnc_endpoint":
        return { path: "/run/fake.sock" };
      case "driver_launcher":
        // A real launcher check spawns Python; keep concurrent callers overlapping.
        await new Promise((resolve) => setTimeout(resolve, 5));
        return { path: "/fake/launcher" };
      default:
        throw new Error(`unexpected ${command}`);
    }
  };
  return { state, call };
}

// T3 Code's plugin host rejects any storage key outside this pattern (apps/server/src/plugins/PluginHost.ts).
const HOST_STORAGE_KEY = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

/** In-memory plugin storage that enforces the host's key contract. */
function memoryStorage() {
  const values = new Map();
  const checked = (key) => {
    if (typeof key !== "string" || !HOST_STORAGE_KEY.test(key)) throw new Error("The plugin host request is invalid.");
    return key;
  };
  return {
    values,
    get: async (key) => (values.has(checked(key)) ? structuredClone(values.get(key)) : null),
    set: async (key, value) => void values.set(checked(key), structuredClone(value)),
    delete: async (key) => void values.delete(checked(key)),
  };
}

async function setup(options = {}) {
  const runtime = fakeRuntime(options);
  const now = options.now;
  const storage = memoryStorage();
  const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "t3r-node-"));
  const cuaCalls = [];
  const realms = createRealms({
    ...(now ? { now } : {}),
    runtime,
    storage,
    sendThread: options.sendThread,
    cards: options.cards,
    settings: { get: async () => null },
    dataDirectory,
    connectCua: () => {
      const session = {
        closed: false,
        ready: Promise.resolve(),
        listTools: async () => [{ name: "click", description: "Click" }, { name: "set_config", description: "no" }],
        call: async (name, args) => {
          cuaCalls.push([name, args]);
          return {
            content: [
              { type: "text", text: "ok" },
              { type: "image", mimeType: "image/png", data: Buffer.from([0x89, 0x50, 0x4e, 0x47]).toString("base64") },
            ],
          };
        },
        close: () => {
          session.closed = true;
        },
      };
      runtime.state.sessions.push(session);
      return session;
    },
    connectRfb: async () => {
      const sent = [];
      return { size: { width: 100, height: 100 }, closed: false, sent, pointer: (...a) => sent.push(["p", ...a]), key: (...a) => sent.push(["k", ...a]), close() { this.closed = true; } };
    },
  });
  return { runtime, storage, realms, dataDirectory, cuaCalls, options: { runtime, storage, dataDirectory } };
}

/** Another worker process over the same runtime and plugin storage. */
function createRealmsLike(previous) {
  return createRealms({
    ...previous.options,
    settings: { get: async () => null },
    connectCua: () => ({ closed: false, ready: Promise.resolve(), listTools: async () => [], call: async () => ({ content: [] }), close() {} }),
    connectRfb: async () => ({ size: { width: 1, height: 1 }, closed: false, pointer() {}, key() {}, close() {} }),
  });
}

const rejects = (promise, code) =>
  assert.rejects(promise, (error) => error instanceof RealmError && error.code === code);

test("an agent's own verified thread is its only Realm owner", () => {
  assert.deepEqual(principal(agent("t1")), { kind: "agent", threadId: "t1" });
  assert.deepEqual(principal(agent("t1", { threadId: "t1" })), { kind: "agent", threadId: "t1" });
  assert.throws(() => principal(agent("t1", { threadId: "t2" })), /own thread/);
  assert.throws(() => principal({ caller: { kind: "agent" } }), /not running in a thread/);
  assert.throws(() => principal({ caller: { kind: "background" } }), /Background/);
  assert.throws(() => principal({ context: { threadId: "t1" } }), /verified caller/);
  // A person targets any thread; input is only a fallback for pages without thread context.
  assert.deepEqual(principal(client("t2"), { threadId: "ignored" }), { kind: "user", threadId: "t2" });
  assert.deepEqual(principal(client(), { threadId: "t3" }), { kind: "user", threadId: "t3" });
});

test("two threads get separate Realms and stopping one leaves the other", async () => {
  const { realms, runtime } = await setup();
  const one = await realms.on(principal(agent("t1")), {});
  const two = await realms.on(principal(agent("t2")), {});
  assert.equal(one.realm.state, "live");
  assert.equal(two.realm.state, "live");
  assert.notEqual(one.realm.id, two.realm.id);
  await realms.stop(principal(agent("t1")));
  assert.equal((await realms.status(principal(agent("t1")))).realm.state, "stopped");
  assert.equal((await realms.status(principal(agent("t2")))).realm.state, "live");
  assert.ok(runtime.state.calls.some(([command, input]) => command === "stop_owner" && input.owner === "thread:t1"));
  assert.ok(!runtime.state.calls.some(([command, input]) => command === "stop_owner" && input.owner === "thread:t2"));
});

test("a person's off keeps the desktop but the agent cannot turn it back on", async () => {
  const { realms } = await setup();
  const me = principal(agent("t1"));
  await realms.on(me, {});
  const off = await realms.off(principal(client("t1")));
  assert.equal(off.mode, "off");
  assert.equal(off.offBy, "user");
  assert.equal(off.realm.state, "live", "off is not stop");
  await rejects(realms.on(me, {}), "disabled");
  await rejects(realms.terminal(me, { command: "echo hi" }), "disabled");
  await rejects(realms.computer(me, { tool: "click", arguments: {} }), "disabled");
  await rejects(realms.shot(me), "disabled");
  // The person can re-enable it.
  assert.equal((await realms.on(principal(client("t1")), {})).mode, "realm");
  assert.equal((await realms.terminal(me, { command: "echo hi" })).data.stdout, "hi\n");
});

test("an agent that turned its own Realm off may turn it on again", async () => {
  const { realms } = await setup();
  const me = principal(agent("t1"));
  await realms.off(me);
  assert.equal((await realms.on(me, {})).mode, "realm");
});

test("missing setup is an explicit error and nothing starts", async () => {
  const { realms, runtime } = await setup({ ready: false });
  await rejects(realms.on(principal(agent("t1")), {}), "setup_required");
  await rejects(realms.terminal(principal(agent("t1")), { command: "true" }), "setup_required");
  assert.ok(!runtime.state.calls.some(([command]) => command === "job_start"));
  await rejects(realms.setupStart(principal(agent("t1")), { reviewId: "x" }), "ownership");
});

test("setup approval binds to the reviewed plan and refuses missing system packages", async () => {
  const { realms, runtime } = await setup({ ready: false });
  const person = principal(client());
  const review = (await realms.setupReview(person)).data;
  assert.deepEqual(review.missing, ["labwc"]);
  await rejects(realms.setupStart(person, { reviewId: "stale" }), "changed");
  await rejects(realms.setupStart(person, { reviewId: review.reviewId }), "blocked");
  assert.ok(!runtime.state.calls.some(([command]) => command === "job_start"));
});

test("only the pinned GUI tool allowlist reaches the driver", async () => {
  const { realms, cuaCalls, runtime } = await setup();
  const me = principal(agent("t1"));
  await rejects(realms.computer(me, { tool: "set_config", arguments: {} }), "invalid_input");
  await rejects(realms.computer(me, { tool: "click", arguments: [] }), "invalid_input");
  const listed = await realms.computer(me, { tool: "list" });
  assert.deepEqual(listed.data.tools.map((tool) => tool.name), ["click"]);
  const clicked = await realms.computer(me, { tool: "click", arguments: { x: 1, y: 2 } });
  assert.deepEqual(cuaCalls, [["click", { x: 1, y: 2 }]]);
  const serves = runtime.state.calls.filter(([command, input]) => command === "exec" && input.argv[1] === "serve");
  assert.equal(serves.length, 1, "one driver daemon per Realm, inside its scope");
  assert.deepEqual(serves[0][1].argv, ["/fake/launcher", "serve"]);
  await realms.repair(me);
  assert.ok(runtime.state.calls.some(([command, input]) => command === "signal" && input.job_id === "serve-1"));
  assert.equal(clicked.images.length, 1);
  assert.match(clicked.images[0].path, /^assets\/cua-.*\.png$/);
});

test("human control pauses agent input and captures until an explicit handback", async () => {
  const { realms } = await setup();
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  await realms.on(me, {});
  await rejects(realms.takeControl(me), "ownership");
  const taken = await realms.takeControl(person);
  assert.equal(taken.realm.controlledBy, "user");
  await rejects(realms.computer(me, { tool: "click", arguments: {} }), "human_control");
  await rejects(realms.shot(me), "human_control");
  const sent = await realms.sendInput(person, { events: [{ type: "pointer", x: 5, y: 6, buttons: 1 }, { type: "key", keysym: 0x61, down: true }] });
  assert.equal(sent.data.sent, 2);
  await rejects(realms.sendInput(person, { events: [{ type: "exec" }] }), "invalid_input");
  await rejects(realms.sendInput(me, { events: [] }), "ownership");
  await realms.handBack(person);
  assert.equal((await realms.computer(me, { tool: "click", arguments: {} })).data.isError, false);
});

test("commands that point display or bus variables at the host are refused before running", async () => {
  const { realms, runtime } = await setup();
  const me = principal(agent("t1"));
  await rejects(realms.terminal(me, { command: "WAYLAND_DISPLAY=wayland-1 foot" }), "host_escape");
  await rejects(realms.terminal(me, { command: "echo hi", cwd: "relative" }), "invalid_input");
  assert.ok(!runtime.state.calls.some(([command]) => command === "exec"));
  const background = await realms.terminal(me, { command: "foot", background: true });
  assert.equal(background.data.jobId, "cmd-1");
  const exec = runtime.state.calls.find(([command]) => command === "exec")[1];
  assert.deepEqual(exec.argv, ["/bin/sh", "-c", "foot"]);
  assert.equal(exec.owner, "thread:t1");
});

test("unknown kinds are refused rather than silently mapped", async () => {
  const { realms } = await setup();
  await rejects(realms.on(principal(agent("t1")), { kind: "unknown" }), "invalid_input");
});

test("the thread status stays quiet until a thread uses a Realm and never lies about control", async () => {
  const { realms } = await setup();
  const person = principal(client("t1"));
  assert.equal(await realms.badge(person), null);
  await realms.on(principal(agent("t1")), {});
  assert.deepEqual((await realms.badge(person)).label, "Live");
  await realms.takeControl(person);
  assert.equal((await realms.badge(person)).tone, "warning");
  await realms.handBack(person);
  await realms.off(person);
  assert.equal((await realms.badge(person)).label, "Live · agent off");
  await realms.stop(person);
  assert.equal((await realms.badge(person)).label, "Off");
});

test("setup approval starts the pinned driver install when only the driver is missing", async () => {
  const { realms, runtime } = await setup({ ready: false });
  const original = runtime.call;
  runtime.call = async (command, input) =>
    command === "setup_plan"
      ? { ready: false, missing: [], blockers: [], packages: [], reviewId: "driver-plan", driver: { installed: false } }
      : original(command, input);
  const person = principal(client());
  const review = (await realms.setupReview(person)).data;
  assert.deepEqual(review.missing, []);
  const started = await realms.setupStart(person, { reviewId: review.reviewId });
  assert.ok(started.data.jobId);
  assert.ok(runtime.state.calls.some(([command, input]) => command === "job_start" && input.kind === "setup"));
});

test("review r1: an agent cannot overwrite a person's off and then turn the Realm back on", async () => {
  const { realms } = await setup();
  const me = principal(agent("t1"));
  await realms.on(me, {});
  await realms.off(principal(client("t1")));
  await realms.off(me);
  await rejects(realms.on(me, {}), "disabled");
});

test("review r1: the terminal honours human control and off, including job polling", async () => {
  const { realms } = await setup();
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  await realms.on(me, {});
  const job = await realms.terminal(me, { command: "sleep 9", background: true });
  await realms.takeControl(person);
  await rejects(realms.terminal(me, { command: "wtype hi" }), "human_control");
  await rejects(realms.terminal(me, { jobId: job.data.jobId, signal: "KILL" }), "human_control");
  await realms.handBack(person);
  await realms.off(person);
  await rejects(realms.terminal(me, { jobId: job.data.jobId }), "disabled");
});

test("review r1: control taken while an agent prepares its driver call blocks the input", async () => {
  const { realms, cuaCalls, runtime } = await setup();
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  await realms.on(me, {});
  const original = runtime.call;
  runtime.call = async (command, input, options) => {
    if (command === "driver_launcher") await realms.takeControl(person);
    return original(command, input, options);
  };
  await rejects(realms.computer(me, { tool: "click", arguments: {} }), "human_control");
  assert.equal(cuaCalls.length, 0);
});

test("review r1: an agent cannot stop, resize or repair its way out of a person's control", async () => {
  const { realms } = await setup();
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  await realms.on(me, {});
  await realms.takeControl(person);
  await rejects(realms.stop(me), "human_control");
  await rejects(realms.resize(me, { size: "800x600" }), "human_control");
  await rejects(realms.repair(me), "human_control");
  assert.equal((await realms.status(person)).realm.controlledBy, "user");
});

test("review r1: control from an earlier desktop generation does not carry over", async () => {
  const { realms, runtime } = await setup();
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  const { realm } = await realms.on(me, {});
  await realms.takeControl(person);
  runtime.state.records.get(realm.id).generation = "g2";
  assert.equal((await realms.status(person)).realm.controlledBy, null);
  assert.equal((await realms.computer(me, { tool: "click", arguments: {} })).data.isError, false);
});

test("review r1: large command output stays within the host result budget and keeps the exit code", async () => {
  const { realms, runtime } = await setup();
  const me = principal(agent("t1"));
  const original = runtime.call;
  runtime.call = async (command, input, options) =>
    command === "job"
      ? { job_id: input.job_id, returncode: 3, stdout: '"\n'.repeat(60_000), stderr: "é\u0001".repeat(60_000) }
      : original(command, input, options);
  const result = await realms.terminal(me, { command: "noisy" });
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 120_000, "under the host's 128 KB limit");
  assert.equal(result.data.exitCode, 3);
  assert.equal(result.data.truncated, true);
  assert.match(result.data.stdout, /omitted/);
});

test("review r1: a person's input renews the idle lease at most every 30 seconds", async () => {
  let clock = 1_000_000;
  const { realms, runtime } = await setup({ now: () => clock });
  const person = principal(client("t1"));
  await realms.on(principal(agent("t1")), {});
  await realms.takeControl(person);
  const touches = () => runtime.state.calls.filter(([command]) => command === "touch").length;
  const before = touches();
  const key = { events: [{ type: "key", keysym: 0x61, down: true }] };
  await realms.sendInput(person, key);
  await realms.sendInput(person, key);
  clock += 31_000;
  await realms.sendInput(person, key);
  assert.equal(touches() - before, 2);
});

test("review r2: concurrent cold computer calls share one driver daemon and session, and repair closes it", async () => {
  const { realms, runtime } = await setup();
  const me = principal(agent("t1"));
  await realms.on(me, {});
  const results = await Promise.all([1, 2, 3].map(() => realms.computer(me, { tool: "click", arguments: {} })));
  assert.equal(results.length, 3);
  const serves = runtime.state.calls.filter(([command, input]) => command === "exec" && input.argv[1] === "serve");
  assert.equal(serves.length, 1);
  assert.equal(runtime.state.sessions.length, 1);
  await realms.repair(me);
  assert.ok(runtime.state.sessions.every((session) => session.closed));
});

test("review r2: the driver daemon is remembered across a plugin worker restart", async () => {
  const first = await setup();
  const me = principal(agent("t1"));
  await first.realms.on(me, {});
  await first.realms.computer(me, { tool: "click", arguments: {} });
  // A fresh worker shares storage and runtime state but not memory.
  const second = createRealmsLike(first);
  await second.repair(me);
  assert.ok(first.runtime.state.calls.some(([command, input]) => command === "signal" && input.job_id === "serve-1"));
});

test("review r2: a command that lands as a person takes control is killed and refused", async () => {
  const { realms, runtime } = await setup();
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  await realms.on(me, {});
  const original = runtime.call;
  runtime.call = async (command, input, options) => {
    const result = await original(command, input, options);
    if (command === "exec" && input.argv[1] !== "serve") await realms.takeControl(person);
    return result;
  };
  await rejects(realms.terminal(me, { command: "xdotool type hi", background: true }), "human_control");
  assert.ok(runtime.state.calls.some(([command, input]) => command === "signal" && input.job_id === "cmd-1" && input.signal === 9));
});

test("review r2: after a person's off the agent cannot stop the desktop either", async () => {
  const { realms } = await setup();
  const me = principal(agent("t1"));
  await realms.on(me, {});
  await realms.off(principal(client("t1")));
  await rejects(realms.stop(me), "disabled");
  assert.equal((await realms.status(principal(client("t1")))).realm.state, "live");
});

test("review r2: long output keeps its tail and says it was shortened", async () => {
  const { realms, runtime } = await setup();
  const me = principal(agent("t1"));
  const original = runtime.call;
  runtime.call = async (command, input, options) =>
    command === "job"
      ? { job_id: input.job_id, returncode: 1, stdout: "x".repeat(input.job_id === "cmd-1" ? 150_000 : 70_000) + "THE END", stderr: "" }
      : original(command, input, options);
  const result = await realms.terminal(me, { command: "long" });
  assert.match(result.data.stdout, /THE END$/);
  assert.equal(result.data.truncated, true);
  const fits = await realms.terminal(me, { jobId: "other" });
  assert.equal(fits.data.stdout.length, 70_007, "output that fits is not cut");
  assert.equal(fits.data.truncated, undefined);
});

test("storage keys satisfy the host contract for any thread id, including long ones", async () => {
  const { realms, storage } = await setup();
  // Thread ids are opaque to Realms: up to 200 non-space characters, including ones the host refuses in keys.
  const longId = `thread:${"a/b:c".repeat(38)}`.slice(0, 200);
  const otherId = `${longId.slice(0, 199)}z`;
  const person = principal(client(longId));
  const me = principal(agent(longId));
  assert.equal((await realms.status(person)).mode, "unset");
  await realms.on(me, {});
  await realms.off(person);
  assert.equal((await realms.status(person)).mode, "off");
  await realms.on(person, {});
  const taken = await realms.takeControl(person);
  assert.equal(taken.realm.controlledBy, "user");
  assert.ok(await realms.badge(person));
  await realms.handBack(person);
  assert.equal((await realms.status(person)).realm.controlledBy, null);
  // A neighbouring thread whose id differs only in its last character keeps its own preference.
  assert.equal((await realms.status(principal(client(otherId)))).mode, "unset");
  assert.ok(storage.values.size > 0);
  for (const key of storage.values.keys()) assert.match(key, HOST_STORAGE_KEY);
});

test("VM kind is persisted, routed to setup/start, and survives off", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "user", threadId: "vm-owner" };
  const state = await s.realms.on(who, { kind: "omarchy-vm" });
  assert.equal(state.kind, "omarchy-vm");
  assert.match(s.realms.summary(state), /omarchy realm/);
  assert.equal(s.runtime.state.calls.find(([cmd]) => cmd === "job_start")[1].input.config.kind, "omarchy-vm");
  assert.equal((await s.realms.off(who)).kind, "omarchy-vm");
});

test("file transfers are owned detached jobs, require an explicit pull destination and exclude human control", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "agent", threadId: "vm-files" };
  await s.realms.on(who, { kind: "omarchy-vm" });
  await assert.rejects(s.realms.files(who, { action: "pull", source: "/guest/project" }), /destination/i);
  const result = await s.realms.files(who, { action: "pull", source: "/guest/project", destination: "/host/export" });
  assert.ok(result.data.jobId);
  const call = s.runtime.state.calls.find(([cmd, value]) => cmd === "job_start" && value.kind === "transfer");
  assert.equal(call[1].owner, "thread:vm-files");
  assert.equal(call[1].input.destination, "/host/export");
  await s.realms.takeControl({ kind: "user", threadId: who.threadId });
  await assert.rejects(s.realms.files(who, { action: "push", source: "/host/project" }), (error) => error.code === "human_control");
});

test("VM setup review binds resources and exact selected kind", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "user", threadId: "setup-vm" };
  const review = await s.realms.setupReview(who, { kind: "omarchy-vm" });
  assert.equal(review.data.kind, "omarchy-vm");
  await assert.rejects(s.realms.setupStart(who, { kind: "realm", reviewId: review.data.reviewId }), (e) => e.code === "changed");
});

test("switching kind stops compute and keeps each kind's workspace", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "user", threadId: "switch" };
  await s.realms.on(who, {});
  const regular = [...s.runtime.state.records.values()][0];
  await s.realms.on(who, { kind: "omarchy-vm" });
  assert.equal(regular.status, "stopped");
  assert.equal(s.runtime.state.records.size, 2);
  const state = await s.realms.status(who);
  assert.equal(state.kind, "omarchy-vm");
  assert.equal(state.realm.kind, "omarchy-vm");
});

test("a named VM cannot bypass a person's off or human control", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const person = { kind: "user", threadId: "vm-auth" }, agentWho = { ...person, kind: "agent" };
  await s.realms.on(person, {});
  await s.realms.takeControl(person);
  await assert.rejects(s.realms.on(agentWho, { kind: "omarchy-vm" }), (e) => e.code === "human_control");
  await s.realms.handBack(person);
  await s.realms.off(person);
  await assert.rejects(s.realms.on(agentWho, { kind: "omarchy-vm" }), (e) => e.code === "disabled");
  await assert.rejects(s.realms.setupReview(agentWho, { kind: "omarchy-vm" }), (e) => e.code === "ownership");
});

test("transfer job polling refuses another thread or a setup job", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "agent", threadId: "transfer-owner" };
  await s.realms.on(who, { kind: "omarchy-vm" });
  s.runtime.state.jobs.set("other", { job_id: "other", kind: "transfer", owner: "thread:other", state: "running" });
  await assert.rejects(s.realms.files(who, { action: "status", jobId: "other" }), (e) => e.code === "ownership");
  s.runtime.state.jobs.set("setup", { job_id: "setup", kind: "vm_setup", owner: "thread:transfer-owner", state: "running" });
  await assert.rejects(s.realms.files(who, { action: "cancel", jobId: "setup" }), (e) => e.code === "invalid_input");
});

test("VM setup starts only the exact approved plan as a detached setup job", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const baseCall = s.runtime.call;
  s.runtime.call = async (command, input, options) => command === "setup_plan"
    ? { kind: "omarchy-vm", reviewId: "exact-vm-plan", ready: false, missing: [], driver: { installed: false } }
    : baseCall(command, input, options);
  const who = { kind: "user", threadId: "vm-setup-job" };
  await assert.rejects(s.realms.setupStart(who, { kind: "omarchy-vm", reviewId: "stale" }), (e) => e.code === "changed");
  const result = await s.realms.setupStart(who, { kind: "omarchy-vm", reviewId: "exact-vm-plan" });
  const call = s.runtime.state.calls.find(([cmd, input]) => cmd === "job_start" && input.kind === "vm_setup");
  assert.ok(result.data.jobId); assert.equal(call[1].input.review_id, "exact-vm-plan");
  assert.equal(call[1].input.config.kind, "omarchy-vm");
});

test("the management list includes both kinds and stays inside the result budget", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  for (let i = 0; i < 150; i++) s.runtime.state.records.set(`v-${i}`, { id: `v-${i}`, owner: `thread:${i}`, kind: i % 2 ? "realm" : "omarchy-vm", status: "recovery-required", generation: `g-${i}`, recovery_reason: "x".repeat(5000) });
  const result = await s.realms.list({ kind: "user" });
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 128000);
  assert.equal(result.data.total, 150); assert.ok(result.data.nextOffset > 0);
  assert.ok(result.data.realms.some((r) => r.kind === "omarchy-vm" && r.needsRecovery));
  const second = await s.realms.list({ kind: "user" }, { offset: result.data.nextOffset });
  assert.notEqual(result.data.realms[0].id, second.data.realms[0].id);
});

test("VM repair confirms driver retirement before a fresh connection can start", async (t) => {
  const s = await setup(); t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "agent", threadId: "vm-driver-retire" };
  await s.realms.on(who, { kind: "omarchy-vm" });
  await s.realms.computer(who, { tool: "list" });
  const call = s.runtime.call;
  let stopping = false, retired = false;
  let resolveSignal, resolveExit;
  const signalled = new Promise((r) => { resolveSignal = r; });
  const exit = new Promise((r) => { resolveExit = r; });
  s.runtime.call = async (command, input, opts) => {
    if (command === "signal") { stopping = true; resolveSignal(); }
    if (command === "exec" && stopping && input.argv[1] === "serve") assert.ok(retired, "old VM driver must be confirmed retired before starting another");
    if (command === "job" && stopping && input.job_id === "serve-1") {
      await exit; retired = true;
      return { job_id: "serve-1", returncode: 0 };
    }
    return call(command, input, opts);
  };
  const repair = s.realms.repair(who);
  await signalled;
  const before = s.runtime.state.sessions.length;
  const fresh = s.realms.computer(who, { tool: "list" });
  // Both operations must cross the same exit milestone before a new daemon/session.
  resolveExit();
  await repair; await fresh;
  assert.equal(s.runtime.state.sessions.length, before + 1);
  assert.ok(s.runtime.state.sessions.slice(0, before).every((session) => session.closed));
});


const childAgent = () => principal({ caller: { kind: "agent", threadId: "child", subagentOf: "parent" }, context: { threadId: "child" } });
const childClient = () => principal({ caller: { kind: "client" }, context: { threadId: "child", subagentOf: "parent" } });

test("verified subagents share ownership but cannot forge the target or lineage", () => {
  assert.equal(childAgent().threadId, "parent");
  assert.equal(childClient().threadId, "parent");
  assert.equal(principal(agent("child"), { subagentOf: "parent" }).threadId, "child");
  assert.equal(principal({ caller: { kind: "client" }, context: { threadId: "child" } }, { subagentOf: "parent" }).threadId, "child");
  assert.throws(() => principal({ caller: { kind: "agent", threadId: "child", subagentOf: "parent" }, context: { threadId: "parent" } }), /own thread/);
});

test("shared Realm preferences, control, terminal jobs and driver sessions belong to the parent", async () => {
  const { realms, runtime } = await setup();
  const parent = principal(agent("parent")), child = childAgent(), person = childClient();
  const first = await realms.on(parent, {});
  const shared = await realms.on(child, {});
  assert.equal(shared.realm.id, first.realm.id);
  assert.equal(shared.sharedFrom, "parent");
  assert.match((await realms.badge(person)).detail, /shared from parent/i);
  await Promise.all([realms.computer(parent, { tool: "list" }), realms.computer(child, { tool: "list" })]);
  assert.equal(runtime.state.sessions.length, 1);
  await realms.terminal(child, { jobId: "cmd-1" });
  await realms.takeControl(person);
  await rejects(realms.terminal(parent, { jobId: "cmd-1" }), "human_control");
  await rejects(realms.terminal(child, { jobId: "cmd-1" }), "human_control");
  await realms.handBack(principal(client("parent")));
  await realms.off(person);
  await rejects(realms.on(parent, {}), "disabled");
  await rejects(realms.terminal(child, { jobId: "cmd-1" }), "disabled");
  assert.ok(!runtime.state.calls.some(([, input]) => input.owner === "thread:child"));
});

async function pendingSetup(options = {}) {
  const sent = [];
  const s = await setup({ ready: false, sendThread: async (input) => { sent.push(input); if (options.error) throw options.error; }, ...options });
  const who = options.child ? childAgent() : principal(agent("parent"));
  await rejects(s.realms.on(who, {}), "setup_required");
  s.runtime.state.ready = true;
  const person = principal(client("parent"));
  // A successful person-approved setup job; no command arguments belong in its receipt.
  const job = { job_id: "approved-setup", kind: "driver_install", state: "succeeded", created_at: 0 };
  s.runtime.state.jobs.set(job.job_id, job);
  return { ...s, sent, who, person, job };
}

test("a person observes successful setup once and resumes only the requesting thread", async () => {
  const s = await pendingSetup({ child: true });
  // Approval attaches pending requests, even when setup is global on the page.
  await s.realms.setupStart(principal(client()), { reviewId: (await s.realms.setupReview(principal(client()))).data.reviewId });
  await Promise.all([s.realms.jobStatus(s.person, { jobId: s.job.job_id }), s.realms.badge(childClient()), s.realms.status(s.person)]);
  assert.equal(s.sent.length, 1);
  assert.equal(s.sent[0].threadId, "child");
  assert.ok(s.sent[0].idempotencyKey);
  assert.match(s.sent[0].text, /reevaluate/i);
  assert.match(s.sent[0].text, /do not replay/i);
  await s.realms.status(s.person);
  assert.equal(s.sent.length, 1);
});

test("setup continuation is revoked by off, kind switch, expiry, denial or uncertain send", async () => {
  for (const outcome of ["off", "switch", "expired", "denied", "uncertain"]) {
    let clock = 100;
    const s = await pendingSetup({ now: () => clock, error: ["denied", "uncertain"].includes(outcome) ? Object.assign(new Error(outcome), { reason: outcome === "denied" ? "permission_denied" : "storage_failed" }) : undefined });
    if (outcome === "off") await s.realms.off(s.person);
    if (outcome === "switch") await s.realms.on(s.person, { kind: "omarchy-vm" });
    if (outcome === "expired") clock += 3600001;
    await s.realms.setupStart(principal(client()), { reviewId: (await s.realms.setupReview(principal(client()))).data.reviewId });
    await s.realms.status(s.person);
    await s.realms.status(s.person);
    assert.equal(s.sent.length, ["denied", "uncertain"].includes(outcome) ? 1 : 0, outcome);
  }
});

test("manual setup and failed, cancelled, interrupted setup never resume an agent", async () => {
  for (const state of ["failed", "cancelled", "running"]) {
    const s = await pendingSetup();
    s.job.state = state;
    await s.realms.jobStatus(s.person, { jobId: s.job.job_id });
    await s.realms.status(s.person);
    assert.equal(s.sent.length, 0);
  }
  const sent = [];
  const { realms } = await setup({ sendThread: async (input) => sent.push(input) });
  await realms.status(principal(client("manual")));
  assert.equal(sent.length, 0);
});

test("approved detached setup resumes on client polls, never on agent polls, across worker restart", async () => {
  const sent = [];
  const s = await setup({ ready: false, sendThread: async (input) => sent.push(input) });
  const me = principal(agent("parent"));
  await rejects(s.realms.terminal(me, { command: "private-command-never-replayed" }), "setup_required");
  const original = s.runtime.call;
  s.runtime.call = async (command, input, options) => command === "setup_plan"
    ? { ready: false, missing: ["labwc"], packages: ["labwc"], blockers: [], command: "reviewed-command", argv: ["reviewed-command"], reviewId: "approved-plan" }
    : original(command, input, options);
  const started = await s.realms.setupStart(principal(client()), { reviewId: "approved-plan" });
  const job = s.runtime.state.jobs.get(started.data.jobId);
  job.state = "running";
  await s.realms.jobStatus(principal(client()), { jobId: job.job_id });
  s.runtime.state.ready = true;
  job.state = "succeeded";
  await s.realms.status(me);
  assert.equal(sent.length, 0, "an agent cannot trigger continuation");
  const restarted = createRealms({ ...s.options, settings: { get: async () => null }, sendThread: async (input) => sent.push(input) });
  await Promise.all([restarted.badge(principal(client("parent"))), restarted.jobStatus(principal(client()), { jobId: job.job_id })]);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].threadId, "parent");
  assert.ok(!sent[0].text.includes("private-command"));
  assert.ok(!s.runtime.state.calls.some(([command]) => command === "exec"));
});

test("failed or cancelled approved setup cannot continue even if later prerequisites look ready", async () => {
  for (const state of ["failed", "cancelled", "interrupted"]) {
    const sent = [];
    const s = await setup({ ready: false, sendThread: async (input) => sent.push(input) });
    await rejects(s.realms.on(principal(agent("parent")), {}), "setup_required");
    const original = s.runtime.call;
    s.runtime.call = async (command, input, options) => command === "setup_plan"
      ? { ready: false, missing: [], packages: [], blockers: [], reviewId: "approved-plan" }
      : original(command, input, options);
    const started = await s.realms.setupStart(principal(client()), { reviewId: "approved-plan" });
    const job = s.runtime.state.jobs.get(started.data.jobId);
    job.state = state;
    s.runtime.state.ready = true;
    await s.realms.jobStatus(principal(client()), { jobId: job.job_id });
    await s.realms.status(principal(client("parent")));
    assert.equal(sent.length, 0, state);
  }
});

test("shared VM transfer jobs, size and stopping use the owner identity", async () => {
  const { realms, runtime } = await setup();
  const parent = principal(agent("parent"));
  await realms.on(parent, { kind: "omarchy-vm" });
  const job = await realms.files(parent, { action: "push", source: "/source" });
  await realms.files(childAgent(), { action: "status", jobId: job.data.jobId });
  await realms.resize(childAgent(), { size: "1280x720" });
  await realms.stop(childAgent());
  assert.equal((await realms.status(parent)).realm.state, "stopped");
  assert.ok(!runtime.state.calls.some(([, input]) => input.owner === "thread:child"));
});

test("a queued subagent start rechecks the parent's Off after acquiring ownership", async () => {
  const s = await setup();
  await s.realms.on(principal(agent("parent")), {});
  let releaseOff, offEntered, preferenceRead;
  const blocked = new Promise((resolve) => { releaseOff = resolve; });
  const entered = new Promise((resolve) => { offEntered = resolve; });
  const read = new Promise((resolve) => { preferenceRead = resolve; });
  const get = s.storage.get;
  let intercepted = false;
  s.storage.get = async (key) => {
    if (key === "setup-continuations-v1" && !intercepted) {
      intercepted = true;
      offEntered();
      await blocked;
    }
    const value = await get(key);
    if (key.startsWith("thread.")) preferenceRead();
    return value;
  };
  const off = s.realms.off(childClient());
  await entered;
  const queued = s.realms.terminal(childAgent(), { command: "never-after-off", background: true });
  await read;
  const refused = rejects(queued, "disabled");
  releaseOff();
  await off;
  await refused;
  assert.ok(!s.runtime.state.calls.some(([command, input]) => command === "exec" && input.argv.includes("never-after-off")));
});

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const testKey = async (kind, id) => `${kind}.${(await import("node:crypto")).createHash("sha256").update(id).digest("hex")}`;
const boundaryText = (text) => {
  assert.match(text, /only this Realm|this Realm call|Realm actions only/i);
  assert.match(text, /ordinary.*(shell|tools|files).*unaffected/i);
  assert.match(text, /continue.*(work|ordinary)/i);
};
async function robustFixture(t, options) {
  const s = await setup(options);
  t.after(async () => { s.realms.dispose(); await fs.rm(s.dataDirectory, { recursive: true, force: true }); });
  s.me = principal(agent("parent")); s.person = principal(client("parent"));
  return s;
}
function pauseRuntime(s, selected) {
  const entered = deferred(), gate = deferred(), base = s.runtime.call;
  s.runtime.call = async (command, input, options) => {
    if (command === selected) { entered.resolve(); await gate.promise; }
    return base(command, input, options);
  };
  return { entered: entered.promise, release: gate.resolve };
}

test("robust C9/C10: discovery and management preserve the ordinary-tool boundary and correct child context", async (t) => {
  const s = await robustFixture(t);
  const manifest = JSON.parse(await fs.readFile(new URL("../t3-plugin.json", import.meta.url)));
  for (const action of manifest.actions.filter((entry) => entry.agentCallable)) boundaryText(action.description);
  assert.throws(() => principal({ caller: { kind: "agent", threadId: "child", subagentOf: "parent" }, context: { threadId: "parent" } }), (error) => {
    assert.match(error.message, /omit.*override/i); assert.match(error.message, /automatically/i); boundaryText(error.message); return true;
  });
  const { activate, deactivate } = await import("../plugin.mjs");
  const handlers = new Map();
  const interpreter = path.join(s.dataDirectory, "fake-python");
  await fs.writeFile(interpreter, `#!/usr/bin/env python3
import json, sys
command = sys.argv[sys.argv.index('--home') + 2]
results = {'list': [], 'job_list': [], 'doctor': {'ready': True}}
print(json.dumps({'ok': True, 'result': results[command]}))
`, { mode: 0o700 });
  await activate({ storage: s.storage, settings: { get: async (key) => key === "python" ? interpreter : null }, dataDirectory: s.dataDirectory,
    signal: new AbortController().signal, handle: (name, handler) => handlers.set(name, handler) });
  t.after(deactivate);
  // Watch is a real agent management reply that does not require a native runtime.
  const result = await handlers.get("action:realm")({ action: "watch" }, agent("parent"));
  boundaryText(result.message);
  const off = await handlers.get("action:realm")({ action: "off" }, agent("parent"));
  assert.equal(off.data.mode, "off"); boundaryText(off.message); assert.match(off.message, /nothing to exit/i);
  const status = await handlers.get("action:realm")({ action: "status" }, agent("parent"));
  boundaryText(status.message); assert.match(status.message, /off is not needed/i);
  await assert.rejects(handlers.get("action:realm-terminal")({ command: "true" }, agent("parent")), (error) => { boundaryText(error.message); assert.match(error.message, /nothing to exit/i); return true; });
  await assert.rejects(handlers.get("action:realm")({ action: "unknown" }, agent("parent")), (error) => { boundaryText(error.message); return true; });
});

test("robust lineage: unresolved caller ancestry never allocates a separate Realm", () => {
  assert.throws(() => principal({ caller: { kind: "agent", threadId: "child", lineage: "unresolved" } }), (error) => {
    assert.equal(error.code, "lineage_unresolved"); assert.match(error.message, /retry.*status/i); boundaryText(error.message); return true;
  });
  assert.equal(principal(agent("root")).threadId, "root");
});

for (const turnOnAgain of [false, true]) test(`robust B4/parity1: Off${turnOnAgain ? " then On" : ""} during cold preparation fences input and session publication`, async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {});
  const gate = pauseRuntime(s, "driver_launcher");
  const pending = s.realms.computer(childAgent(), { tool: "click", arguments: {} });
  const refused = rejects(pending, "disabled");
  await gate.entered; await s.realms.off(s.person);
  if (turnOnAgain) await s.realms.on(s.person, {});
  gate.release(); await refused;
  assert.deepEqual(s.cuaCalls, []); assert.ok(s.runtime.state.sessions.every((session) => session.closed));
});

test("robust B5: disposal invalidates a connection completing after session ready", async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {});
  const gate = pauseRuntime(s, "driver_launcher");
  const pending = s.realms.computer(s.me, { tool: "click" }); const refused = rejects(pending, "cancelled");
  await gate.entered; s.realms.dispose(); gate.release(); await refused;
  assert.deepEqual(s.cuaCalls, []); assert.ok(s.runtime.state.sessions.every((session) => session.closed));
});

for (const handBack of [false, true]) test(`robust parity2: capture withholds and removes pixels after takeover${handBack ? " and handback" : ""}`, async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {});
  await fs.mkdir(path.join(s.dataDirectory, "assets"));
  const asset = path.join(s.dataDirectory, "assets/shot-1.jpg"); await fs.writeFile(asset, "private pixels");
  const gate = pauseRuntime(s, "shot"); const pending = s.realms.shot(s.me); const refused = rejects(pending, "human_control");
  await gate.entered; await s.realms.takeControl(s.person); if (handBack) await s.realms.handBack(s.person);
  gate.release(); await refused; await assert.rejects(fs.stat(asset), { code: "ENOENT" });
});

for (const kind of ["realm", "omarchy-vm"]) test(`robust parity3: retained ${kind} Stop preserves another kind startup`, async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, { kind });
  const old = s.runtime.state.records.get(state.realm.id); old.status = "stopped";
  s.runtime.state.jobs.set("other-start", { job_id: "other-start", owner: "thread:parent", kind: "start", state: "running", input: { config: { kind: kind === "realm" ? "omarchy-vm" : "realm" } } });
  await s.realms.stopById(s.person, { realmId: old.id });
  assert.ok(!s.runtime.state.calls.some(([command, input]) => command === "job_cancel" && input.job_id === "other-start"));
});

test("robust B8: cancelled queued Off never mutates preferences and releases its lock", async (t) => {
  const s = await robustFixture(t); const gate = pauseRuntime(s, "job_start");
  const starting = s.realms.on(s.me, {}); await gate.entered;
  const controller = new AbortController(); const off = s.realms.off(s.person, { signal: controller.signal });
  controller.abort(); const refused = rejects(off, "cancelled"); gate.release(); await starting; await refused;
  assert.equal((await s.realms.status(s.me)).mode, "realm");
  assert.equal((await s.realms.off(s.person)).mode, "off");
});

test("robust B3: malformed saved kind recovers without clearing a person's Off", async (t) => {
  const s = await robustFixture(t); const key = await testKey("thread", "parent");
  await s.storage.set(key, { kind: "not-a-kind", mode: "off", setBy: "user" });
  assert.equal((await s.realms.status(s.me)).mode, "off");
  await rejects(s.realms.on(s.me, { kind: "realm" }), "disabled");
  assert.equal((await s.realms.on(s.person, { kind: "realm" })).kind, "realm");
  assert.equal((await s.realms.terminal(s.me, { command: "true" })).data.exitCode, 0);
});

test("robust C1/C6: cleanup and retained-data recovery expose distinct next steps without starting", async (t) => {
  const s = await robustFixture(t);
  for (const cleanup of [true, false]) {
    s.runtime.state.records.set("retained", { id: "retained", owner: "thread:parent", generation: "g", status: "recovery-required", cleanup_required: cleanup, recovery_reason: cleanup ? "Compute retirement unconfirmed" : "Retained disk changed" });
    const state = await s.realms.status(s.me); assert.equal(state.realm.cleanupRequired, cleanup);
    assert.match(state.realm.nextStep, cleanup ? /retry Stop/ : /preserve.*data/i);
    for (const use of [() => s.realms.terminal(s.me, { command: "true" }), () => s.realms.computer(s.me, { tool: "list" }), () => s.realms.repair(s.me)])
      await assert.rejects(use(), (error) => { assert.equal(error.code, "recovery_required"); boundaryText(error.message); return true; });
  }
  assert.ok(!s.runtime.state.calls.some(([command]) => command === "job_start"));
  s.runtime.state.records.get("retained").status = "cleanup_failed";
  const status = await s.realms.status(s.me); assert.match(status.realm.nextStep, /retry Stop/);
});

test("robust C3: failed detached boot remains visible and implicit tools do not reboot", async (t) => {
  const s = await robustFixture(t); const job = { job_id: "failed-boot", owner: "thread:parent", kind: "start", state: "failed", code: "timeout", error: "boot deadline expired", input: { config: { kind: "realm" } } };
  s.runtime.state.jobs.set(job.job_id, job);
  const status = await s.realms.status(s.me); assert.equal(status.startAttempt.jobId, job.job_id); assert.equal(status.startAttempt.error, job.error);
  await assert.rejects(s.realms.terminal(s.me, { command: "true" }), (error) => { assert.match(error.message, /boot deadline expired/); assert.match(error.message, /action.*on/); return true; });
  assert.ok(!s.runtime.state.calls.some(([command]) => command === "job_start"));
  assert.equal((await s.realms.on(s.me, {})).realm.state, "live");
});

test("robust C2: failed staging is visible, wrong-kind poll is actionable and no second staging starts", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, { kind: "omarchy-vm" });
  const job = { job_id: "driver-stage", owner: "thread:parent", kind: "vm_driver", state: "failed", error: "Guest driver checksum mismatch", input: { id: state.realm.id, incarnation: "g1" } };
  s.runtime.state.jobs.set(job.job_id, job);
  assert.equal((await s.realms.status(s.me)).driverPreparation.error, job.error);
  await assert.rejects(s.realms.computer(s.me, { tool: "list" }), /checksum mismatch/);
  assert.ok(!s.runtime.state.calls.some(([command]) => command === "driver_launcher"));
  await assert.rejects(s.realms.files(s.me, { action: "status", jobId: job.job_id }), (error) => {
    assert.equal(error.code, "invalid_input"); assert.match(error.message, /driver.*status/i); return true;
  });
});

test("robust C4: failed takeover keeps a scoped hold across workers until person Hand back", async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {}); const base = s.runtime.call;
  s.runtime.call = async (command, input, options) => { if (command === "vnc_endpoint") throw new RealmError("not_running", "Display unavailable"); return base(command, input, options); };
  await rejects(s.realms.takeControl(s.person), "not_running");
  const restarted = createRealmsLike(s); t.after(() => restarted.dispose());
  assert.equal((await restarted.status(s.person)).realm.controlConnection, "failed");
  await assert.rejects(restarted.terminal(childAgent(), { command: "true" }), (error) => { boundaryText(error.message); assert.match(error.message, /Hand back/); return true; });
  await restarted.handBack(s.person); assert.equal((await restarted.terminal(childAgent(), { command: "true" })).data.exitCode, 0);
});

for (const method of ["get", "set"]) test(`robust C8: optional continuation ${method} failure preserves setup blocker`, async (t) => {
  const s = await robustFixture(t, { ready: false }); const original = s.storage[method];
  s.storage[method] = async (key, ...args) => { if (key === "setup-continuations-v1") throw new Error("Notification store offline"); return original(key, ...args); };
  await assert.rejects(s.realms.terminal(s.me, { command: "true" }), (error) => {
    assert.equal(error.code, "setup_required"); assert.match(error.message, /labwc/); assert.match(error.message, /manually/); boundaryText(error.message); return true;
  });
  assert.ok(!s.runtime.state.calls.some(([command]) => command === "job_start"));
});

test("robust C11: unavailable setup continuation is visible on repeated client observations", async (t) => {
  const s = await robustFixture(t, { ready: false }); await rejects(s.realms.terminal(s.me, { command: "true" }), "setup_required");
  s.runtime.state.ready = true; await s.realms.setupStart(s.person, { reviewId: "ready-plan" });
  for (let i = 0; i < 2; i++) {
    const state = await s.realms.status(s.person); assert.equal(state.setup.ready, true);
    assert.equal(state.continuation[0].state, "unavailable"); assert.match(state.continuation[0].message, /ask the agent to continue/i);
  }
});

test("robust C5: argument data and inherited private endpoints execute, overrides stay scoped", async (t) => {
  const s = await robustFixture(t);
  for (const command of ["printf '%s\\n' A=1 DISPLAY=:0", 'env WAYLAND_DISPLAY="$WAYLAND_DISPLAY" true'])
    assert.equal((await s.realms.terminal(s.me, { command })).data.exitCode, 0);
  await assert.rejects(s.realms.terminal(s.me, { command: "DISPLAY=:0 xdotool key Return" }), (error) => { boundaryText(error.message); assert.match(error.message, /remove.*override/i); return true; });
});

test("robust C7/B7: ambiguous exec reports uncertainty; admitted cancelled job stays controllable", async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {}); const base = s.runtime.call;
  s.runtime.call = async (command, input, options) => { if (command === "exec") throw new RealmError("timeout", "reply lost"); return base(command, input, options); };
  await assert.rejects(s.realms.terminal(s.me, { command: "write-once" }), (error) => { assert.match(error.message, /may already have started/); assert.match(error.message, /not.*resubmit.*blindly/i); boundaryText(error.message); return true; });
  const controller = new AbortController();
  s.runtime.call = async (command, input, options) => { const result = await base(command, input, options); if (command === "exec") controller.abort(); if (options?.signal?.aborted) throw new RealmError("cancelled", "cancelled"); return result; };
  // Acknowledgement may be lost; inspect status for any durable receipt when available.
  await assert.rejects(s.realms.terminal(s.me, { command: "long-command" }, { signal: controller.signal }), /may already have started|job cmd-1/);
});

test("robust B7: foreground cancellation preserves the acknowledged job id in status", async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {}); const controller = new AbortController(), base = s.runtime.call;
  s.runtime.call = async (command, input, options) => {
    if (command === "job") { controller.abort(); throw new RealmError("cancelled", "poll cancelled"); }
    return base(command, input, options);
  };
  await assert.rejects(s.realms.terminal(s.me, { command: "long-command" }, { signal: controller.signal }), /cmd-1/);
  const status = await s.realms.status(s.me); assert.equal(status.terminalJobs[0].jobId, "cmd-1");
  s.runtime.call = base; assert.equal((await s.realms.terminal(childAgent(), { jobId: "cmd-1", signal: "TERM" })).data.jobId, "cmd-1");
});

for (const method of ["shot", "frame"]) test(`robust B6: ${method} never returns an image above the host limit`, async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {}); const base = s.runtime.call;
  await fs.mkdir(path.join(s.dataDirectory, "assets")); const asset = path.join(s.dataDirectory, "assets/shot-large.jpg"); await fs.writeFile(asset, Buffer.alloc(4 * 1024 * 1024 + 1));
  s.runtime.call = async (command, input, options) => command === "shot" ? { path: "assets/shot-large.jpg", mimeType: "image/jpeg", bytes: 1, width: 3840, height: 2160 } : base(command, input, options);
  await assert.rejects(s.realms[method](method === "frame" ? s.person : s.me, { scale: 1 }), (error) => { assert.equal(error.code, "image_too_large"); assert.match(error.message, /smaller|scale|zoom/i); return true; });
  await assert.rejects(fs.stat(asset), { code: "ENOENT" });
});

test("robust B9: status observing idle retirement closes the old MCP proxy", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, {}); await s.realms.computer(s.me, { tool: "list" });
  s.runtime.state.records.get(state.realm.id).status = "stopped"; await s.realms.status(s.person);
  assert.ok(s.runtime.state.sessions.every((session) => session.closed));
});

test("robust B1/B2: regular driver retirement is native-owned even without plugin tracking", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, {}); await s.realms.computer(s.me, { tool: "list" });
  await s.storage.delete(await testKey("driver", state.realm.id)); const base = s.runtime.call;
  let retired = false;
  s.runtime.call = async (command, input, options) => {
    if (command === "driver_stop") { assert.equal(input.incarnation, "g1"); retired = true; return { retired: true }; }
    return base(command, input, options);
  };
  await s.realms.repair(s.me); assert.equal(retired, true);
});

test("robust Off: cleanup failure stays visible after access was successfully revoked", async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {}); const base = s.runtime.call;
  s.runtime.call = async (command, input, options) => { if (command === "driver_stop") throw new Error("owned endpoint retirement unavailable"); return base(command, input, options); };
  const state = await s.realms.off(s.person);
  assert.equal(state.mode, "off"); assert.equal(state.driverCleanup.state, "failed"); assert.match(state.driverCleanup.nextStep, /Stop/);
  await rejects(s.realms.terminal(s.me, { command: "true" }), "disabled");
});

test("robust C7: lost GUI reply gives bounded repair guidance without replaying input", async (t) => {
  const s = await robustFixture(t); await s.realms.computer(s.me, { tool: "list" }); let inputs = 0;
  s.runtime.state.sessions[0].call = async () => { inputs++; throw new RealmError("driver_unavailable", "driver exited"); };
  await assert.rejects(s.realms.computer(s.me, { tool: "click" }), (error) => {
    assert.match(error.message, /may already have landed/); assert.match(error.message, /try one.*repair/i); assert.match(error.message, /fresh capture/); boundaryText(error.message); return true;
  });
  assert.equal(inputs, 1);
});

test("robust admission: Off while transfer touch waits prevents admission", async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, { kind: "omarchy-vm" });
  const gate = pauseRuntime(s, "touch"); const pending = s.realms.files(s.me, { action: "push", source: "/source" }); const refused = rejects(pending, "disabled");
  await gate.entered; await s.realms.off(s.person); gate.release(); await refused;
  assert.ok(!s.runtime.state.calls.some(([command, input]) => command === "job_start" && input.kind === "transfer"));
});

test("robust C11: denied and uncertain continuation outcomes are visible without dispatch retry", async (t) => {
  for (const state of ["denied", "uncertain"]) {
    let attempts = 0;
    const s = await robustFixture(t, { ready: false, sendThread: async () => { attempts++; throw Object.assign(new Error("send unconfirmed"), { code: state === "denied" ? "permission_denied" : "storage_failed" }); } });
    await rejects(s.realms.on(s.me, {}), "setup_required"); s.runtime.state.ready = true;
    await s.realms.setupStart(s.person, { reviewId: "ready-plan" });
    for (let i = 0; i < 2; i++) { const status = await s.realms.status(s.person); assert.equal(status.continuation[0].state, state); assert.equal(status.continuation[0].manualContinuationRequired, true); }
    assert.equal(attempts, 1);
  }
});

test("robust C1: broken inventory still exposes status and exact person Stop recovery", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, {}); const base = s.runtime.call;
  s.runtime.call = async (command, input, options) => { if (command === "list") throw new Error("Permission denied: unrelated cleanup"); return base(command, input, options); };
  const status = await s.realms.status(s.me); assert.match(status.runtimeFailure.error, /unrelated cleanup/); assert.match(status.runtimeFailure.nextStep, /person.*cleanup/i);
  assert.equal((await s.realms.off(s.person)).mode, "off");
  await s.realms.stopById(s.person, { realmId: state.realm.id });
  assert.equal(s.runtime.state.records.get(state.realm.id).status, "stopped");
});

test("robust B2: a duplicate serve that exits during handshake is never adopted", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, {}); await s.realms.computer(s.me, { tool: "list" });
  const key = await testKey("driver", state.realm.id); await s.storage.delete(key); s.runtime.state.sessions[0].close();
  const base = s.runtime.call;
  s.runtime.call = async (command, input, options) => {
    const result = await base(command, input, options);
    if (command === "job" && input.job_id === "serve-2") s.runtime.state.daemonJobs.get(input.job_id).returncode = 1;
    return result;
  };
  await assert.rejects(s.realms.computer(s.me, { tool: "click" }), /identity.*not adopted|retirement.*unconfirmed/i);
  assert.notEqual((await s.storage.get(key))?.jobId, "serve-2");
  assert.deepEqual(s.cuaCalls, []);
});

test("robust disposal: late session-ready completion closes the unpublished proxy", async (t) => {
  const s = await robustFixture(t); await s.realms.on(s.me, {});
  const ready = deferred(), entered = deferred();
  const restarted = createRealms({ ...s.options, settings: { get: async () => null }, connectCua: () => {
    const session = { closed: false, ready: ready.promise, close() { this.closed = true; }, call() { throw new Error("must not dispatch"); } };
    s.runtime.state.sessions.push(session); entered.resolve(); return session;
  } });
  t.after(() => restarted.dispose());
  const pending = restarted.computer(s.me, { tool: "click" }); const refused = rejects(pending, "cancelled");
  await entered.promise; restarted.dispose(); ready.resolve(); await refused;
  assert.ok(s.runtime.state.sessions.every((session) => session.closed));
});

test("robust parity3: exact prepared startup cancels, stale incarnation startup survives", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, {}); const record = s.runtime.state.records.get(state.realm.id); record.status = "starting";
  for (const generation of ["older", "g1"]) {
    s.runtime.state.calls.length = 0; record.status = "starting";
    s.runtime.state.jobs.set("exact-start", { job_id: "exact-start", owner: record.owner, kind: "start", state: "running", input: { config: { kind: "realm" } }, progress: { realm_id: record.id, generation } });
    await s.realms.stopById(s.person, { realmId: record.id });
    assert.equal(s.runtime.state.calls.some(([command, input]) => command === "job_cancel" && input.job_id === "exact-start"), generation === "g1");
  }
});

test("robust status: a long recovery cause fits the host badge and retains its next step", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, {}); const record = s.runtime.state.records.get(state.realm.id);
  record.status = "recovery-required"; record.cleanup_required = true; record.recovery_reason = "x".repeat(6000);
  const badge = await s.realms.badge(s.person); assert.ok(badge.detail.length <= 300); assert.match(badge.detail, /retry Stop/);
});

test("robust C3: observed boot failure survives native job-history pruning", async (t) => {
  const s = await robustFixture(t);
  s.runtime.state.jobs.set("lost-boot", { job_id: "lost-boot", kind: "start", owner: "thread:parent", state: "failed", error: "guest boot failed", input: { config: { kind: "realm" } } });
  await s.realms.status(s.me); s.runtime.state.jobs.clear();
  const status = await s.realms.status(s.me); assert.equal(status.startAttempt?.jobId, "lost-boot");
  await assert.rejects(s.realms.terminal(s.me, { command: "true" }), /guest boot failed/);
  assert.ok(!s.runtime.state.calls.some(([command]) => command === "job_start"));
});

test("robust C2: observed staging failure survives native job-history pruning", async (t) => {
  const s = await robustFixture(t); const state = await s.realms.on(s.me, { kind: "omarchy-vm" });
  s.runtime.state.jobs.set("lost-staging", { job_id: "lost-staging", kind: "vm_driver", owner: "thread:parent", state: "failed", error: "driver checksum mismatch", input: { id: state.realm.id, incarnation: "g1" } });
  await s.realms.status(s.me); s.runtime.state.jobs.clear();
  const status = await s.realms.status(s.me); assert.equal(status.driverPreparation?.jobId, "lost-staging");
  await assert.rejects(s.realms.computer(s.me, { tool: "list" }), /checksum mismatch/);
  assert.ok(!s.runtime.state.calls.some(([command]) => command === "driver_launcher"));
});

test("native VM: allocated compute is usable until retirement actually needs recovery", async (t) => {
  const s = await setup();
  t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "agent", threadId: "vm-live-cleanup" };
  const started = await s.realms.on(who, { kind: "omarchy-vm" });
  const record = s.runtime.state.records.get(started.realm.id);
  record.cleanup_required = true;
  for (const state of ["starting", "running", "stopping"]) {
    record.status = state;
    const status = await s.realms.status(who);
    assert.equal(status.realm.needsRecovery, false);
    assert.equal(status.realm.cleanupRequired, false);
    assert.equal(status.realm.nextStep, null);
  }
  record.status = "running";
  assert.equal((await s.realms.terminal(who, { command: "true" })).data.exitCode, 0);
  await s.realms.computer(who, { tool: "list" });
  assert.equal((await s.realms.badge(who)).label, "Live");
  record.status = "recovery-required";
  assert.equal((await s.realms.status(who)).realm.needsRecovery, true);
  await rejects(s.realms.terminal(who, { command: "true" }), "recovery_required");
});

test("robust C11: already-ready global setup exposes the requesting thread's manual outcome", async (t) => {
  const s = await robustFixture(t, { ready: false }); await rejects(s.realms.on(s.me, {}), "setup_required"); s.runtime.state.ready = true;
  const result = await s.realms.setupStart({ kind: "user" }, { reviewId: "ready-plan" });
  assert.equal(result.data.continuation[0]?.threadId, "parent"); assert.equal(result.data.continuation[0].state, "unavailable");
});

test("native requalification: terminal transfer failures describe the failure and explicit recovery", async (t) => {
  const s = await setup();
  t.after(() => fs.rm(s.dataDirectory, { recursive: true, force: true }));
  const who = { kind: "agent", threadId: "transfer-diagnostic" };
  await s.realms.on(who, { kind: "omarchy-vm" });
  for (const state of ["failed", "cancelled"]) {
    s.runtime.state.jobs.set(state, { job_id: state, kind: "transfer", owner: "thread:transfer-diagnostic", state,
      error: state === "failed" ? "Destination conflict: retained.txt" : "Operation cancelled" });
    const result = await s.realms.files(who, { action: "status", jobId: state });
    assert.match(result.message, new RegExp(state));
    assert.match(result.message, /Only this Realm transfer/);
    assert.match(result.message, /Inspect.*source.*destination/);
    assert.match(result.message, /explicit retry/);
    assert.match(result.message, /do not blindly replay/i);
    assert.match(result.message, state === "failed" ? /Destination conflict: retained.txt/ : /Operation cancelled/);
    assert.equal(result.data.state, state);
  }
  assert.equal(s.runtime.state.calls.filter(([command, input]) => command === "job_start" && input.kind === "transfer").length, 0);
});

// ---- first-run setup ---------------------------------------------------------------------------

/** A machine missing only plugin-local parts, unless `plan` says otherwise. */
async function firstRun({ plan = {}, finishes = true, ...options } = {}) {
  const s = await setup({ ready: false, ...options });
  const original = s.runtime.call;
  s.runtime.call = async (command, input, ...rest) => {
    if (command === "setup_plan")
      return { kind: input.config.kind ?? "realm", ready: s.runtime.state.ready, missing: [], blockers: [], packages: [], reviewId: "plan-1", halt: s.halt ?? null, ...plan };
    if (command === "vm_download") return { bytes: 2 * 1024 ** 3, estimatedBytes: 5 * 1024 ** 3 };
    const result = await original(command, input, ...rest);
    if (command === "job_start" && input.input?.unattended) {
      const job = s.runtime.state.jobs.get(result.job_id);
      job.state = finishes ? "succeeded" : "running";
      if (finishes) s.runtime.state.ready = true;
    }
    return result;
  };
  s.unattended = () => s.runtime.state.calls.filter(([command, input]) => command === "job_start" && input.input?.unattended);
  return s;
}

test("an agent installs a missing driver and gets its Realm in the same call, with nothing to approve", async () => {
  const sent = [];
  const s = await firstRun({ cards: true, sendThread: async (input) => sent.push(input) });
  const state = await s.realms.on(principal(agent("t1")), {});
  assert.equal(state.realm.state, "live");
  assert.equal(s.unattended().length, 1);
  assert.equal(s.unattended()[0][1].input.review_id, "plan-1");
  await s.realms.status(principal(client("t1")));
  assert.equal(sent.length, 0, "the agent never stopped, so nothing resumes it");
  assert.equal(state.continuation.length, 0);
});

test("system packages and other host changes never start unattended and show one card", async () => {
  for (const plan of [{ packages: ["labwc"], command: "pkexec pacman" }, { blockers: ["KVM access is required"] }, { resources: { blockers: ["Insufficient free storage"] } }]) {
    const s = await firstRun({ plan, cards: true });
    const me = principal(agent("t1"));
    const first = await s.realms.on(me, {}).catch((error) => error);
    assert.equal(first.code, "setup_required");
    assert.equal(first.card.viewId, "setup");
    assert.deepEqual(first.card.data, { kind: "realm" });
    const second = await s.realms.on(me, {}).catch((error) => error);
    assert.equal(second.code, "setup_required");
    assert.equal(second.card, undefined, "repeat calls don't repeat the card");
    assert.equal(s.unattended().length, 0);
  }
});

test("hosts without chat cards point to the panel instead of a card that isn't there", async () => {
  for (const options of [{ plan: { packages: ["labwc"] } }, { plan: { halt: { state: "failed", error: "offline", job_id: "old" } } }]) {
    const s = await firstRun(options);
    const error = await s.realms.on(principal(agent("t1")), {}).catch((failure) => failure);
    assert.equal(error.card, undefined);
    assert.match(error.message, /Realm panel/);
    assert.doesNotMatch(error.message, /card/);
  }
});

test("a retry after failure shows the packages it would install", async () => {
  const s = await firstRun({ plan: { packages: ["qemu-full"], command: "pkexec pacman", halt: { state: "failed", error: "changed", job_id: "old" } } });
  const card = (await s.realms.setupState(principal(client("t1")), {})).data;
  assert.deepEqual([card.phase, card.packages, card.command], ["failed", ["qemu-full"], "pkexec pacman"]);
});

test("an agent's on against a running Realm settles its pending resume", async () => {
  const sent = [];
  const s = await firstRun({ finishes: false, sendThread: async (input) => sent.push(input) });
  const me = principal(agent("t1"));
  await rejects(s.realms.on(me, {}), "preparing");
  s.runtime.state.ready = true;
  const job = [...s.runtime.state.jobs.values()].find((entry) => entry.kind === "setup");
  job.state = "succeeded";
  await s.realms.on(me, {});
  await s.realms.on(me, {});
  await s.realms.status(principal(client("t1")));
  assert.equal(sent.length, 0);
});

test("turning automatic installs off leaves the install to a person", async () => {
  const s = await firstRun({ cards: true });
  const person = principal(client());
  await rejects(s.realms.setAutoInstall(principal(agent("t1")), { enabled: true }), "ownership");
  await s.realms.setAutoInstall(person, { enabled: false });
  await rejects(s.realms.on(principal(agent("t1")), {}), "setup_required");
  assert.equal(s.unattended().length, 0);
  assert.equal((await s.realms.setupState(person, {})).data.phase, "approve");
  await s.realms.setAutoInstall(person, { enabled: true });
  assert.equal((await s.realms.on(principal(agent("t1")), {})).realm.state, "live");
});

test("a person's cancel and a failure stay stopped until a person retries", async () => {
  for (const state of ["cancelled", "failed"]) {
    const s = await firstRun({ cards: true });
    s.halt = { state, error: "offline", job_id: "old" };
    await rejects(s.realms.on(principal(agent("t1")), {}), "setup_required");
    assert.equal(s.unattended().length, 0);
    const card = (await s.realms.setupState(principal(client("t1")), {})).data;
    assert.equal(card.phase, state);
    assert.equal(card.reviewId, "plan-1");
  }
});

test("a dead job's failure counts before the agent decides to install", async () => {
  const s = await firstRun({ cards: true });
  const original = s.runtime.call;
  s.runtime.call = async (command, input, ...rest) => {
    // Listing reconciles a dead job, which is what publishes its halt.
    if (command === "job_list") s.halt = { state: "failed", error: "interrupted", job_id: "dead" };
    return original(command, input, ...rest);
  };
  await rejects(s.realms.on(principal(agent("t1")), {}), "setup_required");
  assert.equal(s.unattended().length, 0);
});

test("Agent Off stops unattended installs", async () => {
  const s = await firstRun();
  await s.realms.off(principal(client("t1")));
  await rejects(s.realms.on(principal(agent("t1")), {}), "disabled");
  assert.equal(s.unattended().length, 0);
});

test("the VM prepares in the background, survives a switch to Desktop and resumes the agent once", async () => {
  const sent = [];
  const s = await firstRun({ finishes: false, cards: true, sendThread: async (input) => sent.push(input) });
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  const first = await s.realms.on(me, { kind: "omarchy-vm" }).catch((error) => error);
  assert.equal(first.code, "preparing");
  assert.equal(first.card.viewId, "setup");
  assert.deepEqual(first.card.data, { kind: "omarchy-vm" });
  const again = await s.realms.on(me, { kind: "omarchy-vm" }).catch((error) => error);
  assert.equal(again.code, "preparing");
  assert.equal(again.card, undefined);
  assert.equal(s.unattended().length, 1, "a second call attaches to the running job");
  assert.equal((await s.realms.badge(person)).label, "Preparing");
  assert.ok((await s.realms.status(me)).setup.job);
  const card = (await s.realms.setupState(person, { kind: "omarchy-vm" })).data;
  assert.equal(card.phase, "installing");

  // Desktop is ready while the VM isn't, so the agent carries on there.
  const job = s.unattended()[0];
  const original = s.runtime.call;
  s.runtime.call = async (command, input, ...rest) => {
    if (command === "doctor") return { ready: input.config.kind !== "omarchy-vm" || s.vmReady === true, missing: [], message: "x", driver: { verified: true } };
    if (command === "setup_plan" && input.config.kind === "omarchy-vm") return { kind: "omarchy-vm", ready: s.vmReady === true, missing: [], blockers: [], packages: [], reviewId: "plan-1" };
    return original(command, input, ...rest);
  };
  assert.equal((await s.realms.on(me, { kind: "realm" })).realm.state, "live");
  assert.ok(job);
  s.vmReady = true;
  [...s.runtime.state.jobs.values()].find((entry) => entry.kind === "vm_setup").state = "succeeded";
  await s.realms.status(person);
  await s.realms.status(person);
  assert.equal(sent.length, 1);
  assert.match(sent[0].text, /Omarchy VM setup succeeded/);
  assert.match(sent[0].text, /kind "omarchy-vm"/);
  assert.match(sent[0].text, /Do not replay/);
});

test("Off still revokes an unattended install's resume", async () => {
  const sent = [];
  const s = await firstRun({ finishes: false, sendThread: async (input) => sent.push(input) });
  const me = principal(agent("t1"));
  await rejects(s.realms.on(me, { kind: "omarchy-vm" }), "preparing");
  await s.realms.off(principal(client("t1")));
  s.runtime.state.ready = true;
  [...s.runtime.state.jobs.values()].find((entry) => entry.kind === "vm_setup").state = "succeeded";
  await s.realms.status(principal(client("t1")));
  assert.equal(sent.length, 0);
});

test("a blocked resume explains itself and offers a way on, and only after setup", async () => {
  const denied = Object.assign(new Error("no"), { reason: "permission_denied" });
  const s = await firstRun({ finishes: false, sendThread: async () => { throw denied; } });
  const me = principal(agent("t1"));
  const person = principal(client("t1"));
  await rejects(s.realms.on(me, { kind: "omarchy-vm" }), "preparing");
  assert.equal((await s.realms.status(person)).continuation.filter((entry) => entry.manualContinuationRequired).length, 0);
  s.runtime.state.ready = true;
  [...s.runtime.state.jobs.values()].find((entry) => entry.kind === "vm_setup").state = "succeeded";
  const card = (await s.realms.setupState(person, { kind: "omarchy-vm" })).data;
  assert.equal(card.phase, "ready");
  assert.equal(card.resumeBlocked, true);
  assert.match(card.resumeMessage, /Settings → Plugins/);
  const nudge = await s.realms.continueAgent(person);
  assert.equal(nudge.data.sent, false);
  assert.match(nudge.data.text, /continue/);
  assert.equal(nudge.intents, undefined, "cards have no composer");
  assert.equal((await s.realms.setupState(person, { kind: "omarchy-vm" })).data.resumeBlocked, true, "a refused message settles nothing");
  await rejects(s.realms.continueAgent(me), "ownership");
});

test("the card reports packages for a person's reviewed install", async () => {
  const s = await firstRun({ plan: { packages: ["qemu-full"], command: "pkexec pacman", reviewId: "plan-2" } });
  const person = principal(client("t1"));
  const card = (await s.realms.setupState(person, {})).data;
  assert.deepEqual([card.phase, card.packages, card.command, card.reviewId], ["packages", ["qemu-full"], "pkexec pacman", "plan-2"]);
  await rejects(s.realms.setupState(principal(agent("t1")), {}), "ownership");
  await assert.rejects(s.realms.setupState(person, { kind: "other" }), /kind must be/);
});

test("Use Desktop instead switches the thread and tells the agent", async () => {
  const sent = [];
  const s = await firstRun({ plan: { packages: ["qemu-full"] }, sendThread: async (input) => sent.push(input) });
  const person = principal(client("t1"));
  await rejects(s.realms.on(principal(agent("t1")), { kind: "omarchy-vm" }), "setup_required");
  await s.realms.useDesktop(person, {});
  assert.equal((await s.realms.status(person)).kind, "realm");
  assert.match(sent[0].text, /Desktop Realm/);
});

test("removal is a person's: components, and everything only after typing it", async () => {
  const s = await setup();
  const person = principal(client());
  const me = principal(agent("t1"));
  const original = s.runtime.call;
  s.runtime.call = async (command, input, ...rest) => {
    if (command === "components") return { driver: { present: true } };
    if (command === "component_remove") return {};
    return original(command, input, ...rest);
  };
  await rejects(s.realms.components(me), "ownership");
  await rejects(s.realms.removeComponent(me, { component: "driver" }), "ownership");
  await rejects(s.realms.removeEverything(me, { phrase: "remove everything" }), "ownership");
  await rejects(s.realms.removeComponent(person, { component: "other" }), "invalid_input");
  assert.equal((await s.realms.components(person)).data.autoInstall, true);
  await rejects(s.realms.removeEverything(person, { phrase: "yes" }), "invalid_input");
  await s.realms.on(me, {});
  await rejects(s.realms.removeEverything(person, { phrase: "remove everything" }), "busy");
  await s.realms.stop(principal(client("t1")));
  const result = await s.realms.removeEverything(person, { phrase: "remove everything" });
  assert.ok(s.runtime.state.jobs.get(result.data.jobId), "large machines outlast a host call, so this is a job");
  assert.equal(s.runtime.state.jobs.get(result.data.jobId).kind, "teardown");
});
