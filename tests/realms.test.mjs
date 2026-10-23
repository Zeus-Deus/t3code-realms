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
  const state = { ready, records: new Map(), jobs: new Map(), calls: [], next: 1, sessions: [] };
  const record = (owner) => [...state.records.values()].filter((entry) => entry.owner === owner);
  const call = async (command, input = {}) => {
    state.calls.push([command, input]);
    switch (command) {
      case "doctor":
        return { ready: state.ready, missing: state.ready ? [] : ["labwc", "verified cua-driver"], message: state.ready ? "Ready" : "Install labwc", driver: { verified: state.ready } };
      case "list":
        return [...state.records.values()].filter((entry) => !input.owner || entry.owner === input.owner);
      case "job_list":
        return [...state.jobs.values()].filter((job) => !input.owner || job.owner === input.owner);
      case "job_start": {
        const job_id = `job-${state.next++}`;
        state.jobs.set(job_id, { job_id, kind: input.kind, owner: input.owner, state: "succeeded" });
        if (input.kind === "start") {
          const id = `r-${String(state.next++).padStart(24, "0")}`;
          state.records.set(id, { id, owner: input.owner, status: "running", generation: "g1", size: input.input.config.size });
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
      case "exec":
        if (input.argv[1] === "serve") return { job_id: "serve-1", pid: 43 };
        return { job_id: "cmd-1", pid: 42 };
      case "job":
        if (input.job_id === "serve-1") return { job_id: "serve-1", returncode: null };
        return { job_id: input.job_id, returncode: 0, stdout: "hi\n", stderr: "" };
      case "signal":
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

function memoryStorage() {
  const values = new Map();
  return {
    values,
    get: async (key) => (values.has(key) ? structuredClone(values.get(key)) : null),
    set: async (key, value) => void values.set(key, structuredClone(value)),
    delete: async (key) => void values.delete(key),
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

test("unsupported kinds and the Omarchy VM are explicit, not silently mapped", async () => {
  const { realms } = await setup();
  await rejects(realms.on(principal(agent("t1")), { kind: "omarchy-vm" }), "unsupported");
});

test("the thread status stays quiet until a thread uses a Realm and never lies about control", async () => {
  const { realms } = await setup();
  const person = principal(client("t1"));
  assert.equal(await realms.badge(person), null);
  await realms.on(principal(agent("t1")), {});
  assert.deepEqual((await realms.badge(person)).label, "Realm live");
  await realms.takeControl(person);
  assert.equal((await realms.badge(person)).tone, "warning");
  await realms.handBack(person);
  await realms.off(person);
  assert.equal((await realms.badge(person)).label, "Realm live · agent off");
  await realms.stop(person);
  assert.equal((await realms.badge(person)).label, "Realm off");
});

test("setup approval starts the pinned driver install when only the driver is missing", async () => {
  const { realms, runtime } = await setup({ ready: false });
  const original = runtime.call;
  runtime.call = async (command, input) =>
    command === "doctor"
      ? { ready: false, missing: ["verified cua-driver"], message: "Install driver", driver: { verified: false } }
      : original(command, input);
  const person = principal(client());
  const review = (await realms.setupReview(person)).data;
  assert.deepEqual(review.missing, []);
  const started = await realms.setupStart(person, { reviewId: review.reviewId });
  assert.ok(started.data.jobId);
  assert.ok(runtime.state.calls.some(([command, input]) => command === "job_start" && input.kind === "driver_install"));
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
