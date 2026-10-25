// Minimal MCP stdio client for the pinned cua-driver, launched only through the Realm's
// contained launcher. One session per running Realm generation; Repair discards it.
import { spawn } from "node:child_process";
import { RealmError } from "./runtime.mjs";

const PROTOCOL_VERSION = "2025-06-18";
const MAX_LINE_BYTES = 48 * 1024 * 1024;

export function createCuaSession({ command, args = ["mcp"], env, version = "0.0.0", startupTimeoutMs = 15_000 }) {
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"], env });
  const pending = new Map();
  let next = 1;
  let buffer = Buffer.alloc(0);
  let closed = false;
  let closeReason = "The Realm GUI driver stopped.";
  const fail = (reason) => {
    if (closed) return;
    closed = true;
    closeReason = reason;
    for (const { reject, cleanup } of pending.values()) {
      cleanup();
      reject(new RealmError("driver_unavailable", reason));
    }
    pending.clear();
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
  };
  // A write racing the driver's exit must not become an uncaught error that kills the worker.
  child.stdin.on("error", () => fail("The Realm GUI driver closed its input."));
  const write = (message) => {
    if (closed) return false;
    child.stdin.write(`${JSON.stringify(message)}\n`);
    return true;
  };
  const handle = (message) => {
    if (message && "id" in message && ("result" in message || "error" in message)) {
      const entry = pending.get(message.id);
      if (!entry) return;
      pending.delete(message.id);
      entry.cleanup();
      if (message.error) entry.reject(new RealmError("driver_error", String(message.error.message ?? "GUI driver error.").slice(0, 2_000)));
      else entry.resolve(message.result);
      return;
    }
    // The driver may ask the client for roots or sampling; this client offers neither.
    if (message && "id" in message && typeof message.method === "string")
      write({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Not supported" } });
  };
  child.stdout.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    let index;
    while ((index = buffer.indexOf(0x0a)) >= 0) {
      const line = buffer.subarray(0, index).toString("utf8").trim();
      buffer = buffer.subarray(index + 1);
      if (!line) continue;
      try {
        handle(JSON.parse(line));
      } catch {
        fail("The Realm GUI driver sent an invalid message.");
        return;
      }
    }
    if (buffer.length > MAX_LINE_BYTES) fail("The Realm GUI driver sent an oversized message.");
  });
  // A bounded tail explains a driver that refuses to start (missing library, bad flag).
  let stderrTail = "";
  child.stderr.on("data", (chunk) => {
    stderrTail = (stderrTail + chunk.toString("utf8")).slice(-2_000);
  });
  const withDetail = (reason) => {
    const detail = stderrTail.trim().split("\n").filter(Boolean).at(-1);
    return detail ? `${reason} ${detail.slice(0, 300)}` : reason;
  };
  child.once("error", () => fail("The Realm GUI driver could not start."));
  child.once("close", (code, signal) =>
    fail(withDetail(`The Realm GUI driver exited (${signal ?? `code ${code}`}).`)),
  );
  const request = (method, params, { timeoutMs = 30_000, signal } = {}) =>
    new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(new RealmError("cancelled", "This Realm GUI request was cancelled before dispatch. Take a fresh capture before a new request."));
        return;
      }
      if (closed) {
        reject(new RealmError("driver_unavailable", closeReason));
        return;
      }
      const id = next++;
      const timer = setTimeout(() => {
        pending.delete(id);
        signal?.removeEventListener("abort", abort);
        // An unanswered input request may still land; the connection is no longer trustworthy.
        fail("The Realm GUI driver did not answer in time.");
        reject(new RealmError("timeout", "The Realm GUI driver did not answer in time."));
      }, timeoutMs);
      const abort = () => {
        if (!pending.has(id)) return;
        pending.delete(id);
        cleanup();
        fail("The GUI request was cancelled; the driver connection was reset.");
        reject(new RealmError("cancelled", "The Realm GUI request was cancelled after dispatch; input may have landed. Inspect status, use Repair once if needed, then take a fresh capture. Do not replay uncertain input."));
      };
      const cleanup = () => { clearTimeout(timer); signal?.removeEventListener("abort", abort); };
      pending.set(id, { resolve, reject, cleanup });
      signal?.addEventListener("abort", abort, { once: true });
      write({ jsonrpc: "2.0", id, method, params });
    });
  const ready = request(
    "initialize",
    {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "t3code-realms", version },
    },
    { timeoutMs: startupTimeoutMs },
  ).then((result) => {
    write({ jsonrpc: "2.0", method: "notifications/initialized" });
    return result;
  });
  ready.catch(() => {});
  return {
    get closed() {
      return closed;
    },
    get stderr() {
      return stderrTail;
    },
    pid: child.pid,
    ready,
    listTools: async (options) => {
      await ready;
      return (await request("tools/list", {}, options)).tools ?? [];
    },
    call: async (name, args, options) => {
      await ready;
      return request("tools/call", { name, arguments: args ?? {} }, options);
    },
    close: () => fail("The Realm GUI driver connection was closed."),
  };
}
