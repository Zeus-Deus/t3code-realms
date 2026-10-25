// The native runtime is a stdlib-only Python package run as a short-lived JSON CLI.
// Long work (starting a desktop, installing the driver) runs as detached runtime jobs,
// so no call here outlives a plugin invocation.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as path from "node:path";

export const RUNTIME_ENTRY = fileURLToPath(new URL("../runtime/t3realms_cli.py", import.meta.url));
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

export const TOOL_BOUNDARY = "Only this Realm call was refused or interrupted. Your ordinary shell, files and other tools are unaffected; continue other work. Call realm status for this Realm; if the blocker repeats, report its cause and ask the person for the stated recovery.";
export const scopedMessage = (message) => `${String(message).replaceAll(TOOL_BOUNDARY, "").trim().slice(0, 8000)} ${TOOL_BOUNDARY}`;

export class RealmError extends Error {
  constructor(code, message) {
    super(scopedMessage(message));
    this.code = code;
  }
}

/** Only these variables reach the runtime; the host's display and buses never do. */
function runtimeEnvironment() {
  // Bytecode must never be written beside the modules: they live in an immutable snapshot.
  const env = { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" };
  for (const key of ["HOME", "LANG", "LC_ALL", "TMPDIR"]) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  return env;
}

export function createRuntime({ home, python = "python3", entry = RUNTIME_ENTRY, timeoutMs = 25_000 }) {
  if (!path.isAbsolute(home)) throw new RealmError("invalid_input", "Realm data directory must be absolute.");
  const call = (command, input = {}, { signal, timeout = timeoutMs } = {}) =>
    new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(new RealmError("cancelled", "The request was cancelled."));
        return;
      }
      const child = spawn(
        python,
        ["-I", "-B", entry, "--home", home, command, "--input", JSON.stringify(input)],
        { stdio: ["ignore", "pipe", "pipe"], env: runtimeEnvironment(), detached: false },
      );
      const chunks = [];
      let size = 0;
      let stderr = "";
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        if (error) reject(error);
        else resolve(value);
      };
      const kill = () => {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
      };
      const abort = () => {
        kill();
        finish(new RealmError("cancelled", "The request was cancelled."));
      };
      const timer = setTimeout(() => {
        kill();
        finish(new RealmError("timeout", `Realm runtime command "${command}" timed out.`));
      }, timeout);
      signal?.addEventListener("abort", abort, { once: true });
      child.stdout.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_OUTPUT_BYTES) {
          kill();
          finish(new RealmError("failed", "Realm runtime output exceeded its limit."));
          return;
        }
        chunks.push(chunk);
      });
      child.stderr.on("data", (chunk) => {
        if (stderr.length < 4_000) stderr += chunk.toString("utf8").slice(0, 4_000 - stderr.length);
      });
      child.once("error", (error) =>
        finish(
          new RealmError(
            "setup_required",
            error.code === "ENOENT"
              ? `Python 3 was not found as "${python}". Install python3 or set the Python setting.`
              : "The Realm runtime could not start.",
          ),
        ),
      );
      child.once("close", (code) => {
        const line = Buffer.concat(chunks).toString("utf8").trim().split("\n").at(-1) ?? "";
        let reply;
        try {
          reply = JSON.parse(line);
        } catch {
          const detail = stderr.trim().split("\n").at(-1);
          finish(
            new RealmError(
              "failed",
              `Realm runtime command "${command}" failed${code === null ? "" : ` (exit ${code})`}${detail ? `: ${detail.slice(0, 300)}` : "."}`,
            ),
          );
          return;
        }
        if (reply?.ok === true) finish(undefined, reply.result);
        else
          finish(
            new RealmError(
              typeof reply?.code === "string" ? reply.code : "failed",
              typeof reply?.error === "string" ? reply.error : "The Realm runtime failed.",
            ),
          );
      });
    });
  return { home, call };
}
