// T3 Code Realms: private Linux test desktops for agents, shared by a thread and its verified subagents.
// GUI separation and owned process lifetime, not a hostile-code sandbox.
import { createRuntime, RealmError } from "./lib/runtime.mjs";
import { createRealms, principal } from "./lib/realms.mjs";
import { createCuaSession } from "./lib/cua.mjs";
import { connectRfb } from "./lib/rfb.mjs";

const VERSION = "0.1.0";
let realms;

/** Agents read the code in brackets; people read the sentence. */
const failure = (error) => {
  if (error instanceof RealmError) return new Error(`[${error.code}] ${error.message}`);
  return new Error(`[failed] ${new RealmError("failed", error instanceof Error ? error.message : "Realm operation failed. Inspect status before retrying; do not replay uncertain input.").message}`);
};
const run = (task) => async (input, invocation) => {
  try {
    const result = await task(input && typeof input === "object" && !Array.isArray(input) ? input : {}, invocation);
    if (invocation?.caller?.kind === "agent" && result && typeof result === "object")
      result.message = `${result.message ?? "Realm call completed."} Realm actions only: your ordinary shell, files and other tools are unaffected; continue ordinary work. There is nothing to exit, and off is not needed for ordinary work.`;
    if (Buffer.byteLength(JSON.stringify(result)) > 120_000)
      throw new RealmError("result_too_large", "This Realm result exceeded the host limit and was withheld. Inspect status or request smaller output/a smaller capture; do not replay uncertain input.");
    return result;
  } catch (error) {
    // Setup that needs a person is a result, because only results can carry a chat card.
    if (error instanceof RealmError && error.card && invocation?.caller?.kind === "agent")
      return { message: `[${error.code}] ${error.message}`, data: { code: error.code }, card: error.card };
    throw failure(error);
  }
};

export async function activate(ctx) {
  // Settings are host calls (bounded per invocation), so the interpreter setting is read at most
  // every few seconds rather than on every runtime command.
  let python = { value: "python3", at: -Infinity };
  const runtimeFor = async () => {
    if (Date.now() - python.at > 5_000)
      python = { value: String((await ctx.settings.get("python")) ?? "python3"), at: Date.now() };
    return createRuntime({ home: ctx.dataDirectory, python: python.value });
  };
  const runtime = {
    call: async (command, input, options) => (await runtimeFor()).call(command, input, options),
  };
  realms = createRealms({
    runtime,
    storage: ctx.storage,
    settings: ctx.settings,
    dataDirectory: ctx.dataDirectory,
    connectCua: (launcher) =>
      createCuaSession({
        command: launcher.path,
        args: ["mcp"],
        env: { PATH: "/usr/bin:/bin", CUA_DRIVER_RS_TELEMETRY_ENABLED: "0" },
        version: VERSION,
      }),
    connectRfb,
    sendThread: ctx.threads?.send ? (input) => ctx.threads.send(input) : undefined,
    cards: ["ui", "ui.conversation-cards"].every((capability) => ctx.capabilities?.includes(capability)),
  });
  ctx.signal.addEventListener("abort", () => realms?.dispose(), { once: true });

  const withStatus = async (who, state) => ({ message: realms.summary(state), data: state });
  const options = (invocation) => ({ signal: invocation.signal });

  ctx.handle(
    "action:realm",
    run(async (input, invocation) => {
      const who = principal(invocation, input);
      const action = input.action ?? "status";
      switch (action) {
        case "status":
          return withStatus(who, await realms.status(who, options(invocation)));
        case "on":
          return withStatus(who, await realms.on(who, input, options(invocation)));
        case "off":
          return withStatus(who, await realms.off(who, options(invocation)));
        case "stop":
          return withStatus(who, await realms.stop(who, options(invocation)));
        case "size":
          return withStatus(who, await realms.resize(who, input, options(invocation)));
        case "repair":
          return realms.repair(who, options(invocation));
        case "shot":
          return realms.shot(who, options(invocation));
        case "watch":
          return {
            message: "A person can watch this Realm from its panel beside the thread (Realm in the thread menu). Watching is view-only until they take control.",
            intents: [{ type: "view.open", viewId: "realm" }],
          };
        default:
          throw new RealmError("invalid_input", "action must be on, off, status, size, stop, repair, shot or watch.");
      }
    }),
  );
  ctx.handle(
    "action:realm-terminal",
    run(async (input, invocation) => realms.terminal(principal(invocation, input), input, options(invocation))),
  );
  ctx.handle("action:realm-files", run(async (input, invocation) => realms.files(principal(invocation, input), input, options(invocation))));
  ctx.handle(
    "action:realm-computer",
    run(async (input, invocation) => realms.computer(principal(invocation, input), input, options(invocation))),
  );
  ctx.handle(
    "action:panel",
    run(async (input, invocation) => {
      const who = principal(invocation, input);
      const state = await realms.status(who, options(invocation));
      return { message: realms.summary(state), intents: [{ type: "view.open", viewId: "realm" }] };
    }),
  );

  ctx.handle(
    "status:realm",
    run(async (input, invocation) => ({ data: await realms.badge(principal(invocation, input), options(invocation)) })),
  );

  // The per-thread side panel. View handlers are reachable only from a person's client.
  const view = (name, task) =>
    ctx.handle(
      `view:realm:${name}`,
      run(async (input, invocation) => task(principal(invocation, input), input, options(invocation))),
    );
  view("status", async (who, _input, opts) => ({ data: await realms.status(who, opts) }));
  view("on", async (who, input, opts) => ({ data: await realms.on(who, input, opts) }));
  view("off", async (who, _input, opts) => ({ data: await realms.off(who, opts) }));
  view("stop", async (who, _input, opts) => ({ data: await realms.stop(who, opts) }));
  view("size", async (who, input, opts) => ({ data: await realms.resize(who, input, opts) }));
  view("repair", (who, _input, opts) => realms.repair(who, opts));
  view("frame", (who, input, opts) => realms.frame(who, input, opts));
  view("take", async (who, _input, opts) => ({ data: await realms.takeControl(who, opts) }));
  view("handback", async (who, _input, opts) => ({ data: await realms.handBack(who, opts) }));
  view("input", (who, input, opts) => realms.sendInput(who, input, opts));
  view("setup-review", (who, input, opts) => realms.setupReview(who, input, opts));
  view("setup-start", (who, input, opts) => realms.setupStart(who, input, opts));
  view("job-status", (who, input, opts) => realms.jobStatus(who, input, opts));
  view("job-cancel", (who, input, opts) => realms.jobCancel(who, input, opts));
  view("open-realms", async () => ({ intents: [{ type: "view.open", viewId: "realms" }] }));

  // The setup card in a conversation.
  const card = (name, task) =>
    ctx.handle(
      `view:setup:${name}`,
      run(async (input, invocation) => task(principal(invocation, input), input, options(invocation))),
    );
  card("state", (who, input, opts) => realms.setupState(who, input, opts));
  card("start", (who, input, opts) => realms.setupStart(who, input, opts));
  card("cancel", (who, input, opts) => realms.jobCancel(who, input, opts));
  card("continue", (who, input) => realms.continueAgent(who, input));
  card("use-desktop", (who, input, opts) => realms.useDesktop(who, input, opts));

  // The environment-wide Realms page.
  const page = (name, task) =>
    ctx.handle(
      `view:realms:${name}`,
      run(async (input, invocation) => task(principal(invocation, input), input, options(invocation))),
    );
  page("list", (who, input, opts) => realms.list(who, input, opts));
  page("stop", async (who, input, opts) => ({ data: await realms.stopById(who, input, opts) }));
  page("delete-review", (who, input, opts) => realms.deleteReview(who, input, opts));
  page("delete", (who, input, opts) => realms.deleteWorkspace(who, input, opts));
  page("setup-review", (who, input, opts) => realms.setupReview(who, input, opts));
  page("setup-start", (who, input, opts) => realms.setupStart(who, input, opts));
  page("job-status", (who, input, opts) => realms.jobStatus(who, input, opts));
  page("job-cancel", (who, input, opts) => realms.jobCancel(who, input, opts));
  page("prune-review", (who, input, opts) => realms.pruneReview(who, input, opts));
  page("prune", (who, input, opts) => realms.pruneRecovery(who, input, opts));
  page("components", (who, input, opts) => realms.components(who, input, opts));
  page("auto-install", (who, input) => realms.setAutoInstall(who, input));
  page("component-remove", (who, input, opts) => realms.removeComponent(who, input, opts));
  page("remove-everything", (who, input, opts) => realms.removeEverything(who, input, opts));
  page("reveal", async (who, input) => {
    if (who.kind !== "user" || typeof input.threadId !== "string") throw new RealmError("invalid_input", "Choose a thread.");
    return { intents: [{ type: "thread.reveal", threadId: input.threadId }] };
  });
}

export function deactivate() {
  realms?.dispose();
}
