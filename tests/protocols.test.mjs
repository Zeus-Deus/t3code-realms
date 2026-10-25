import { test } from "node:test";
import { getEventListeners } from "node:events";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { hostEscape } from "../lib/hostGuard.mjs";
import { createRuntime, RealmError } from "../lib/runtime.mjs";
import { createCuaSession } from "../lib/cua.mjs";
import { connectRfb } from "../lib/rfb.mjs";

const temp = () => fs.mkdtemp(path.join(os.tmpdir(), "t3r-"));

// Cases carried over from Hermes Realms' own guard tests.
test("host guard refuses re-pointing display and bus handles at the host", () => {
  for (const command of [
    "env WAYLAND_DISPLAY=wayland-0 hyprctl monitors",
    "HYPRLAND_INSTANCE_SIGNATURE=abc hyprctl dispatch exit",
    "export DISPLAY=:0; xdotool key Return",
    "XDG_RUNTIME_DIR=/run/user/1000 grim /tmp/host.png",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus gdbus call --session",
    "cd /tmp && DISPLAY=:0 xdotool key Return",
    "echo start; WAYLAND_DISPLAY=wayland-0 grim /tmp/host.png",
  ])
    assert.match(hostEscape(command) ?? "", /Blocked/, command);
  for (const command of [
    "ls -la ~",
    "grep -rn 'DISPLAY=:0' /etc",
    "echo WAYLAND_DISPLAY=wayland-0 >> notes.txt",
    "WAYLAND_DISPLAY= grim /tmp/shot.png",
    "python -c 'print(1)'",
    "",
    "echo 'unterminated",
  ])
    assert.equal(hostEscape(command), undefined, command);
});

test("runtime wrapper decodes one JSON reply and passes only a sanitized environment", async () => {
  const directory = await temp();
  const entry = path.join(directory, "fake_cli.py");
  await fs.writeFile(
    entry,
    [
      "import json, os, sys",
      "args = sys.argv[1:]",
      "command = args[2]",
      "payload = json.loads(args[4])",
      "if command == 'fail':",
      "    print(json.dumps({'ok': False, 'code': 'not_running', 'error': 'nope'}))",
      "elif command == 'crash':",
      "    sys.stderr.write('Traceback\\nboom\\n'); sys.exit(3)",
      "elif command == 'hang':",
      "    import time; time.sleep(30)",
      "else:",
      "    print(json.dumps({'ok': True, 'result': {'home': args[1], 'payload': payload, 'env': sorted(os.environ), 'flags': [sys.flags.isolated, sys.dont_write_bytecode]}}))",
    ].join("\n"),
  );
  process.env.WAYLAND_DISPLAY = "wayland-host";
  process.env.DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/user/1000/bus";
  const runtime = createRuntime({ home: directory, entry, timeoutMs: 2_000 });
  const echoed = await runtime.call("echo", { a: 1 });
  assert.equal(echoed.home, directory);
  assert.deepEqual(echoed.payload, { a: 1 });
  assert.ok(!echoed.env.includes("WAYLAND_DISPLAY"));
  assert.ok(!echoed.env.includes("DBUS_SESSION_BUS_ADDRESS"));
  assert.deepEqual(echoed.flags, [1, true]);
  await assert.rejects(runtime.call("fail"), (error) => error instanceof RealmError && error.code === "not_running");
  await assert.rejects(runtime.call("crash"), /exit 3.*boom/);
  await assert.rejects(runtime.call("hang", {}, { timeout: 300 }), (error) => error.code === "timeout");
  const controller = new AbortController();
  const pending = runtime.call("hang", {}, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, (error) => error.code === "cancelled");
  assert.throws(() => createRuntime({ home: "relative" }), /absolute/);
});

test("GUI driver client speaks MCP over stdio and fails closed when the driver dies", async () => {
  const directory = await temp();
  const server = path.join(directory, "fake_mcp.mjs");
  await fs.writeFile(
    server,
    `import * as readline from "node:readline";
const lines = readline.createInterface({ input: process.stdin });
let initialized = false;
lines.on("line", (line) => {
  const message = JSON.parse(line);
  const reply = (result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\\n");
  if (message.method === "initialize") reply({ protocolVersion: message.params.protocolVersion, capabilities: {}, serverInfo: { name: "fake" } });
  else if (message.method === "notifications/initialized") initialized = true;
  else if (message.method === "tools/list") reply({ tools: [{ name: "click", description: "Click", inputSchema: {} }] });
  else if (message.params?.name === "crash") process.exit(1);
  else if (message.params?.name === "slow") {}
  else reply({ content: [{ type: "text", text: JSON.stringify({ initialized, args: message.params.arguments }) }] });
});`,
  );
  const session = createCuaSession({ command: process.execPath, args: [server], env: { PATH: process.env.PATH } });
  assert.deepEqual((await session.listTools()).map((tool) => tool.name), ["click"]);
  const result = await session.call("click", { x: 3 });
  assert.deepEqual(JSON.parse(result.content[0].text), { initialized: true, args: { x: 3 } });
  await assert.rejects(session.call("slow", {}, { timeoutMs: 200 }), (error) => error.code === "timeout");
  assert.equal(session.closed, true, "an unanswered input request resets the connection");
  await assert.rejects(session.call("click", {}), (error) => error.code === "driver_unavailable");

  const crashing = createCuaSession({ command: process.execPath, args: [server], env: { PATH: process.env.PATH } });
  await assert.rejects(crashing.call("crash", {}), (error) => error.code === "driver_unavailable");
});

test("takeover input completes an RFB 3.8 handshake and sends pointer and key events", async () => {
  const directory = await temp();
  const socketPath = path.join(directory, "vnc.sock");
  const received = [];
  let arrived;
  const fourteen = new Promise((resolve) => {
    arrived = resolve;
  });
  const server = net.createServer((socket) => {
    let stage = 0;
    let buffer = Buffer.alloc(0);
    socket.write("RFB 003.008\n");
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (stage === 0 && buffer.length >= 12) {
        assert.equal(buffer.subarray(0, 12).toString(), "RFB 003.008\n");
        buffer = buffer.subarray(12);
        socket.write(Buffer.from([1, 1]));
        stage = 1;
      }
      if (stage === 1 && buffer.length >= 1) {
        assert.equal(buffer[0], 1);
        buffer = buffer.subarray(1);
        socket.write(Buffer.from([0, 0, 0, 0]));
        stage = 2;
      }
      if (stage === 2 && buffer.length >= 1) {
        buffer = buffer.subarray(1);
        const init = Buffer.alloc(24 + 4);
        init.writeUInt16BE(800, 0);
        init.writeUInt16BE(600, 2);
        init.writeUInt32BE(4, 20);
        init.write("test", 24);
        socket.write(init);
        stage = 3;
      }
      if (stage === 3) {
        received.push(buffer);
        buffer = Buffer.alloc(0);
        if (Buffer.concat(received).length >= 14) arrived();
      }
    });
  });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  try {
    const client = await connectRfb(socketPath);
    assert.deepEqual(client.size, { width: 800, height: 600 });
    client.pointer(900, -5, 1);
    client.key(0xff0d, true);
    await fourteen;
    const bytes = Buffer.concat(received);
    assert.deepEqual([...bytes.subarray(0, 6)], [5, 1, 0x03, 0x1f, 0, 0], "coordinates are clamped to the desktop");
    assert.deepEqual([...bytes.subarray(6, 14)], [4, 1, 0, 0, 0, 0, 0xff, 0x0d]);
    client.close();
  } finally {
    server.close();
  }
  await assert.rejects(connectRfb(path.join(directory, "missing.sock")), (error) => error.code === "not_running");
});

test("GUI client never sends an already-cancelled input and releases abort listeners", async (t) => {
  const directory = await temp(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const script = path.join(directory, "cancel-server.mjs");
  await fs.writeFile(script, `import * as readline from "node:readline";
let inputs=0;
readline.createInterface({input:process.stdin}).on("line",line=>{
 const message=JSON.parse(line);
 if(message.id===undefined)return;
 if(message.method==="tools/call")inputs++;
 process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:message.id,result:message.method==="initialize"?{capabilities:{}}:{content:[{type:"text",text:String(inputs)}]}})+"\\n");
});`);
  const session = createCuaSession({ command: process.execPath, args: [script], env: { PATH: process.env.PATH } }); t.after(() => session.close());
  await session.ready;
  const controller = new AbortController(); controller.abort();
  await assert.rejects(session.call("click", {}, { signal: controller.signal }), (error) => error.code === "cancelled");
  assert.equal((await session.call("get_screen_size", {})).content[0].text, "1", "only the fresh diagnostic was sent");
  const live = new AbortController();
  for (let index = 0; index < 12; index++) await session.call("get_screen_size", {}, { signal: live.signal });
  assert.equal(getEventListeners(live.signal, "abort").length, 0);
});

test("host guard keeps quoted shell operators as argument data", () => {
  assert.equal(hostEscape("printf '%s\\n' ';' A=1 DISPLAY=:0"), undefined);
  assert.match(hostEscape("printf hello # comment\nDISPLAY=:0 xdotool key Return") ?? "", /Blocked/);
});
