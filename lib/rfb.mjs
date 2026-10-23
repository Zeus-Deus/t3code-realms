// Human takeover input over the Realm's private wayvnc socket (RFB 3.8, None security).
// The socket is mode 0600 inside the Realm's 0700 runtime; the runtime validates that path
// belongs to the live generation before it is handed here. Frames are not read: watching
// uses compositor captures, so this connection only carries pointer and key events.
import * as net from "node:net";
import { RealmError } from "./runtime.mjs";

const HANDSHAKE_TIMEOUT_MS = 5_000;
const MAX_HANDSHAKE_BYTES = 64 * 1024;

export function connectRfb(socketPath, { timeoutMs = HANDSHAKE_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let buffer = Buffer.alloc(0);
    let stage = "version";
    let settled = false;
    const done = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        socket.destroy();
        reject(error);
      } else resolve(value);
    };
    const timer = setTimeout(
      () => done(new RealmError("timeout", "The Realm display did not accept control in time.")),
      timeoutMs,
    );
    const take = (count) => {
      if (buffer.length < count) return undefined;
      const value = buffer.subarray(0, count);
      buffer = buffer.subarray(count);
      return value;
    };
    const step = () => {
      for (;;) {
        if (stage === "version") {
          const version = take(12);
          if (!version) return;
          if (version.toString("latin1") !== "RFB 003.008\n")
            return done(new RealmError("failed", "Unsupported Realm display protocol."));
          socket.write("RFB 003.008\n");
          stage = "security";
        } else if (stage === "security") {
          if (buffer.length < 1) return;
          const count = buffer[0];
          if (count === 0) return done(new RealmError("failed", "The Realm display refused the connection."));
          const types = take(1 + count);
          if (!types) return;
          if (!types.subarray(1).includes(1))
            return done(new RealmError("failed", "The Realm display requires unsupported authentication."));
          socket.write(Buffer.from([1]));
          stage = "result";
        } else if (stage === "result") {
          const result = take(4);
          if (!result) return;
          if (result.readUInt32BE(0) !== 0)
            return done(new RealmError("failed", "The Realm display refused the connection."));
          // Shared: watching viewers and the agent's driver keep their own connections.
          socket.write(Buffer.from([1]));
          stage = "init";
        } else if (stage === "init") {
          if (buffer.length < 24) return;
          const nameLength = buffer.readUInt32BE(20);
          if (nameLength > 4096) return done(new RealmError("failed", "Invalid Realm display handshake."));
          const init = take(24 + nameLength);
          if (!init) return;
          stage = "ready";
          const width = init.readUInt16BE(0);
          const height = init.readUInt16BE(2);
          // Server messages (bells, cut text, framebuffer updates) are never requested; drain them.
          socket.removeListener("data", onData);
          socket.on("data", () => {});
          return done(undefined, makeClient(socket, { width, height }));
        }
      }
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_HANDSHAKE_BYTES)
        return done(new RealmError("failed", "Invalid Realm display handshake."));
      step();
    };
    socket.on("data", onData);
    socket.once("error", () => done(new RealmError("not_running", "The Realm display is not available.")));
    socket.once("close", () => done(new RealmError("not_running", "The Realm display closed the connection.")));
  });
}

function makeClient(socket, size) {
  let closed = false;
  socket.once("close", () => {
    closed = true;
  });
  socket.on("error", () => {
    closed = true;
  });
  const write = (bytes) => {
    if (closed) throw new RealmError("not_running", "Control of the Realm display was lost.");
    socket.write(bytes);
  };
  const clamp = (value, max) => Math.max(0, Math.min(max - 1, Math.round(value)));
  return {
    size,
    get closed() {
      return closed;
    },
    pointer(x, y, buttons) {
      const message = Buffer.alloc(6);
      message[0] = 5;
      message[1] = buttons & 0xff;
      message.writeUInt16BE(clamp(x, size.width), 2);
      message.writeUInt16BE(clamp(y, size.height), 4);
      write(message);
    },
    key(keysym, down) {
      const message = Buffer.alloc(8);
      message[0] = 4;
      message[1] = down ? 1 : 0;
      message.writeUInt32BE(keysym >>> 0, 4);
      write(message);
    },
    close() {
      closed = true;
      socket.destroy();
    },
  };
}
