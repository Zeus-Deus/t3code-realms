// Adapted from Hermes Realms 0.2.0 realms/host_guard.py (MIT, Copyright (c) 2026 Zeus-Deus).
//
// A Realm strips the host's display, bus and input handles from every child's environment.
// Nothing stops a command from putting them back: one `env WAYLAND_DISPLAY=wayland-1` prefix
// points a GUI tool inside the private desktop at the user's real session. This guard refuses
// that recognisable pattern out loud. It is an agent-judgment guardrail, not containment.

const GUARDED_KEYS = new Set([
  "WAYLAND_DISPLAY",
  "HYPRLAND_INSTANCE_SIGNATURE",
  "HYPRLAND_CMD",
  "DISPLAY",
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
  "AT_SPI_BUS_ADDRESS",
  "SWAYSOCK",
  "I3SOCK",
  "YDOTOOL_SOCKET",
  "CUA_INJECT_SOCKET",
  "CUA_DRIVER_SOCKET",
  "XAUTHORITY",
]);
const PREFIX_WORDS = new Set(["env", "export", "declare", "typeset", "setenv"]);
const SEPARATORS = new Set([";", "&&", "||", "|", "&"]);
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/;

/** POSIX-ish word splitting with quotes and comments; undefined when unbalanced. */
function shellWords(command) {
  const words = [];
  let word = "";
  let started = false;
  let quote = null;
  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    if (quote === "'") {
      if (char === "'") quote = null;
      else word += char;
      continue;
    }
    if (quote === '"') {
      if (char === '"') quote = null;
      else if (char === "\\" && index + 1 < command.length && '"\\$`'.includes(command[index + 1]))
        word += command[++index];
      else word += char;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      started = true;
    } else if (char === "\\") {
      if (index + 1 < command.length) word += command[++index];
      started = true;
    } else if (";&|\n".includes(char)) {
      if (started) words.push({ value: word, operator: false });
      words.push({ value: char === "\n" ? ";" : char, operator: true });
      word = "";
      started = false;
    } else if (/\s/.test(char)) {
      if (started) words.push({ value: word, operator: false });
      word = "";
      started = false;
    } else if (char === "#" && !started) {
      while (index < command.length && command[index] !== "\n") index++;
      if (index < command.length) words.push({ value: ";", operator: true });
    } else {
      word += char;
      started = true;
    }
  }
  if (quote) return undefined;
  if (started) words.push({ value: word, operator: false });
  return words;
}

function isHostValue(key, value) {
  if (!value || value === `$${key}` || value === "${" + key + "}") return false;
  if (key === "XDG_RUNTIME_DIR") return /^\/run\/user\/[0-9]+\/?$/.test(value);
  if (key === "DISPLAY") return /^:[0-9]+(\.[0-9]+)?$/.test(value);
  if (key === "DBUS_SESSION_BUS_ADDRESS" || key === "AT_SPI_BUS_ADDRESS")
    return /\/run\/user\/[0-9]+\/(bus|at-spi)/.test(value);
  return true;
}

/** A refusal message when the command re-points a guarded key, otherwise undefined. */
export function hostEscape(command) {
  if (typeof command !== "string" || !command.trim()) return undefined;
  const tokens = shellWords(command);
  if (!tokens) return undefined;
  const found = [];
  let prefix = true;
  let wrapper = null;
  let skip = false;
  for (const { value: token, operator } of tokens) {
    if (operator && SEPARATORS.has(token)) { prefix = true; wrapper = null; skip = false; continue; }
    if (skip) { skip = false; continue; }
    if (!prefix) continue;
    const match = ASSIGNMENT.exec(token);
    if (match) {
      const [, key, value] = match;
      if (GUARDED_KEYS.has(key) && isHostValue(key, value)) found.push(key);
      continue;
    }
    if (wrapper && token.startsWith("-")) {
      if (wrapper === "env" && ["-u", "--unset", "-C", "--chdir"].includes(token)) skip = true;
      continue;
    }
    const name = token.split("/").at(-1);
    if (PREFIX_WORDS.has(name)) { wrapper = name; continue; }
    if (wrapper && wrapper !== "env") continue;
    prefix = false;
  }
  if (found.length === 0) return undefined;
  return (
    `Blocked only this realm-terminal call: its ${[...new Set(found)].join(", ")} assignment could select a non-Realm endpoint. ` +
    "Keep the supplied private environment and remove the override for private testing. This pattern check is not proof that anything reached the physical desktop. " +
    "Use your ordinary provider shell for non-GUI work; that shell, files and other tools are unaffected. Continue other work."
  );
}
