# Adapted from Hermes Realms at da5cdd3 (MIT, Copyright (c) 2026 Zeus-Deus)
"""Guest-only foreground driver ownership; control bytes are not authentication.

Stage this module without Hermes or site-packages. The adapter owns endpoint
verification, the control channel, runtime cleanup and takeover authorization.
"""
import math
import os
import selectors
import signal
import subprocess
import sys
import time


def _guarded_argv(argv):
    # A fresh interpreter avoids running Python/ctypes in a preexec_fn after a
    # multithreaded fork. exec preserves the exact child PID held by Popen.
    return [sys.executable, "-I", "-S", os.path.abspath(__file__),
            "--exec-driver", str(os.getpid()), *argv]


def _exec_driver(parent_pid, argv):
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    # PR_SET_PDEATHSIG. SIGTERM is insufficient for a stuck/resistant driver.
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # windows-footgun: ok — runtime package rejects non-Linux hosts
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    # Cover parent exit between Popen and arming the kernel guard.
    if os.getppid() != parent_pid:
        raise SystemExit(125)
    # Restore subprocess' signal policy after the intermediate Python runtime.
    for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
        value = getattr(signal, name, None)
        if value is not None:
            signal.signal(value, signal.SIG_DFL)
    os.execve(argv[0], argv, os.environ)


class GuestDriverSupervisor:
    def __init__(self, argv, *, env, cwd, stop_argv, heartbeat_timeout=10.0,
                 stop_timeout=3.0, exit_timeout=5.0, terminate_timeout=2.0,
                 kill_timeout=2.0):
        self.argv = self._argv(argv)
        self.stop_argv = self._argv(stop_argv)
        if self.argv[0] != self.stop_argv[0]:
            raise ValueError("serve and stop must use the same verified executable")
        self.env = dict(env)
        if any(not isinstance(key, str) or not key or '=' in key or '\0' in key
               or not isinstance(value, str) or '\0' in value
               for key, value in self.env.items()):
            raise ValueError("driver environment must contain valid string pairs")
        self.cwd = os.fspath(cwd)
        if not os.path.isabs(self.cwd) or '\0' in self.cwd:
            raise ValueError("driver cwd must be an absolute path")
        for value in (heartbeat_timeout, stop_timeout, exit_timeout, terminate_timeout, kill_timeout):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 60:
                raise ValueError("driver lifecycle timeouts must be finite and between zero and 60 seconds")
        self.heartbeat_timeout = float(heartbeat_timeout)
        self.stop_timeout = float(stop_timeout)
        self.exit_timeout = float(exit_timeout)
        self.terminate_timeout = float(terminate_timeout)
        self.kill_timeout = float(kill_timeout)
        self.process = None

    @staticmethod
    def _argv(value):
        if isinstance(value, (str, bytes)):
            raise ValueError("driver command must be an argv sequence")
        result = tuple(value)
        if (not result or any(not isinstance(arg, str) or '\0' in arg for arg in result)
                or not os.path.isabs(result[0])):
            raise ValueError("driver command requires an absolute executable and NUL-free arguments")
        return result

    def run(self, *, control_fd):
        if self.process is not None:
            raise RuntimeError("driver supervisor cannot be reused")
        # Register before spawning: an invalid channel must not strand a child.
        with selectors.DefaultSelector() as selector:
            selector.register(control_fd, selectors.EVENT_READ)
            self.process = subprocess.Popen(
                _guarded_argv(self.argv), env=self.env, cwd=self.cwd, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
            )
            try:
                reason = self._monitor(selector, control_fd, self.process)
            finally:
                self._retire(self.process)
        return {"reason": reason, "driver_pid": self.process.pid,
                "driver_returncode": self.process.returncode}

    def _monitor(self, selector, control_fd, process: subprocess.Popen):
        deadline = time.monotonic() + self.heartbeat_timeout
        pending = b''
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "heartbeat_timeout"
            if not selector.select(min(remaining, 0.1)):
                continue
            data = os.read(control_fd, 4096)
            if not data:
                return "eof"
            pending += data
            while b'\n' in pending:
                command, pending = pending.split(b'\n', 1)
                if command == b'STOP':
                    return "stop"
                if command != b'HEARTBEAT':
                    return "protocol_error"
                deadline = time.monotonic() + self.heartbeat_timeout
            # Bound both unfinished frames and work per read. Partial bytes do
            # not renew; driver output is deliberately disconnected from here.
            if pending and not any(frame.startswith(pending) for frame in (b'HEARTBEAT\n', b'STOP\n')):
                return "protocol_error"
        return "driver_exit"

    def _retire(self, process: subprocess.Popen):
        if process.poll() is not None:
            return
        try:
            subprocess.run(_guarded_argv(self.stop_argv), env=self.env, cwd=self.cwd,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, close_fds=True, timeout=self.stop_timeout)
        except (OSError, subprocess.TimeoutExpired):
            # A failed/missing stop helper cannot prevent owned-Popen cleanup.
            pass
        finally:
            try:
                process.wait(timeout=self.exit_timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=self.terminate_timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.kill_timeout)


if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] != "--exec-driver":
        raise SystemExit(2)
    _exec_driver(int(sys.argv[2]), sys.argv[3:])
