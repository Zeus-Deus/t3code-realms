"""Guest terminal process group with a disconnect/heartbeat lifetime."""
import os
import selectors
import signal
import subprocess
import sys
import time

process = subprocess.Popen(['/bin/bash', '-c', sys.argv[1]], stdin=subprocess.DEVNULL, start_new_session=True)
try:
    pending = b''
    deadline = time.monotonic() + 10
    with selectors.DefaultSelector() as selector:
        selector.register(0, selectors.EVENT_READ)
        while process.poll() is None:
            if time.monotonic() >= deadline: break
            if not selector.select(.2): continue
            data = os.read(0, 4096)
            if not data: break
            pending += data
            if len(pending) > 4096: break
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                if line == b'HEARTBEAT': deadline = time.monotonic() + 10
                elif line.startswith(b'SIGNAL:') and line[7:].isdigit():
                    number = int(line[7:])
                    if number not in {1, 2, 3, 9, 15, 28}: raise ValueError('Unsupported signal')
                    os.killpg(process.pid, number)
                else: raise ValueError('Unknown command control frame')
finally:
    # Children share a group created here; no name/PID discovery is involved.
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait()
raise SystemExit(process.returncode if process.returncode >= 0 else 128 - process.returncode)
