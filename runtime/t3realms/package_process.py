"""Independent holder of setup exclusion while an approved root transaction drains.

Executed under -I. The inherited flock survives loss of the plugin job runner.
No package-manager subprocess is launched except from the reviewed setup worker.
"""
import json
import os
import signal
import subprocess
import sys


def supervise(argv, env):
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        return process.wait(timeout=1820)
    except subprocess.TimeoutExpired:
        try:
            # The captured child is unreaped, so its process-group id cannot be reused.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            # The root-side timeout owns retirement after elevation. Keep exclusion until exit.
            pass
        process.wait()
        return 124


if __name__ == '__main__':
    payload = json.loads(sys.argv[1])
    raise SystemExit(supervise(payload['argv'], payload['env']))
