#!/usr/bin/env python3
"""Run soapy_power beside the USB receiver; stop it when the control pipe closes.

This stdlib-only worker is also sent to SSH hosts with python3 -c. It does not
install files or send IQ. Its stdout is the unmodified spectrum output.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time


def main():
    command = json.loads(sys.argv[1])
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise ValueError("Expected a command argument list")
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, env=env)
    stopping = threading.Event()
    last_contact = [time.monotonic()]

    def stop(*_args):
        if stopping.is_set():
            return
        stopping.set()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()

    def watch_controller():
        # Both local pipes and SSH signal EOF when their controller disappears.
        while os.read(sys.stdin.fileno(), 1):
            last_contact[0] = time.monotonic()
        stop()

    def watch_heartbeat():
        # A broken network can leave sshd alive without delivering EOF promptly.
        while not stopping.wait(2):
            if time.monotonic() - last_contact[0] > 20:
                stop()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    threading.Thread(target=watch_controller, daemon=True).start()
    threading.Thread(target=watch_heartbeat, daemon=True).start()
    try:
        return process.wait()
    finally:
        stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as exc:
        print('Cannot start soapy_power: %s' % exc, file=sys.stderr, flush=True)
        sys.exit(1)
