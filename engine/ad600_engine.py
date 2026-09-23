#!/usr/bin/env python3
"""
ad600_engine.py — thin wrapper around the PROVEN firehose recipe.

Runs `python3 ad600_console.py <secs> <cmdfile> <logfile>` (the firehose_owner.sh recipe) as a
subprocess with env DERIVED FROM DISCOVERY + the selected interface — nothing hardcoded:
    WWB_DEVCID=<device_cid>  WWB_DEVIP=<device_ip>  WWB_DEVPORT=<device_port>
    WWB_CID=<derive_our_cid(iface MAC)>  WWB_MYIP=<iface ipv4>  AD600_MCAST_IF=<iface name>
plus the firehose_owner flags (AD600_OWNER_CLAIM=1 AD600_REACTIVE_ACK=1 AD600_ARM_ON_STATUS=1
AD600_ACCESS_PROBE=0 AD600_EMIT_FRAMES=1, …).

Parses the subprocess stdout:
    FRAME <curve> <flo> <fhi> <b64>  → bridge.feed(...)
    status markers                   → owner / scan-ready / streaming / pkt-rate state
Restarts the subprocess on exit while running (like the .mjs agent). start()/stop()/status().

Off-device safe: does NOTHING until start() is called with a discovered device.
Stdlib only.
"""
import os, sys, base64, struct, threading, subprocess, time, signal, secrets

# Bundle-aware resource resolution: works from source AND from inside a py2app .app.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import resource_path, engine_dir, scratch_dir

# default locations (overridable) — the proven console + its faithful command feed, now BUNDLED
# under engine/ so the app never depends on /Users/nt_mbp/AD600_HANDOFF/ existing at runtime.
CLIENT_DIR = os.environ.get("AD600_CLIENT_DIR", engine_dir())
CONSOLE_PY = os.environ.get("AD600_CONSOLE_PY", os.path.join(CLIENT_DIR, "ad600_console.py"))
DEFAULT_FEED = os.environ.get("AD600_REACTIVE_FEED", "BUILTIN")
# SCRATCH → a per-user WRITABLE dir (~/Library/Application Support/…), never inside the .app.
SCRATCH = scratch_dir()
CONSOLE_LOG_MAX_BYTES = 20 * 1024 * 1024   # rotate console_out.log past this (it's very chatty)


def fresh_session_cid():
    """A new random controller CID for every console session. A MAC-derived (or otherwise reused)
    CID draws JOIN_REFUSE reason 6 (IDENTITY IN USE) on a quick reconnect, and on macOS the real
    MAC is often hidden (02:00:00:00:00:00) so it isn't unique per machine either (findings §6.6)."""
    try:
        from ad600_discovery import CID_SUFFIX
    except Exception:
        CID_SUFFIX = "000011dda000000eddcccccc"
    return "%08x" % (0x10000000 + secrets.randbelow(0xe0000000)) + CID_SUFFIX


def _resolve_iface(iface):
    """Accept the interface as EITHER a record dict ({name,mac,ipv4}) OR a bare NAME string.
    A string is looked up via ad600_discovery.list_interfaces() to recover its ipv4/mac; a dict
    is used as-is. Always returns a dict with at least a 'name' key (empty ipv4/mac if unknown)."""
    if isinstance(iface, dict):
        return iface
    if isinstance(iface, str):
        try:
            import ad600_discovery as _disc
            ifd = _disc.iface_by_name(iface)
        except Exception:
            ifd = None
        return ifd or {"name": iface, "mac": "", "ipv4": ""}
    return {"name": "", "mac": "", "ipv4": ""}


def _firehose_env(device, iface, our_cid, rt_comp=None, start_khz=None, stop_khz=None,
                  curve_mask=None, repeat=None):
    """The firehose_owner.sh env, but with IDENTITY/NETWORK derived from discovery + interface.
    `iface` may be an interface record dict OR a bare interface name string (resolved here).
    `rt_comp` (if set) selects the delivered RBW: REAL_TIME_COMPRESSION = rt_comp, RBW = rt_comp*25kHz
    (e.g. 14 → 350 kHz; None/0 → the feed default of 36 → 900 kHz).
    `start_khz`/`stop_khz` (if set) narrow the scan range (uint32 kHz); None → feed default 470-1000."""
    iface = _resolve_iface(iface)
    env = dict(os.environ)
    # ── delivered-RBW selection (from /configuration rbwHz → compression) ──
    if rt_comp:
        env["AD600_RT_COMPRESSION"] = str(int(rt_comp))
    # ── scan range (from /configuration startHz/stopHz → uint32 kHz) ──
    if start_khz:
        env["AD600_SCAN_START_KHZ"] = str(int(start_khz))
    if stop_khz:
        env["AD600_SCAN_STOP_KHZ"] = str(int(stop_khz))
    # ── curve selection (bitmask: 0x7E = all 6; 0x02 = A only) ──
    if curve_mask:
        env["AD600_CURVE_SELECT"] = str(int(curve_mask))
    # ── repeat request (0xFF = continuous, 0x01 = single-shot) ──
    if repeat:
        env["AD600_REPEAT"] = str(int(repeat))
    # ── identity/network — from discovery + selected interface (NOTHING hardcoded) ──
    if device.get("device_cid"):
        env["WWB_DEVCID"] = device["device_cid"]
    if device.get("device_ip"):
        env["WWB_DEVIP"] = device["device_ip"]
    if device.get("device_port"):
        env["WWB_DEVPORT"] = str(device["device_port"])
    env["WWB_CID"] = our_cid
    if iface.get("ipv4"):
        env["WWB_MYIP"] = iface["ipv4"]
    if iface.get("name"):
        env["AD600_MCAST_IF"] = iface["name"]
    # ── firehose_owner.sh recipe flags (timing knobs stay env-overridable) ──
    env.setdefault("AD600_REACTIVE_ACK", "1")
    env.setdefault("AD600_DROP_SPURIOUS", "1")
    env.setdefault("AD600_ARM_ON_STATUS", "1")
    env.setdefault("AD600_OWNER_CLAIM", "1")
    env.setdefault("AD600_PRIME_SETTLE", "2.8")
    env.setdefault("AD600_OWNER_CLAIM_TIMEOUT", "3.0")
    env.setdefault("AD600_SCANREADY_TIMEOUT", "6.0")
    env.setdefault("AD600_PERSIST_UNTIL_STATUS", "0")
    env.setdefault("AD600_LOOP_UNTIL_OWN", "0")
    env.setdefault("AD600_AUTO_ARM", "0")
    env.setdefault("AD600_ACCESS_PROBE", "0")
    env.setdefault("AD600_SOCK_TIMEOUT", "0.004")
    env.setdefault("AD600_POLL", "0.003")
    # ── the machine-parseable frame emit (our hook) ──
    env["AD600_EMIT_FRAMES"] = "1"
    return env


class Engine:
    def __init__(self, bridge, feed=DEFAULT_FEED, console=CONSOLE_PY, client_dir=CLIENT_DIR,
                 run_secs=None):
        self.bridge = bridge
        self.feed = feed
        self.console = console
        self.client_dir = client_dir
        self.run_secs = int(run_secs or os.environ.get("AD600_CONSOLE_SECS", "3600"))

        self.device = None
        self.iface = None
        self.our_cid = None

        self.running = False
        self.proc = None
        self._reader = None
        self._supervisor = None
        self._lock = threading.Lock()
        self._rearm_lock = threading.Lock()
        # Bumped only by an EXTERNAL stop() — never by _rearm_worker's own stop-then-restart — so a
        # re-arm in progress can tell the operator stopped it and must not revive the session.
        self._generation = 0

        # observable state (menubar)
        self.owner = None            # True / False / None (unknown)
        self.scan_ready = False
        self.streaming = False
        self.blocked = False         # True when supervisor gave up (slot-0 taken / repeated fail)
        self.status_note = ""
        self.last_line = ""
        self.started_at = 0.0
        self._cmd_file = os.path.join(SCRATCH, "console_cmd.txt")   # for QUIT-FIRST clean stop

    # ─────────────────────────────── lifecycle ───────────────────────────────
    def start(self, device, iface, our_cid=None):
        """Begin the firehose against a DISCOVERED device on the selected interface. `our_cid` is
        only used for the first session; every console (re)launch gets a fresh one (_run_once)."""
        with self._lock:
            if self.running:
                return
            self.device = device
            self.iface = _resolve_iface(iface)    # accept a dict OR a bare interface-name string
            self.our_cid = our_cid
            self.owner = None
            self.scan_ready = False
            self.streaming = False
            self.blocked = False
            self.status_note = "starting"
            self.running = True
            self.started_at = time.time()
        self._supervisor = threading.Thread(target=self._supervise, daemon=True)
        self._supervisor.start()

    def _requested_rt_comp(self):
        """The delivered-RBW compression configured via /configuration (rbwHz → comp),
        or None to use the feed default (900 kHz). Read from the bridge's scan_config."""
        try:
            c = int((self.bridge.scan_config or {}).get("req_rt_compression") or 0)
        except Exception:
            c = 0
        return c if c > 0 else None

    def _requested_range(self):
        """The scan range configured via /configuration (startHz/stopHz → uint32 kHz), or
        (None, None) for the feed default (470-1000 MHz). Only honored once a range is set."""
        sc = self.bridge.scan_config or {}
        if not sc.get("_range_from_config"):
            return (None, None)
        try:
            return (int(sc.get("scan_start_freq_khz") or 0) or None,
                    int(sc.get("scan_stop_freq_khz") or 0) or None)
        except Exception:
            return (None, None)

    def _requested_curve_mask(self):
        sc = self.bridge.scan_config or {}
        try:
            return int(sc.get("curve_select") or 0) or None
        except Exception:
            return None

    def _requested_repeat(self):
        sc = self.bridge.scan_config or {}
        try:
            return int(sc.get("repeat") or 0) or None
        except Exception:
            return None

    def apply_config(self, cfg=None):
        """Bridge on_config_change hook. The AD600 latches scan config (RBW + range) at ARM time, so
        a change takes effect on the next (re)start. If a sweep is already live and the requested RBW
        OR range differs from what we armed at, re-arm by cleanly restarting the console (stop() runs
        the QUIT-FIRST teardown, so the slot is released before we re-JOIN). If nothing is running we
        just store it — the next Start picks it up via _requested_rt_comp()/_requested_range()."""
        want_comp = self._requested_rt_comp()
        want_range = self._requested_range()
        want_curve_mask = self._requested_curve_mask()
        want_repeat = self._requested_repeat()
        with self._lock:
            running = self.running
            dev, ifc = self.device, self.iface
        changed = (want_comp != getattr(self, "_armed_rt_comp", None)
                   or want_range != getattr(self, "_armed_range", (None, None))
                   or want_curve_mask != getattr(self, "_armed_curve_mask", None)
                   or want_repeat != getattr(self, "_armed_repeat", None))
        if running and changed and dev:
            threading.Thread(target=self._rearm_worker, args=(dev, ifc), daemon=True).start()

    def _config_differs(self):
        return (self._requested_rt_comp() != getattr(self, "_armed_rt_comp", None)
                or self._requested_range() != getattr(self, "_armed_range", (None, None))
                or self._requested_curve_mask() != getattr(self, "_armed_curve_mask", None)
                or self._requested_repeat() != getattr(self, "_armed_repeat", None))

    def _rearm_worker(self, dev, ifc):
        """Restart the console at the new config. Only one worker runs at a time; it loops so a burst
        of UI changes (e.g. RBW then range) collapses into as few re-arms as possible."""
        if not self._rearm_lock.acquire(blocking=False):
            return                       # the active worker will pick up the newer config
        try:
            while True:
                with self._lock:
                    running = self.running
                    d = self.device or dev
                    i = self.iface or ifc
                    gen_before = self._generation
                if not (running and d and self._config_differs()):
                    break
                self.status_note = "re-arming at new configuration…"
                if hasattr(self.bridge, "reset_observed"):
                    self.bridge.reset_observed()
                self.stop(_internal=True)
                # settle so the device fully releases the slot before we re-claim it
                time.sleep(1.5)
                with self._lock:
                    if self._generation != gen_before:
                        return           # operator stopped us mid-re-arm: stay stopped
                self.start(d, i)
                time.sleep(1.0)
        except Exception as ex:
            sys.stderr.write("[ad600_engine re-arm error] %r\n" % (ex,))
        finally:
            self._rearm_lock.release()

    def stop(self, _internal=False):
        with self._lock:
            if not _internal:
                self._generation += 1
            self.running = False
            p = self.proc
            sup = self._supervisor
        if p and p.poll() is None:
            # QUIT-FIRST clean stop: ask the console to disconnect cleanly (RELEASE_SCAN_ID + LEAVE)
            # via the cmd file and give it a REAL grace window to reach the wire, BEFORE any signal.
            # A hard SIGINT/SIGTERM kills the loop mid-flight with no teardown → the device keeps our
            # stale membership + scan-slot-0 lease → the next launch hits JOIN_REFUSE / NOT-OWNER until
            # a power-cycle. This is the fix for that lifecycle bug.
            try:
                with open(self._cmd_file, "a") as f:
                    f.write("quit\n")
            except Exception:
                pass
            deadline = time.time() + 3.0
            while time.time() < deadline and p.poll() is None:
                if "clean disconnect sent" in (self.last_line or ""):
                    break
                time.sleep(0.05)
            # Escalate only if it still hasn't exited: SIGINT (console handler → clean loop exit),
            # then SIGTERM, then SIGKILL as a last resort.
            if p.poll() is None:
                try:
                    p.send_signal(signal.SIGINT)
                except Exception:
                    pass
                for _ in range(20):
                    if p.poll() is not None:
                        break
                    time.sleep(0.1)
            if p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
                for _ in range(10):
                    if p.poll() is not None:
                        break
                    time.sleep(0.1)
            if p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass
        if sup and sup is not threading.current_thread() and sup.is_alive():
            # let the old supervisor observe running=False and exit before a re-arm starts a new
            # one, so two supervisors never race to relaunch the console
            sup.join(timeout=3.0)
        self.status_note = "stopped"
        self.streaming = False

    def _supervise(self):
        """Run the console; on exit decide whether to relaunch. Critically: do NOT blindly
        re-hammer. A NOT-OWNER outcome means slot-0 is held (by another controller or by a
        just-dropped session that never released it) — retrying only draws GET_FAIL on
        0x0107010f and can poison the slot, so we STOP and tell the operator to power-cycle.
        A session that actually STREAMED and then dropped gets a bounded resume attempt."""
        consec_fail = 0
        while True:
            with self._lock:
                if not self.running:
                    return
            # fresh per-run outcome so we can judge THIS run
            self.owner = None
            self.scan_ready = False
            self.streaming = False
            self._run_once()
            with self._lock:
                if not self.running:
                    return               # operator hit Stop

            if self.owner is False:
                # slot-0 taken — retrying is worse than useless (poisons the slot). Instead of a dead
                # stop, watch the device's SDDP adverts: when it goes silent and REAPPEARS (a reboot →
                # slot-0 guaranteed free) auto-resume, so the operator's power-cycle is all it takes.
                if os.environ.get("AD600_AUTO_RECOVER", "1") != "0" and self._await_power_cycle():
                    consec_fail = 0
                    continue
                self.status_note = "slot-0 taken — power-cycle AD600 (WWB off), then ▶ Start"
                self.blocked = True
                with self._lock:
                    self.running = False
                return

            if self.streaming:
                consec_fail = 0          # a good session; reset the fail counter
                self.status_note = "scan session ended — resuming…"
            else:
                consec_fail += 1
                if consec_fail >= 3:
                    if os.environ.get("AD600_AUTO_RECOVER", "1") != "0" and self._await_power_cycle():
                        consec_fail = 0
                        continue
                    self.status_note = "couldn't start scan — power-cycle AD600 (WWB off), then ▶ Start"
                    self.blocked = True
                    with self._lock:
                        self.running = False
                    return
                self.status_note = "reconnecting… (%d/3)" % consec_fail
            time.sleep(2.0)              # brief backoff before a bounded relaunch

    def _device_present(self):
        """Bounded SLP probe: is OUR AD600 currently advertising on the selected iface?
        Returns True (present) / False (absent) / None (probe inconclusive — do not act)."""
        try:
            import ad600_discovery as _disc
            want = (self.device or {}).get("device_cid")
            rec = _disc.discover(self.iface, timeout=3, our_cid=self.our_cid)
            if not rec:
                return False
            got = rec.get("device_cid")
            return (got == want) if (want and got) else True   # beacon-only (cid=None) still = present
        except Exception:
            return None   # transient probe failure ≠ device gone; keep waiting, never false-resume

    def _await_power_cycle(self):
        """After a NOT-OWNER / can't-start outcome, do NOT dead-stop. Watch the device's SDDP adverts;
        when it goes SILENT (powered off) and then REAPPEARS (rebooted → slot-0 guaranteed free),
        auto-resume. The operator's Stop still cancels. Returns True to resume, False if cancelled."""
        self.status_note = "slot-0 held — power-cycle the AD600 (WWB off); waiting for it to reboot…"
        self.blocked = True
        seen_gone = False
        while True:
            with self._lock:
                if not self.running:
                    return False                       # operator hit Stop
            present = self._device_present()           # True / False / None
            if present is False:
                if not seen_gone:
                    self.status_note = "AD600 powered down — waiting for it to come back…"
                seen_gone = True
            elif present is True and seen_gone:
                self.status_note = "AD600 rebooted — slot-0 free, resuming…"
                self.blocked = False
                return True
            time.sleep(2.0)

    def _run_once(self):
        os.makedirs(SCRATCH, exist_ok=True)
        cmd_file = self._cmd_file = os.path.join(SCRATCH, "console_cmd.txt")
        log_file = os.path.join(SCRATCH, "console_out.log")
        try:
            if os.path.getsize(log_file) > CONSOLE_LOG_MAX_BYTES:
                os.replace(log_file, log_file + ".1")
        except OSError:
            pass
        # Fresh controller identity for EVERY console session — including the supervisor's
        # automatic relaunches and re-arms — never a reused one (findings §6.6).
        self.our_cid = fresh_session_cid()
        # the console loads the feed via one control line, then owner-claim drives the arm.
        # Shared with Bridge's /bias handler, which appends to this same file from the HTTP
        # thread — take its lock so a truncate here can't land mid-append and lose a command.
        cmdfile_lock = getattr(self.bridge, "cmdfile_lock", None)
        with (cmdfile_lock or threading.Lock()), open(cmd_file, "w") as f:
            f.write("lockfeed %s\n" % (self.feed or "BUILTIN"))
        rt_comp = self._requested_rt_comp()
        start_khz, stop_khz = self._requested_range()
        curve_mask = self._requested_curve_mask()
        repeat = self._requested_repeat()
        env = _firehose_env(self.device, self.iface, self.our_cid,
                            rt_comp=rt_comp, start_khz=start_khz, stop_khz=stop_khz,
                            curve_mask=curve_mask, repeat=repeat)
        self._armed_rt_comp = rt_comp          # remember what this session armed at (for re-arm diffing)
        self._armed_range = (start_khz, stop_khz)
        self._armed_curve_mask = curve_mask
        self._armed_repeat = repeat
        env["AD600_CONSOLE_SECS"] = str(self.run_secs)
        # ensure the console's sibling imports resolve even if launched from an unusual cwd
        _pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = self.client_dir + (os.pathsep + _pp if _pp else "")
        env["PYTHONUNBUFFERED"] = "1"   # keep FRAME lines flowing through the pipe promptly
        # sys.executable is a GENERAL interpreter in BOTH modes: the real python3 from source, and
        # py2app's bundled `Contents/MacOS/python` stub in a frozen .app (verified to run script
        # files + import the bundled stdlib-only engine siblings). So one direct spawn covers both.
        argv = [sys.executable, "-u", self.console, str(self.run_secs), cmd_file, log_file]
        try:
            self.proc = subprocess.Popen(
                argv, cwd=self.client_dir, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, universal_newlines=True,
                encoding="utf-8", errors="replace")   # console emits Unicode markers (★ → ✪); frozen-app locale is ASCII
        except Exception as e:
            self.status_note = "launch failed: %r" % e
            return
        self._reader = threading.Thread(target=self._read_stdout, args=(self.proc,), daemon=True)
        self._reader.start()
        self.proc.wait()

    # ─────────────────────────────── stdout parse ───────────────────────────────
    def _read_stdout(self, proc):
        for line in proc.stdout:
            self.last_line = line.rstrip("\n")
            # Forward telemetry lines (BIAS, TEMP, CONNECTED, etc.) to stdout for server.js
            if not line.startswith("FRAME "):
                sys.stdout.write(line)
                sys.stdout.flush()
            if line.startswith("FRAME "):
                self._on_frame(line)
                self.streaming = True
                continue
            if line.startswith("BIAS "):
                try:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        ant = parts[1].upper()
                        val = bool(int(parts[2]))
                        if hasattr(self.bridge, "antenna_bias") and isinstance(self.bridge.antenna_bias, dict):
                            self.bridge.antenna_bias[ant] = val
                except Exception:
                    pass
                continue
            self._on_status(line)

    def _on_frame(self, line):
        try:
            _, curve, flo, fhi, b64 = line.rstrip("\n").split(" ", 4)
            raw = base64.b64decode(b64)
            n = len(raw) // 2
            amps = [struct.unpack(">h", raw[i * 2:i * 2 + 2])[0] / 10.0 for i in range(n)]
            self.bridge.feed(int(curve), int(flo), int(fhi), amps)
        except Exception:
            pass

    def _on_status(self, line):
        s = line
        if "OWNERSHIP CLAIMED" in s:
            self.owner = True
            self.status_note = "owner (slot 0)"
        elif "NOT OWNER" in s:
            self.owner = False
            self.status_note = "slot-0 taken — power-cycle AD600 w/ WWB off"
        if "SCAN-READY gate open" in s or "SCAN-READY EVENT 0x01070137" in s:
            self.scan_ready = True
        if "SCAN LANDED" in s or "RSSI FIREHOSE EVENT" in s:
            self.streaming = True

    # ─────────────────────────────── status ───────────────────────────────
    def status(self):
        return {
            "running": self.running,
            "owner": self.owner,
            "scan_ready": self.scan_ready,
            "streaming": self.streaming,
            "blocked": self.blocked,
            "note": self.status_note,
            "pkts_per_s": round(getattr(self.bridge, "pkts_per_s", 0.0), 1),
            "sweep_id": getattr(self.bridge, "sweep_id", 0),
            "frames_total": getattr(self.bridge, "frames_total", 0),
            "device_ip": (self.device or {}).get("device_ip"),
        }


if __name__ == "__main__":
    # tiny dry harness: verify env derivation without touching the device
    import ad600_discovery as disc
    fake_dev = {"device_cid": "ddac0650000011dda000000eddcccccc",
                "device_ip": "192.168.5.101", "device_port": 57383}
    fake_if = {"name": "en10", "mac": "34:99:71:ea:53:37", "ipv4": "192.168.5.68"}
    env = _firehose_env(fake_dev, fake_if, disc.derive_our_cid(fake_if["mac"]))
    for k in ("WWB_DEVCID", "WWB_DEVIP", "WWB_DEVPORT", "WWB_CID", "WWB_MYIP",
              "AD600_MCAST_IF", "AD600_OWNER_CLAIM", "AD600_EMIT_FRAMES"):
        print("  %-20s = %s" % (k, env.get(k)))
