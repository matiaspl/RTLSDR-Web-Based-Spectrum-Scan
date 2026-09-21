#!/usr/bin/env python3
"""
ad600_bridge.py — Standalone AD600 Spectrum Analyzer Bridge HTTP server.

High-performance standalone AD600 RF bridge engine: it is fed decoded
RF_SCAN_DATA frames (curve, freq_idx_lo, freq_idx_hi, amps[dBm]) by ad600_engine.py and serves
/info, /configuration, /sweep/*, /trace to clients on 127.0.0.1:<port>.

NOTHING HARDCODED (operator hardening):
  • The frequency GRID is DERIVED FROM OBSERVED DATA — min/max FREQ_IDX and the per-frame stride
    (COMP) the device actually streams. startHz/stopHz/stepHz/pointCount reflect the REAL scan,
    not a baked-in 470–998 MHz / 1325-point grid. A sensible default seeds /info before the first
    sweep, then the grid LOCKS to what the device streams (any band, any resolution).
  • ANTENNAS/series are derived from the data — however many CURVE_IDX values stream (1..N → A..),
    not assumed to be exactly 6.
  • The only FIXED physical constant is the channel plan: freq_MHz = 174 + freq_idx * 0.025
    (25 kHz per index). Everything else adapts.
  • PORT is configurable (env AD600_BRIDGE_PORT, default 8088). Binds 127.0.0.1 only.
  • The 8 AD600 RF_SCAN config values are a PARAMETERIZED dict (scan_config) with derived defaults;
    POST /configuration maps requested startHz/stopHz → SCAN_START_FREQ/SCAN_STOP_FREQ freq_idx
    and invokes on_config_change (engine hook). See TODO in apply_configuration().

Stdlib only. Import and drive via feed()/start()/stop(), or run standalone for a self-test:
    python3 ad600_bridge.py --selftest
"""
import os, sys, json, time, threading, struct, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── the ONE fixed physical constant: the channel plan (25 kHz per freq_idx, base 174 MHz) ──
FREQ_BASE_KHZ = 174000            # freq_idx 0 == 174.000 MHz
IDX_KHZ       = 25                # 25 kHz per freq_idx step  (freq_MHz = 174 + idx*0.025)
FLOOR_DBM     = -130.0            # amplitude floor for grid points with no sample

# ── delivered RBW = REAL_TIME_COMPRESSION * 25 kHz (verified live: comp 36→900kHz, comp 14→350kHz) ──
# Standard RBW reference set so the user picks from standard analyzer values. Whatever they
# pick, rbw_hz_to_comp maps it to the nearest RBW the AD600 can actually STREAM — clamped to the
# validated [350k,900k] band (comp 14..36) — and the POST /configuration response echoes the EFFECTIVE
# value (the clamp-and-echo model). 350 kHz (comp 14) is the finest confirmed streamable; the device
# SET_FAILs below 25 kHz outright, and comp<14 is unproven. Narrow the scan range (startHz/stopHz)
# to afford a finer RBW cheaply.
RBW_COMP_MIN  = 1                 # 25 kHz (1 * 25 kHz) — native hardware quantization floor
RBW_COMP_MAX  = 36                # 900 kHz — feed default (coarsest)
SUPPORTED_RBW_HZ = [25000, 50000, 100000, 350000, 900000]


def rbw_hz_to_comp(rbw_hz):
    """Requested rbwHz → REAL_TIME_COMPRESSION, clamped to the validated streamable [350k,900k]."""
    try:
        comp = int(round(float(rbw_hz) / (IDX_KHZ * 1000.0)))
    except Exception:
        return None
    return max(RBW_COMP_MIN, min(RBW_COMP_MAX, comp))


def comp_to_rbw_hz(comp):
    """REAL_TIME_COMPRESSION → delivered RBW in Hz (the effective value echoed to client)."""
    return int(comp) * IDX_KHZ * 1000


def freq_hz(idx):
    """freq_idx -> Hz. The only physical constant in the whole bridge."""
    return int(round((FREQ_BASE_KHZ + idx * IDX_KHZ) * 1000))


def khz_to_idx(khz):
    return int(round((khz - FREQ_BASE_KHZ) / IDX_KHZ))


def hz_to_idx(hz):
    return khz_to_idx(hz / 1000.0)


def idx_to_khz(idx):
    return FREQ_BASE_KHZ + idx * IDX_KHZ


# ── SEED grid (before the first sweep). These are DEFAULTS, env-overridable, replaced by observed
#    data as soon as frames arrive. They are NOT the runtime grid — the device's real scan is. ──
SEED_IDX_LO = int(os.environ.get("AD600_GRID_IDX_LO", "11840"))    # ~470 MHz
SEED_IDX_HI = int(os.environ.get("AD600_GRID_IDX_HI", "33024"))    # ~998 MHz
SEED_STEP   = int(os.environ.get("AD600_GRID_STEP",   "16"))       # 16 idx == 400 kHz bins


class Grid:
    """A uniform freq_idx grid: lo..hi inclusive, stride `step` (freq_idx units)."""
    __slots__ = ("lo", "hi", "step")

    def __init__(self, lo, hi, step):
        self.lo, self.hi, self.step = int(lo), int(hi), max(1, int(step))

    @property
    def n(self):
        return (self.hi - self.lo) // self.step + 1

    def gi(self, idx):
        return int(round((idx - self.lo) / self.step))

    @property
    def start_hz(self):
        return freq_hz(self.lo)

    @property
    def stop_hz(self):
        return freq_hz(self.hi)

    @property
    def step_hz(self):
        return int(self.step * IDX_KHZ * 1000)

    def key(self):
        return (self.lo, self.hi, self.step)

    def __eq__(self, o):
        return isinstance(o, Grid) and self.key() == o.key()


def _default_scan_config(grid):
    """The 8 AD600 RF_SCAN config values as a parameterized dict, defaults DERIVED from the grid.
    Overridden (start/stop) from client POST /configuration. No inline hex literals."""
    return {
        "scan_start_freq_khz": idx_to_khz(grid.lo),   # SCAN_START_FREQ  (uint32 kHz)
        "scan_stop_freq_khz":  idx_to_khz(grid.hi),   # SCAN_STOP_FREQ   (uint32 kHz)
        "scan_step_idx":       grid.step,             # decimation / bins-per-sample stride
        "res_bw_khz":          grid.step * IDX_KHZ,   # resolution bandwidth
        "repeat":              1,                     # continuous
        "curve_select":        0,                     # 0 = all antennas
        "sweep_rate":          0,                     # device default
        "rt_compression":      grid.step,             # COMP stride reported per frame
    }


class Bridge:
    def __init__(self, port=None, on_start=None, on_stop=None, on_config_change=None):
        self.port = int(port if port is not None else os.environ.get("AD600_BRIDGE_PORT", "8088"))
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_config_change = on_config_change

        self.trace_mode = "clear-write"
        self.max_hold = None          # max-hold accumulator
        self.min_hold = None          # min-hold accumulator
        self._avg_sum = None          # average accumulator (sum + count)
        self._avg_n = 0
        self.vbw_hz = None            # video bandwidth — SOFTWARE smoothing (device has no VBW)
        self.ref_level_dbm = -20      # display reference level (display only; echoed back)
        self.sweeping = False
        self.sweep_id = 0
        self.trace = None
        self.antenna_bias = {'A': False, 'B': False, 'C': False, 'D': False, 'E': False, 'F': False}
        self.antenna_names = {'A': '', 'B': '', 'C': '', 'D': '', 'E': '', 'F': ''}

        # device/identity (filled from discovery by the engine; None until known)
        self.device = {"name": "Shure AD600 (native, WWB-free)", "model": "AD600",
                       "firmware": "native-1.0", "cid": None, "ip": None}

        # ── adaptive grid state ──
        self.seed_grid = Grid(SEED_IDX_LO, SEED_IDX_HI, SEED_STEP)
        self.obs_lo = None
        self.obs_hi = None
        self.obs_step = None
        self.learned_top = None                # highest fhi seen (the real band top for this config)
        self.scan_config = _default_scan_config(self.seed_grid)

        # ── per-antenna assembly (grid-agnostic: absolute freq_idx -> dBm) ──
        self.building = {}                     # ant -> {freq_idx: dbm}
        self.latest = {}                       # ant -> {freq_idx: dbm} (last completed sweep)
        self.last_flo = {}                     # ant -> last frame's flo (restart detection)
        self.cycle = set()

        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._httpd = None
        self._http_thread = None

        # live stats (menubar)
        self.frames_total = 0
        self.frames_window = 0
        self._win_t0 = time.time()
        self.pkts_per_s = 0.0
        self.last_frame_t = 0.0

    # ───────────────────────────────── grid derivation ─────────────────────────────────
    def reset_observed(self):
        """Forget the learned grid + partial sweeps so the NEXT scan re-learns its range/RBW from
        scratch. Called on a config change (RBW/range) — otherwise the old full-band extents linger
        and effective_grid() keeps reporting the previous span after a re-arm."""
        with self._cv:
            self.obs_lo = self.obs_hi = self.obs_step = None
            self.learned_top = None
            self.building.clear()
            self.latest.clear()
            self.last_flo.clear()
            self.cycle.clear()
            self.trace = None
            self.sweep_id = 0
            self._reset_accum()

    def _observed_grid(self):
        if self.obs_lo is None or self.learned_top is None or not self.obs_step:
            return None
        return Grid(self.obs_lo, self.learned_top, self.obs_step)

    def effective_grid(self):
        return self._observed_grid() or self.seed_grid

    # ───────────────────────────────── frame ingestion ─────────────────────────────────
    def feed(self, curve, flo, fhi, amps):
        """Called per decoded FRAME. Grid-agnostic ingest; publishes a merged trace per sweep."""
        with self._cv:
            n = len(amps)
            if n <= 0:
                return
            stride = int(round((fhi - flo) / (n - 1))) if n > 1 else (self.obs_step or SEED_STEP)
            if stride <= 0:
                stride = self.obs_step or SEED_STEP
            # update observed extents/stride
            self.obs_lo = flo if self.obs_lo is None else min(self.obs_lo, flo)
            self.obs_hi = fhi if self.obs_hi is None else max(self.obs_hi, fhi)
            self.obs_step = stride                    # frames within a config are uniform
            ant = int(curve)

            # restart detection: this antenna's frame wrapped back to (or below) its previous flo
            if ant in self.building and flo <= self.last_flo.get(ant, 1 << 30):
                self._finalize(ant)

            d = self.building.setdefault(ant, {})
            for k, a in enumerate(amps):
                d[flo + k * stride] = a
            self.last_flo[ant] = flo

            # top reached: only finalize if we reached the true target stop frequency
            stop_khz = self.scan_config.get("scan_stop_freq_khz")
            if stop_khz:
                target_top_idx = khz_to_idx(stop_khz)
                if fhi >= target_top_idx - (self.obs_step or SEED_STEP):
                    self._finalize(ant)
            elif self.learned_top is not None and fhi >= self.learned_top:
                self._finalize(ant)

            # stats
            self.frames_total += 1
            self.frames_window += 1
            self.last_frame_t = time.time()
            dt = self.last_frame_t - self._win_t0
            if dt >= 1.0:
                self.pkts_per_s = self.frames_window / dt
                self.frames_window = 0
                self._win_t0 = self.last_frame_t

    def _finalize(self, ant):
        """Move an antenna's building buffer to `latest`; learn band top; publish once per cycle."""
        buf = self.building.pop(ant, None)
        self.last_flo.pop(ant, None)
        if not buf:
            return
        top = max(buf.keys())
        self.learned_top = top if self.learned_top is None else max(self.learned_top, top)
        if ant not in self.latest:
            self.latest[ant] = {}
        # Persistent Phosphor: Update in-place so un-scanned or dropped bins retain previous values
        self.latest[ant].update(buf)
        if ant in self.cycle:
            self._publish()
            self.cycle.clear()
            if self.scan_config.get("repeat") == 1:
                with self._lock:
                    self.sweeping = False
        self.cycle.add(ant)

    def _clean(self, arr):
        return [round((v if v > FLOOR_DBM else FLOOR_DBM) * 10) / 10 for v in arr]

    def _reset_accum(self):
        """Clear all traceMode accumulators — called on a mode change or a fresh sweep start so a
        new max/min/average doesn't inherit the previous run's history."""
        self.max_hold = None
        self.min_hold = None
        self._avg_sum = None
        self._avg_n = 0

    def _apply_vbw(self, arr):
        """Software video-bandwidth smoothing: the AD600 exposes no hardware VBW, so when the client
        selects a VBW below the RBW we emulate it with a centered moving average whose window ≈
        RBW/VBW points. VBW ≥ RBW (or unset) → no smoothing. Honest emulation, clearly not hardware."""
        vbw = self.vbw_hz
        g = self.effective_grid()
        rbw = g.step_hz
        if not vbw or vbw <= 0 or rbw <= 0 or vbw >= rbw:
            return arr
        w = int(round(rbw / float(vbw)))
        if w < 2:
            return arr
        half = w // 2
        n = len(arr)
        out = [0.0] * n
        for i in range(n):
            lo = max(0, i - half)
            hi = min(n, i + half + 1)
            out[i] = sum(arr[lo:hi]) / (hi - lo)
        return out

    def _publish(self):
        grid = self.effective_grid()
        N = grid.n
        ants = sorted(self.latest.keys())
        if not ants or N <= 0:
            return
        merged = [float("-inf")] * N
        series = []
        for ant in ants:
            arr = [float("-inf")] * N
            for idx, v in self.latest[ant].items():
                g = grid.gi(idx)
                if 0 <= g < N and v > arr[g]:
                    arr[g] = v
            for i in range(N):
                if arr[i] > merged[i]:
                    merged[i] = arr[i]
            series.append({"name": self._ant_label(ant), "amplitudesDbm": self._clean(arr)})
        # ── traceMode accumulation (bridge-side, per the contract; device streams raw per-sweep) ──
        out = merged
        if self.trace_mode == "max-hold":
            if self.max_hold is None or len(self.max_hold) != N:
                self.max_hold = merged[:]
            else:
                for i in range(N):
                    if merged[i] > self.max_hold[i]:
                        self.max_hold[i] = merged[i]
            out = self.max_hold[:]
        elif self.trace_mode == "min-hold":
            if self.min_hold is None or len(self.min_hold) != N:
                self.min_hold = merged[:]
            else:
                for i in range(N):
                    if merged[i] < self.min_hold[i]:
                        self.min_hold[i] = merged[i]
            out = self.min_hold[:]
        elif self.trace_mode == "average":
            if self._avg_sum is None or len(self._avg_sum) != N:
                self._avg_sum = merged[:]
                self._avg_n = 1
            else:
                for i in range(N):
                    self._avg_sum[i] += merged[i]
                self._avg_n += 1
            out = [s / self._avg_n for s in self._avg_sum]
        # ── VBW: SOFTWARE video-bandwidth smoothing (the AD600 has no hardware VBW) ──
        out = self._apply_vbw(out)
        self.sweep_id += 1
        self.trace = {
            "startHz": grid.start_hz, "stopHz": grid.stop_hz, "stepHz": grid.step_hz,
            "pointCount": N, "sweepId": self.sweep_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            "unit": "dBm", "amplitudesDbm": self._clean(out), "series": series,
            "sweeping": self.sweeping,
            "antennaBias": self.antenna_bias,
            "antennaNames": self.antenna_names,
        }
        # keep scan_config in sync with the observed grid unless client overrode the range
        self.scan_config.setdefault("_range_from_config", False)
        if not self.scan_config.get("_range_from_config"):
            self.scan_config["scan_start_freq_khz"] = idx_to_khz(grid.lo)
            self.scan_config["scan_stop_freq_khz"] = idx_to_khz(grid.hi)
            self.scan_config["scan_step_idx"] = grid.step
            self.scan_config["rt_compression"] = grid.step
        self._cv.notify_all()

    @staticmethod
    def _ant_label(ant):
        # 1..N -> A..; falls back to "Ant<n>" past Z
        if 1 <= ant <= 26:
            return chr(ord("A") + ant - 1)
        return "Ant%d" % ant

    # ───────────────────────────────── HTTP payloads ─────────────────────────────────
    def info(self):
        g = self.effective_grid()
        caps = {
            "minFrequencyHz": freq_hz(SEED_IDX_LO), "maxFrequencyHz": freq_hz(SEED_IDX_HI),
            "rbwHz": SUPPORTED_RBW_HZ, "vbwHz": SUPPORTED_RBW_HZ,
            "minRefLevelDbm": -130, "maxRefLevelDbm": 0,
            "minStepHz": comp_to_rbw_hz(RBW_COMP_MIN), "maxStepHz": comp_to_rbw_hz(RBW_COMP_MAX),
            "pointCount": g.n, "startHz": g.start_hz, "stopHz": g.stop_hz,
            "traceModes": ["clear-write", "max-hold", "min-hold", "average"],
        }
        name = self.device.get("name") or "Shure AD600 (native, WWB-free)"
        return {"name": name, "manufacturer": "Shure", "model": self.device.get("model", "AD600"),
                "firmware": self.device.get("firmware", "native-1.0"), "protocolVersion": "1.0.0",
                "capabilities": caps}

    def configuration(self):
        g = self.effective_grid()
        # Echo the EFFECTIVE config: what the client asked for, clamped/quantized to what the device
        # will actually stream — so a just-POSTed change reflects back immediately, before frames of
        # the new sweep arrive (reset_observed() cleared the observed grid on reconfig).
        comp = self.scan_config.get("req_rt_compression")
        eff_rbw = comp_to_rbw_hz(comp) if comp else g.step_hz
        if self.scan_config.get("_range_from_config"):
            start_hz = int(self.scan_config["scan_start_freq_khz"] * 1000)
            stop_hz = int(self.scan_config["scan_stop_freq_khz"] * 1000)
        else:
            start_hz, stop_hz = g.start_hz, g.stop_hz
        n = max(1, (stop_hz - start_hz) // eff_rbw + 1) if eff_rbw else g.n
        return {"startHz": start_hz, "stopHz": stop_hz,
                "centerHz": (start_hz + stop_hz) // 2, "spanHz": stop_hz - start_hz,
                "rbwHz": eff_rbw, "stepHz": eff_rbw,
                "vbwHz": self.vbw_hz or eff_rbw, "refLevelDbm": self.ref_level_dbm,
                "traceMode": self.trace_mode, "pointCount": n,
                "sweeping": self.sweeping,
                "curveMask": self.scan_config.get("curve_select", 0x7E),
                "repeat": self.scan_config.get("repeat", 0xFF),
                "antennaBias": self.antenna_bias,
                "antennaNames": self.antenna_names}

    def apply_configuration(self, body):
        """POST /configuration — the FULL scanning-control surface, each field mapped to what
        the AD600 actually has:
          • startHz/stopHz (or centerHz/spanHz) → SCAN_START_FREQ/SCAN_STOP_FREQ  (device range)
          • rbwHz / stepHz                       → REAL_TIME_COMPRESSION           (device resolution)
          • curveMask                            → CURVE_SELECT                    (hardware active curves)
          • repeat                               → SCAN_REPEAT_REQUEST             (continuous vs single)
          • traceMode                            → bridge-side clear-write/max-hold/min-hold/average
          • vbwHz                                → SOFTWARE video-bandwidth smoothing (no hardware VBW)
          • refLevelDbm                          → stored for display echo (display only)
        Range/RBW changes set changed=True → engine re-arms (config latches at arm time). Display-only
        fields (traceMode/vbw/refLevel) take effect immediately without a re-arm. The response echoes
        the EFFECTIVE config after clamping, per the contract.
        """
        changed = False
        # ── traceMode: clear-write / max-hold / min-hold / average (bridge-side accumulation) ──
        tm = body.get("traceMode")
        if tm in ("clear-write", "max-hold", "min-hold", "average") and tm != self.trace_mode:
            self.trace_mode = tm
            self._reset_accum()
        # ── VBW: software smoothing (no device VBW) ──
        if body.get("vbwHz") is not None:
            try:
                self.vbw_hz = float(body["vbwHz"]) or None
            except (TypeError, ValueError):
                pass
        # ── reference level: display only (echoed, no device effect) ──
        if body.get("refLevelDbm") is not None:
            try:
                self.ref_level_dbm = float(body["refLevelDbm"])
            except (TypeError, ValueError):
                pass
        # ── RBW / step → REAL_TIME_COMPRESSION (delivered-resolution knob; rbwHz wins if both sent) ──
        rbw_req = body.get("rbwHz") or body.get("stepHz")
        if rbw_req:
            comp = rbw_hz_to_comp(rbw_req)
            if comp and comp != self.scan_config.get("req_rt_compression"):
                self.scan_config["req_rt_compression"] = comp
                changed = True
        # ── curveMask → CURVE_SELECT ──
        if "curveMask" in body:
            try:
                cm = int(body["curveMask"])
                if cm > 0 and cm != self.scan_config.get("curve_select"):
                    self.scan_config["curve_select"] = cm
                    changed = True
            except Exception:
                pass
        # ── repeat → SCAN_REPEAT_REQUEST (0xFF for continuous, 0x01 for single-shot) ──
        if "repeat" in body:
            try:
                rep = int(body["repeat"])
                if rep in (1, 0xFF, 255) and rep != self.scan_config.get("repeat"):
                    self.scan_config["repeat"] = rep
                    changed = True
            except Exception:
                pass
        # ── range: startHz/stopHz (or centerHz/spanHz) → SCAN_START_FREQ/SCAN_STOP_FREQ (kHz) ──
        start_hz = body.get("startHz")
        stop_hz = body.get("stopHz")
        if start_hz is None and body.get("centerHz") is not None and body.get("spanHz") is not None:
            start_hz = body["centerHz"] - body["spanHz"] / 2.0
            stop_hz = body["centerHz"] + body["spanHz"] / 2.0
        if start_hz is not None and stop_hz is not None and stop_hz > start_hz:
            new_start = idx_to_khz(hz_to_idx(start_hz))
            new_stop = idx_to_khz(hz_to_idx(stop_hz))
            if (new_start != self.scan_config.get("scan_start_freq_khz")
                    or new_stop != self.scan_config.get("scan_stop_freq_khz")
                    or not self.scan_config.get("_range_from_config")):
                self.scan_config["scan_start_freq_khz"] = new_start
                self.scan_config["scan_stop_freq_khz"] = new_stop
                self.scan_config["_range_from_config"] = True
                changed = True
        if changed:
            self.reset_observed()          # re-learn the grid for the new range/RBW after re-arm
            if callable(self.on_config_change):
                try:
                    self.on_config_change(dict(self.scan_config))
                except Exception as e:
                    sys.stderr.write("[bridge] on_config_change hook error: %r\n" % e)
        return self.configuration()

    # ───────────────────────────────── sweep control ─────────────────────────────────
    def sweep_start(self):
        with self._lock:
            self.sweeping = True
            self.sweep_id = 0
            self._reset_accum()        # a fresh sweep starts a clean max/min/average accumulation
        if callable(self.on_start):
            try:
                self.on_start()
            except Exception as e:
                sys.stderr.write("[bridge] on_start hook error: %r\n" % e)
        return {"sweeping": True, "sweepId": self.sweep_id}

    def sweep_stop(self):
        with self._lock:
            self.sweeping = False
            self.sweep_id = 0
        if callable(self.on_stop):
            try:
                self.on_stop()
            except Exception as e:
                sys.stderr.write("[bridge] on_stop hook error: %r\n" % e)
        return {"sweeping": False, "sweepId": self.sweep_id}

    def get_trace(self, wait=2.5):
        """Long-poll: block up to `wait`s for a NEW sweep, else return the latest (or None)."""
        with self._cv:
            seen = self.sweep_id
            if self.trace is not None:
                # return immediately if we already have a trace the caller hasn't seen advance past
                if self.sweep_id > 0:
                    return self.trace
            self._cv.wait(timeout=wait)
            return self.trace

    # ───────────────────────────────── HTTP server ─────────────────────────────────
    def serve(self, block=False):
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _body(self):
                try:
                    ln = int(self.headers.get("Content-Length", 0))
                    raw = self.rfile.read(ln) if ln else b""
                    return json.loads(raw) if raw else {}
                except Exception:
                    return {}

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/info":
                    return self._json(200, bridge.info())
                if path == "/configuration":
                    return self._json(200, bridge.configuration())
                if path == "/bias":
                    return self._json(200, bridge.antenna_bias)
                if path == "/sweep/start":
                    return self._json(200, bridge.sweep_start())
                if path == "/sweep/stop":
                    return self._json(200, bridge.sweep_stop())
                if path == "/trace":
                    tr = bridge.get_trace()
                    if tr is None:
                        return self._json(409, {"error": "no_trace",
                                                "detail": "No sweep completed yet."})
                    return self._json(200, tr)
                return self._json(404, {"error": "not_found"})

            def do_POST(self):
                path = self.path.split("?")[0]
                if path == "/configuration":
                    return self._json(200, bridge.apply_configuration(self._body()))
                if path == "/sweep/start":
                    return self._json(200, bridge.sweep_start())
                if path == "/sweep/stop":
                    return self._json(200, bridge.sweep_stop())
                if path == "/bias":
                    b = self._body()
                    ant = str(b.get("antenna", "A")).upper()
                    enabled = bool(b.get("enabled", False))
                    idx = ord(ant) - ord('A') if ('A' <= ant <= 'F') else 0
                    bridge.antenna_bias[ant] = enabled
                    cmd_dir = os.environ.get("AD600_ENGINE_SCRATCH") or os.path.join(os.path.expanduser("~"), ".ad600_scanner")
                    try:
                        os.makedirs(cmd_dir, exist_ok=True)
                        with open(os.path.join(cmd_dir, "console_cmd.txt"), "a") as f:
                            f.write("set 0107047%d %s\n" % (idx, "01" if enabled else "00"))
                        return self._json(200, {"antenna": ant, "enabled": enabled, "status": "ok"})
                    except Exception as e:
                        return self._json(500, {"error": str(e)})
                if path == "/antenna_name":
                    b = self._body()
                    ant = str(b.get("antenna", "A")).upper()
                    name = str(b.get("name", "")).strip()
                    bridge.antenna_names[ant] = name
                    return self._json(200, {"antenna": ant, "name": name, "status": "ok"})
                return self._json(404, {"error": "not_found"})

        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.port = self._httpd.server_address[1]
        if block:
            self._httpd.serve_forever()
        else:
            self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._http_thread.start()
        return self.port

    def shutdown(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None


# ─────────────────────────────────────────────────────────────────────────────────────────────
# Self-test (off-device): synthetic frames, incl. a NON-default range/stride, assert /trace adapts.
# ─────────────────────────────────────────────────────────────────────────────────────────────
def _synth_sweep(bridge, lo, hi, step, curves, base=-100.0):
    """Feed one full sweep for each curve across lo..hi with the given stride (freq_idx units).
    Split into several frames per antenna to exercise multi-frame assembly."""
    per_frame = 64
    for ant in curves:
        idx = lo
        while idx <= hi:
            fhi = min(idx + per_frame * step, hi)
            amps = []
            j = idx
            while j <= fhi:
                amps.append(base + (ant * 1.0) + ((j - lo) % 7))
                j += step
            bridge.feed(ant, idx, fhi, amps)
            idx = fhi + step


def _selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + name)
        ok = ok and cond

    # 1) default-ish grid, 6 antennas
    b = Bridge(port=0)
    b.serve()
    _synth_sweep(b, SEED_IDX_LO, SEED_IDX_HI, SEED_STEP, range(1, 7))
    _synth_sweep(b, SEED_IDX_LO, SEED_IDX_HI, SEED_STEP, range(1, 7))
    tr = b.trace
    exp_n = (SEED_IDX_HI - SEED_IDX_LO) // SEED_STEP + 1
    check("default grid pointCount == %d" % exp_n, tr and tr["pointCount"] == exp_n)
    check("amplitudesDbm length == pointCount", tr and len(tr["amplitudesDbm"]) == tr["pointCount"])
    check("6 antenna series A..F",
          tr and [s["name"] for s in tr["series"]] == ["A", "B", "C", "D", "E", "F"])
    check("startHz == freq_hz(SEED_IDX_LO)", tr and tr["startHz"] == freq_hz(SEED_IDX_LO))
    check("stopHz == freq_hz(SEED_IDX_HI)", tr and tr["stopHz"] == freq_hz(SEED_IDX_HI))
    info = b.info()
    check("/info valid + protocolVersion 1.0.0", info["protocolVersion"] == "1.0.0")
    cfg = b.configuration()
    check("/configuration pointCount matches", cfg["pointCount"] == exp_n)
    ss = b.sweep_start()
    check("/sweep/start toggles sweeping", ss["sweeping"] is True and b.sweeping)
    b.shutdown()

    # 2) ADAPTIVE: a DIFFERENT range + stride than the default → grid must follow the DATA
    lo2, hi2, step2 = 20000, 25000, 8
    b2 = Bridge(port=0)
    b2.serve()
    _synth_sweep(b2, lo2, hi2, step2, range(1, 4))   # only 3 antennas this time
    _synth_sweep(b2, lo2, hi2, step2, range(1, 4))
    tr2 = b2.trace
    exp_n2 = (hi2 - lo2) // step2 + 1
    check("ADAPTIVE pointCount == %d (not %d default)" % (exp_n2, exp_n),
          tr2 and tr2["pointCount"] == exp_n2 and tr2["pointCount"] != exp_n)
    check("ADAPTIVE startHz == freq_hz(%d)" % lo2, tr2 and tr2["startHz"] == freq_hz(lo2))
    check("ADAPTIVE stopHz == freq_hz(%d)" % hi2, tr2 and tr2["stopHz"] == freq_hz(hi2))
    check("ADAPTIVE stepHz == %d Hz" % (step2 * IDX_KHZ * 1000),
          tr2 and tr2["stepHz"] == step2 * IDX_KHZ * 1000)
    check("ADAPTIVE 3 antenna series A..C",
          tr2 and [s["name"] for s in tr2["series"]] == ["A", "B", "C"])
    # Configuration maps range → scan_config
    caught = {}
    b2.on_config_change = lambda cfg: caught.update(cfg)
    eff = b2.apply_configuration({"startHz": freq_hz(21000), "stopHz": freq_hz(23000),
                                  "traceMode": "max-hold"})
    check("POST /configuration set traceMode max-hold", eff["traceMode"] == "max-hold")
    check("POST /configuration mapped range → scan_config SCAN_START_FREQ",
          caught.get("scan_start_freq_khz") == idx_to_khz(21000))
    b2.shutdown()

    print("\nSELFTEST:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    br = Bridge()
    port = br.serve(block=False)
    sys.stderr.write("AD600 bridge on 127.0.0.1:%d\n" % port)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        br.shutdown()
