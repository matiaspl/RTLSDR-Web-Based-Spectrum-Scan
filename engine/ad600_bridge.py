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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import scratch_dir
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── the ONE fixed physical constant: the channel plan (25 kHz per freq_idx, base 174 MHz) ──
FREQ_BASE_KHZ = 174000            # freq_idx 0 == 174.000 MHz
IDX_KHZ       = 25                # 25 kHz per freq_idx step  (freq_MHz = 174 + idx*0.025)
FLOOR_DBM     = -130.0            # amplitude floor for grid points with no sample
# No legitimate AD600 RF reading is above this — a value past it is a decode artifact (an
# occasional corrupted RF_SCAN_DATA frame reads as a wildly out-of-range int16, e.g. 2253.0 or
# 1459.4 dBm; see AD600_Reverse_Engineering_Findings.md §6.3). Such samples are dropped at ingest
# so they can never reach the trace or latch into a max-hold accumulator.
SANE_CEILING_DBM = 20.0

# ── delivered RBW = REAL_TIME_COMPRESSION * 25 kHz ──
# Standard RBW reference set so the user picks from standard analyzer values. Whatever they
# pick, rbw_hz_to_comp maps it to the nearest RBW the AD600 can actually STREAM — clamped to the
# validated range — and the POST /configuration response echoes the EFFECTIVE value (the
# clamp-and-echo model).
#
# Verified live against a real AD600 (2026-09, cross-checked against desktop testing):
# comp 2 (50 kHz) through comp 36 (900 kHz) stream clean, sane amplitudes. comp 1
# (25 kHz) reproducibly returns CORRUPTED amplitudes (physically impossible dBm values) — the
# RF_SCAN_DATA frame layout at that compression isn't the one parse_rf_scan_data (ad600_native.py)
# assumes, and needs an actual packet capture at comp=1 to fix correctly. So 50 kHz, not 25 kHz,
# is the real floor until that decode is fixed.
RBW_COMP_MIN  = 2                 # 50 kHz — comp 1 (25 kHz) is known to corrupt amplitudes; see above
RBW_COMP_MAX  = 36                # 900 kHz — feed default (coarsest)
SUPPORTED_RBW_HZ = [50000, 100000, 350000, 900000]


def rbw_hz_to_comp(rbw_hz):
    """Requested rbwHz → REAL_TIME_COMPRESSION, clamped to the validated streamable [50k,900k]."""
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
        "repeat":              0xFF,                  # 0xFF = continuous, 1 = single-shot
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
        self.latest = {}                       # ant -> {freq_idx: dbm}, mirrors `building` once covered
        self.seen_lo = {}                      # ant -> has a frame touched grid.lo since the last reset?
        self.seen_hi = {}                      # ant -> has a frame touched grid.hi since the last reset?
        self.sweep_count = 0                   # completed passes over the configured band
        self._single_done = False              # single-shot (repeat==1) pass already completed

        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._httpd = None
        self._http_thread = None
        # Guards console_cmd.txt, which this process's /bias handler (appends) and the engine's
        # _run_once() (truncates on every arm/re-arm) both write to from different threads.
        self.cmdfile_lock = threading.Lock()

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
            self.seen_lo.clear()
            self.seen_hi.clear()
            self.sweep_count = 0
            self._single_done = False
            self.trace = None
            self.sweep_id = 0
            self._reset_accum()

    def _observed_grid(self):
        top = self.learned_top if self.learned_top is not None else self.obs_hi
        if self.obs_lo is None or top is None or not self.obs_step:
            return None
        return Grid(self.obs_lo, top, self.obs_step)

    def effective_grid(self):
        if self.scan_config.get("_range_from_config"):
            start_khz = int(self.scan_config.get("scan_start_freq_khz") or 0)
            stop_khz = int(self.scan_config.get("scan_stop_freq_khz") or 0)
            if start_khz and stop_khz:
                # The configured range is authoritative (not whatever tiles have arrived so far), and
                # so is the EXACT compression we told the device to use — a boundary/short frame's own
                # (fhi-flo)/(n-1) can round to a different stride, and re-gridding every stored point
                # on a per-frame stride makes points blip out of range (findings §6.4).
                step = self.scan_config.get("req_rt_compression") or self.obs_step or 1
                lo, hi = khz_to_idx(start_khz), khz_to_idx(stop_khz)
                # The device streams floor(span/step) samples starting at the start frequency and
                # never includes the stop (verified live: 470-524 MHz @ 350 kHz -> 154 samples,
                # @ 100 kHz -> 540; 470-616 MHz @ 100 kHz -> 1460, ending at 615.9). Predicting
                # that keeps the grid size fixed from the first tile instead of shrinking by one
                # bin when the top tile finally arrives. An observed top beyond the prediction
                # (never seen so far) still wins, capped at the requested stop.
                n = max(1, (hi - lo) // step)
                top = lo + (n - 1) * step
                if self.learned_top is not None and top < self.learned_top <= hi:
                    top = self.learned_top
                return Grid(lo, top, step)
        return self._observed_grid() or self.seed_grid

    # ───────────────────────────────── frame ingestion ─────────────────────────────────
    def feed(self, curve, flo, fhi, amps):
        """Called per decoded FRAME (one tile of one antenna's sweep). See findings §6.2."""
        with self._cv:
            n = len(amps)
            if n <= 0:
                return
            # The compression we requested is authoritative for storage indexing (findings §6.4);
            # only a bare session with no requested compression falls back to the frame's own stride.
            known_comp = self.scan_config.get("req_rt_compression")
            if known_comp:
                stride = int(known_comp)
            else:
                stride = int(round((fhi - flo) / (n - 1))) if n > 1 else (self.obs_step or SEED_STEP)
                if stride <= 0:
                    stride = self.obs_step or SEED_STEP
            self.obs_lo = flo if self.obs_lo is None else min(self.obs_lo, flo)
            self.obs_hi = fhi if self.obs_hi is None else max(self.obs_hi, fhi)
            self.obs_step = stride
            self.learned_top = fhi if self.learned_top is None else max(self.learned_top, fhi)
            ant = int(curve)

            # Never cleared mid-sweep: keys are absolute freq_idx, so a re-sample of a frequency
            # overwrites its own entry and each tile refreshes only its own slice. Corrupted
            # samples (§6.3) are skipped, leaving the previous good value in place.
            d = self.building.setdefault(ant, {})
            for k, a in enumerate(amps):
                if FLOOR_DBM < a <= SANE_CEILING_DBM:
                    d[flo + k * stride] = a

            now = time.time()
            self.frames_total += 1
            self.frames_window += 1
            self.last_frame_t = now
            dt = now - self._win_t0
            if dt >= 1.0:
                self.pkts_per_s = self.frames_window / dt
                self.frames_window = 0
                self._win_t0 = now

            # Coverage tracking, not "sweep completion" (findings §6.2): a wide span at a fine RBW
            # streams as several tiles per antenna arriving at very uneven intervals (live: the top
            # tile of 470-616 MHz @ 100 kHz first arrived ~60 s after the low one). Every frame
            # republishes the accumulated picture on the fixed configured grid, flagged
            # `coverageComplete: false` until each antenna has touched BOTH edges at least once, so
            # the operator sees the band fill in rather than a blank plot or a partial one
            # presented as complete.
            grid = self.effective_grid()
            touched_hi = fhi >= grid.hi - (stride * 2)
            was_covered = bool(self.seen_lo.get(ant) and self.seen_hi.get(ant))
            if flo <= grid.lo + (stride * 5):
                self.seen_lo[ant] = True
            if touched_hi:
                self.seen_hi[ant] = True
            if not d:
                return
            self.latest[ant] = dict(d)
            if not (self.seen_lo.get(ant) and self.seen_hi.get(ant)):
                self._publish()
                return
            # Counts passes of the lowest-numbered antenna: the moment its band first becomes fully
            # covered, then each later top-edge tile — so it tracks sweeps, not frames or antennas.
            if ant == min(self.latest) and (touched_hi or not was_covered):
                self.sweep_count += 1
            if self.scan_config.get("repeat") == 1 and not self._single_done:
                expected = self._expected_antennas()
                if expected and all(self.seen_lo.get(a) and self.seen_hi.get(a) for a in expected):
                    self._single_done = True
                    self.sweeping = False
            self._publish()

    def _expected_antennas(self):
        """Antenna curves (1..6) the device was asked to stream, from the CURVE_SELECT mask."""
        mask = int(self.scan_config.get("curve_select") or 0) or 0x7E
        return [a for a in range(1, 7) if mask & (1 << a)]

    def _clean(self, arr):
        return [round((v if FLOOR_DBM < v <= SANE_CEILING_DBM else FLOOR_DBM) * 10) / 10
                for v in arr]

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
        filled = sum(1 for v in merged if v > FLOOR_DBM)
        complete = bool(ants) and all(self.seen_lo.get(a) and self.seen_hi.get(a) for a in ants)
        self.sweep_id += 1
        self.trace = {
            "startHz": grid.start_hz, "stopHz": grid.stop_hz, "stepHz": grid.step_hz,
            "pointCount": N, "sweepId": self.sweep_id, "sweepCount": self.sweep_count,
            "coverageComplete": complete, "coveragePct": int(100 * filled / N) if N else 0,
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
            self._single_done = False
            if self.scan_config.get("repeat") == 1:
                # a new single-shot pass must re-cover the band before it counts as done
                self.seen_lo.clear()
                self.seen_hi.clear()
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
                    ant = str(b.get("antenna", "")).upper()
                    if len(ant) != 1 or not ('A' <= ant <= 'F'):
                        return self._json(400, {"error": "antenna must be A-F"})
                    enabled = bool(b.get("enabled", False))
                    idx = ord(ant) - ord('A')
                    # antenna_bias is NOT updated here — only the device's own BIAS report (via
                    # the engine) changes it, so a lost or refused SET can't show as applied.
                    cmd_dir = scratch_dir()
                    try:
                        # Shared with Engine._run_once(), which truncates this same file on every
                        # (re)arm — without this lock a bias command written mid-truncate is lost.
                        with bridge.cmdfile_lock, open(os.path.join(cmd_dir, "console_cmd.txt"), "a") as f:
                            f.write("set 0107047%d %s\n" % (idx, "01" if enabled else "00"))
                            f.write("get 0107047%d\n" % idx)   # read back → BIAS telemetry line
                        return self._json(200, {"antenna": ant, "requested": enabled, "status": "pending"})
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

    # 3) MULTI-TILE, UNEVEN ARRIVAL (findings §6.2): 470-616 MHz @ 100 kHz streams as three tiles
    # per antenna, the top one arriving far less often. (a) a frame touching one edge alone must not
    # count as covered; (b) once covered, a repeat low tile must not blank the higher tiles.
    b3 = Bridge(port=0)
    b3.apply_configuration({"startHz": freq_hz(0), "stopHz": freq_hz(3000), "rbwHz": 100000})

    def feed_tile(lo, hi, level, bridge=b3):
        bridge.feed(1, lo, hi, [level] * ((hi - lo) // 4 + 1))

    for _ in range(3):
        feed_tile(0, 1200, -60.0)
    feed_tile(1200, 2400, -70.0)
    tr0 = b3.trace or {}
    check("multi-tile: partial trace flagged incomplete before both edges are covered",
          tr0.get("coverageComplete") is False and 0 < tr0.get("coveragePct", 0) < 100
          and tr0.get("pointCount") == 750 and tr0["amplitudesDbm"][-1] <= FLOOR_DBM)
    feed_tile(2400, 2996, -50.0)
    amps = (b3.trace or {}).get("amplitudesDbm") or []
    check("multi-tile: grid spans the configured range (floor(span/step) samples)", len(amps) == 750)
    check("multi-tile: flagged complete once every tile has arrived",
          b3.trace.get("coverageComplete") is True and b3.trace.get("coveragePct") == 100)
    check("multi-tile: all three tiles present once covered",
          len(amps) > 0 and amps[0] > -125 and amps[len(amps) // 2] > -125 and amps[-1] > -125)
    feed_tile(0, 1200, -61.0)
    amps2 = (b3.trace or {}).get("amplitudesDbm") or []
    check("multi-tile: a repeat low tile doesn't erase the high tiles",
          len(amps2) > 0 and abs(amps2[0] + 61.0) < 0.05 and abs(amps2[-1] + 50.0) < 0.05)

    # 4) CORRUPTED FRAME (findings §6.3): a physically impossible amplitude is dropped at ingest
    # and can never latch into max-hold.
    b3.apply_configuration({"traceMode": "max-hold"})
    feed_tile(0, 1200, 2253.0)
    feed_tile(2400, 2996, -50.0)
    amps3 = (b3.trace or {}).get("amplitudesDbm") or []
    check("corrupted frame: nothing above the sane ceiling reaches the trace",
          len(amps3) > 0 and max(amps3) <= SANE_CEILING_DBM and abs(amps3[0] + 61.0) < 0.05)
    s3 = [x for x in b3.trace["series"] if x["name"] == "A"][0]["amplitudesDbm"]
    check("corrupted frame: per-antenna series also clean", max(s3) <= SANE_CEILING_DBM)

    # 5) SINGLE-SHOT: repeat=1 with only antenna A selected stops once A has covered the band.
    b4 = Bridge(port=0)
    b4.apply_configuration({"startHz": freq_hz(0), "stopHz": freq_hz(3000), "rbwHz": 100000,
                            "curveMask": 0x02, "repeat": 1})
    b4.sweep_start()
    feed_tile(0, 1500, -60.0, b4)
    check("single-shot: still sweeping mid-pass", b4.sweeping is True)
    feed_tile(1500, 3000, -60.0, b4)
    check("single-shot: stops after one covered pass", b4.sweeping is False and b4.sweep_count == 1)

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
