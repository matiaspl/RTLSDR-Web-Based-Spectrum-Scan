#!/usr/bin/env python3
"""rtl_tcp spectrum scanner and local HTTP bridge.

Connects to an rtl_tcp server, tunes across a requested frequency span, computes a windowed
FFT for each tuned segment, and serves the resulting trace on the API used by the dashboard.
Only the Python standard library is required.
"""
import json
import math
import os
import signal
import socket
import struct
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

try:
    from engine import gsm_calibration as gsm
except ModuleNotFoundError:
    import gsm_calibration as gsm


BRIDGE_PORT = int(os.environ.get("RTL_BRIDGE_PORT", "8088"))
RTL_HOST = os.environ.get("RTL_TCP_HOST", "127.0.0.1")
RTL_PORT = int(os.environ.get("RTL_TCP_PORT", "1234"))
SAMPLE_RATE = int(os.environ.get("RTL_SAMPLE_RATE", "1800000"))
if not 250_000 <= SAMPLE_RATE <= 3_200_000:
    raise ValueError("RTL_SAMPLE_RATE must be between 250000 and 3200000 samples/s")
try:
    TUNER_GAIN_DB = float(os.environ.get("RTL_TUNER_GAIN_DB", "25"))
except ValueError as exc:
    raise ValueError("RTL_TUNER_GAIN_DB must be a number in dB") from exc
if not 0 <= TUNER_GAIN_DB <= 50:
    raise ValueError("RTL_TUNER_GAIN_DB must be between 0 and 50 dB")
TUNER_AGC = os.environ.get("RTL_TUNER_AGC", "0") == "1"
DIGITAL_AGC = os.environ.get("RTL_DIGITAL_AGC", "0") == "1"
try:
    PPM_CORRECTION = int(os.environ.get("RTL_PPM_CORRECTION", "0"))
except ValueError as exc:
    raise ValueError("RTL_PPM_CORRECTION must be a whole number from -1000 to 1000") from exc
if not -1000 <= PPM_CORRECTION <= 1000:
    raise ValueError("RTL_PPM_CORRECTION must be a whole number from -1000 to 1000")
FFT_SIZE = 4096
SCAN_STEP_FACTOR = 0.8
SETTLE_SECONDS = float(os.environ.get("RTL_SETTLE_MS", "30")) / 1000.0
if not math.isfinite(SETTLE_SECONDS) or not 0.01 <= SETTLE_SECONDS <= 2.0:
    raise ValueError("RTL_SETTLE_MS must be between 10 and 2000")
try:
    FLUSH_MS = int(os.environ.get("RTL_FLUSH_MS", "200"))
except ValueError as exc:
    raise ValueError("RTL_FLUSH_MS must be an integer from 0 to 5000") from exc
if not 0 <= FLUSH_MS <= 5000:
    raise ValueError("RTL_FLUSH_MS must be an integer from 0 to 5000")
CAPTURE_DIAGNOSTICS = os.environ.get("RTL_CAPTURE_DIAGNOSTICS", "0") == "1"
MIN_FREQUENCY_HZ = 24_000_000
MAX_FREQUENCY_HZ = 1_766_000_000
FLOOR_DBFS = -120.0
SUPPORTED_RBWS = (50_000, 100_000, 350_000, 900_000)
TUNER_NAMES = {
    1: "E4000", 2: "FC0012", 3: "FC0013", 4: "FC2580", 5: "R820T", 6: "R828D"
}


def _fft(values):
    """In-place radix-2 FFT. Input length must be a power of two."""
    n = len(values)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            values[i], values[j] = values[j], values[i]
    size = 2
    while size <= n:
        half = size >> 1
        angle = -2.0 * math.pi / size
        step = complex(math.cos(angle), math.sin(angle))
        for base in range(0, n, size):
            twiddle = 1.0 + 0.0j
            for offset in range(half):
                even = values[base + offset]
                odd = values[base + offset + half] * twiddle
                values[base + offset] = even + odd
                values[base + offset + half] = even - odd
                twiddle *= step
        size <<= 1
    return values


def scan_segments(start_hz, stop_hz, sample_rate):
    """Partition the band into non-overlapping usable FFT windows within tuner limits."""
    usable_span = sample_rate * SCAN_STEP_FACTOR
    left = start_hz
    while left < stop_hz:
        center = int(round(min(MAX_FREQUENCY_HZ, max(MIN_FREQUENCY_HZ, left + usable_span / 2))))
        right = min(stop_hz, center + usable_span / 2)
        yield center, left, right
        left = right


CALIBRATION_FFT_SIZE = 16384


def fm_offset_hz(raw, sample_rate, expected_offset):
    """Channel-filter IQ and average the FM discriminator, not a modulated FFT peak."""
    n = len(raw) // 2
    if n != CALIBRATION_FFT_SIZE:
        raise ValueError("incomplete calibration frame")
    if sum(value <= 1 or value >= 254 for value in raw) / len(raw) > 0.005:
        raise ValueError("IQ clipping; reduce gain or choose a weaker station")
    mean_i, mean_q = statistics.mean(raw[0::2]), statistics.mean(raw[1::2])
    bins = _fft([complex(raw[2*i] - mean_i, raw[2*i+1] - mean_q) for i in range(n)])
    signal, noise = [], []
    for i, value in enumerate(bins):
        frequency = (i if i < n // 2 else i - n) * sample_rate / n
        distance = abs(frequency - expected_offset)
        power = value.real ** 2 + value.imag ** 2
        if distance < 125000:
            signal.append(power)
        elif 160000 < distance < 220000:
            noise.append(power)
        # FFT bandpass, with a raised-cosine transition to reduce ringing.
        weight = 1.0 if distance <= 110000 else (
            0.5 + 0.5 * math.cos(math.pi * (distance - 110000) / 20000)
            if distance < 130000 else 0.0)
        bins[i] = value.conjugate() * weight
    snr = 10 * math.log10(max(statistics.mean(signal), 1e-12) / max(statistics.mean(noise), 1e-12))
    if snr < 8:
        raise ValueError("Station too weak or adjacent-channel interference")
    filtered = _fft(bins)  # conjugate FFT implements inverse; scale cancels below.
    phases = []
    for i in range(n // 4 + 1, 3 * n // 4):
        product = filtered[i].conjugate() * filtered[i-1]
        phases.append(math.atan2(product.imag, product.real))
    return statistics.mean(phases) * sample_rate / (2 * math.pi) - expected_offset, snr


def summarize_fm_calibration(buckets, reference_hz, base_ppm):
    """Use one-second blocks and two LO positions to bound an approximate FM estimate."""
    groups = [[statistics.mean(values) for (side, _), values in buckets.items() if side == index]
              for index in (0, 1)]
    if any(len(group) < 4 for group in groups):
        raise ValueError("Not enough clean FM samples; try a stronger station")
    values = groups[0] + groups[1]
    residual = statistics.mean(values)
    statistical_hz = 2 * statistics.stdev(values) / math.sqrt(len(values))
    offset_disagreement = abs(statistics.mean(groups[0]) - statistics.mean(groups[1])) / 2
    uncertainty_hz = max(statistical_hz, offset_disagreement, reference_hz / 1e6)
    # Positive rtl_tcp correction moves a station higher on the displayed frequency axis.
    suggested = round(base_ppm - residual / reference_hz * 1e6)
    uncertainty_ppm = uncertainty_hz / reference_hz * 1e6
    can_apply = uncertainty_ppm <= 5 and abs(residual) <= 40000 and -1000 <= suggested <= 1000
    return {"residualHz": round(residual, 1), "uncertaintyPpm": round(uncertainty_ppm, 2),
            "suggestedPpm": suggested, "canApply": can_apply,
            "message": "FM estimate: verify with another station before relying on it." if can_apply else
                       "Unstable or out-of-range estimate; use a longer measurement or another station."}


class Bridge:
    def __init__(self):
        self.lock = threading.RLock()
        self.sweeping = False
        try:
            self.repeat = int(os.environ.get("RTL_REPEAT", "255"))
        except ValueError:
            self.repeat = 255
        if self.repeat not in (1, 255):
            self.repeat = 255
        self.trace_mode = "clear-write"
        self.vbw_hz = None
        self.settle_ms = SETTLE_SECONDS * 1000.0
        self.flush_ms = FLUSH_MS
        self.ref_level_dbfs = 0.0
        self.start_hz = int(os.environ.get("RTL_START_HZ", "470000000"))
        self.stop_hz = int(os.environ.get("RTL_STOP_HZ", "524000000"))
        self.rbw_hz = int(os.environ.get("RTL_RBW_HZ", "350000"))
        self.ppm_correction = PPM_CORRECTION
        self.tuner_agc = TUNER_AGC
        self.digital_agc = DIGITAL_AGC
        if self.rbw_hz not in SUPPORTED_RBWS:
            self.rbw_hz = 350_000
        self.trace = None
        self.sweep_id = 0
        self.sweep_count = 0
        self.pass_id = 0
        self.pending_updates = []
        self.revision = 0
        self.max_hold = None
        self.min_hold = None
        self.avg_sum = None
        self.avg_count = 0
        self.server = None
        self.http_thread = None
        self.scanner = None
        self.progress = None
        self.calibration = {"status": "idle"}

    def calibration_status(self):
        with self.lock:
            return dict(self.calibration)

    def calibration_active(self, revision):
        with self.lock:
            return (self.revision == revision and
                    self.calibration["status"] in ("queued", "measuring"))

    def calibration_start(self, body):
        method = body.get("method", "fm")
        if method not in ("fm", "gsm"):
            raise ValueError("Calibration method must be fm or gsm")
        frequency = body.get("referenceHz")
        duration = body.get("durationSeconds", 20)
        if method == "fm" and (isinstance(frequency, bool) or not isinstance(frequency, (int, float)) or not 87_500_000 <= frequency <= 108_000_000):
            raise ValueError("Reference frequency must be between 87.5 and 108 MHz")
        if isinstance(duration, bool) or duration not in (20, 40, 60):
            raise ValueError("Measurement duration must be 20, 40 or 60 seconds")
        with self.lock:
            if self.sweeping or self.calibration["status"] in ("queued", "measuring"):
                raise ValueError("Stop scanning or cancel the current calibration first")
            if self.tuner_agc or self.digital_agc:
                raise ValueError("Turn both AGCs off before calibration")
            if self.scanner and self.scanner.sample_rate < 1_000_000:
                raise ValueError("FM calibration requires a sample rate of at least 1 MS/s")
            self.revision += 1
            self.calibration = {"status": "queued", "revision": self.revision, "method": method,
                                "referenceHz": round(frequency) if method == "fm" else None, "durationSeconds": duration,
                                "basePpm": self.ppm_correction, "progress": 0}
            return dict(self.calibration)

    def calibration_cancel(self):
        with self.lock:
            if self.calibration["status"] in ("queued", "measuring"):
                self.revision += 1
                self.calibration = dict(self.calibration, status="cancelled", canApply=False)
            return dict(self.calibration)

    def config_snapshot(self):
        with self.lock:
            return {
                "startHz": self.start_hz,
                "stopHz": self.stop_hz,
                "rbwHz": self.rbw_hz,
                "revision": self.revision,
            }

    def info(self):
        tuner_type = getattr(self.scanner, "tuner_type", None)
        tuner = TUNER_NAMES.get(tuner_type, "RTL-SDR")
        return {
            "name": "RTL-SDR over rtl_tcp",
            "manufacturer": "RTL-SDR",
            "model": tuner,
            "firmware": "rtl_tcp",
            "protocolVersion": "1.0.0",
            "capabilities": {
                "minFrequencyHz": MIN_FREQUENCY_HZ,
                "maxFrequencyHz": MAX_FREQUENCY_HZ,
                "rbwHz": list(SUPPORTED_RBWS),
                "vbwHz": list(SUPPORTED_RBWS),
                "minRefLevelDbfs": -120,
                "maxRefLevelDbfs": 0,
                "minStepHz": min(SUPPORTED_RBWS),
                "maxStepHz": max(SUPPORTED_RBWS),
                "pointCount": self.configuration()["pointCount"],
                "startHz": self.start_hz,
                "stopHz": self.stop_hz,
                "traceModes": ["clear-write", "max-hold", "min-hold", "average"],
            },
        }

    def configuration(self):
        with self.lock:
            count = max(1, (self.stop_hz - self.start_hz) // self.rbw_hz + 1)
            return {
                "startHz": self.start_hz,
                "stopHz": self.stop_hz,
                "centerHz": (self.start_hz + self.stop_hz) // 2,
                "spanHz": self.stop_hz - self.start_hz,
                "rbwHz": self.rbw_hz,
                "stepHz": self.rbw_hz,
                "vbwHz": self.vbw_hz or self.rbw_hz,
                "refLevelDbfs": self.ref_level_dbfs,
                "traceMode": self.trace_mode,
                "pointCount": count,
                "sweeping": self.sweeping,
                "curveMask": 2,
                "repeat": self.repeat,
                "settleMs": self.settle_ms,
                "flushMs": self.flush_ms,
                "ppmCorrection": self.ppm_correction,
                "tunerAgc": self.tuner_agc,
                "digitalAgc": self.digital_agc,
                "antennaBias": {"A": False},
                "antennaNames": {"A": "RTL-SDR"},
                "unit": "dBFS",
            }

    def apply_configuration(self, body):
        changed = False
        with self.lock:
            receiver_settings = {}
            flush_ms = body.get("flushMs")
            if flush_ms is not None:
                if isinstance(flush_ms, bool) or not isinstance(flush_ms, int) or not 0 <= flush_ms <= 5000:
                    raise ValueError("flushMs must be an integer from 0 to 5000")
            for setting in ("tunerAgc", "digitalAgc"):
                if setting in body:
                    if not isinstance(body[setting], bool):
                        raise ValueError("%s must be true or false" % setting)
                    receiver_settings["tuner_agc" if setting == "tunerAgc" else "digital_agc"] = body[setting]

            ppm_correction = body.get("ppmCorrection")
            if ppm_correction is not None:
                if isinstance(ppm_correction, bool):
                    raise ValueError("ppmCorrection must be a whole number from -1000 to 1000")
                try:
                    numeric_ppm = float(ppm_correction)
                except (TypeError, ValueError):
                    raise ValueError("ppmCorrection must be a whole number from -1000 to 1000")
                if not math.isfinite(numeric_ppm) or not numeric_ppm.is_integer() or not -1000 <= numeric_ppm <= 1000:
                    raise ValueError("ppmCorrection must be a whole number from -1000 to 1000")
                receiver_settings["ppm_correction"] = int(numeric_ppm)

            settle_ms = body.get("settleMs")
            if settle_ms is not None:
                try:
                    settle_ms = float(settle_ms)
                except (TypeError, ValueError):
                    raise ValueError("settleMs must be an integer from 10 to 2000")
                if not math.isfinite(settle_ms) or not settle_ms.is_integer() or not 10 <= settle_ms <= 2000:
                    raise ValueError("settleMs must be an integer from 10 to 2000")
                self.settle_ms = int(settle_ms)
                if self.scanner:
                    self.scanner.settle_seconds = settle_ms / 1000.0

            start_hz = body.get("startHz")
            stop_hz = body.get("stopHz")
            if start_hz is None and body.get("centerHz") is not None and body.get("spanHz") is not None:
                start_hz = float(body["centerHz"]) - float(body["spanHz"]) / 2.0
                stop_hz = float(body["centerHz"]) + float(body["spanHz"]) / 2.0
            if start_hz is not None and stop_hz is not None:
                start_hz, stop_hz = int(float(start_hz)), int(float(stop_hz))
                if stop_hz <= start_hz:
                    raise ValueError("stopHz must be greater than startHz")
                if start_hz < MIN_FREQUENCY_HZ or stop_hz > MAX_FREQUENCY_HZ:
                    raise ValueError("RTL-SDR range must be within 24 MHz to 1766 MHz")
                if (start_hz, stop_hz) != (self.start_hz, self.stop_hz):
                    self.start_hz, self.stop_hz = start_hz, stop_hz
                    changed = True
            rbw = body.get("rbwHz") or body.get("stepHz")
            if rbw is not None:
                rbw = int(float(rbw))
                if rbw not in SUPPORTED_RBWS:
                    raise ValueError("rbwHz must be one of %s" % ", ".join(map(str, SUPPORTED_RBWS)))
                if rbw != self.rbw_hz:
                    self.rbw_hz = rbw
                    changed = True
            mode = body.get("traceMode")
            if mode in ("clear-write", "max-hold", "min-hold", "average") and mode != self.trace_mode:
                self.trace_mode = mode
                self._reset_accum()
            if body.get("vbwHz") is not None:
                try:
                    self.vbw_hz = float(body["vbwHz"]) or None
                except (TypeError, ValueError):
                    pass
            ref_level = body.get("refLevelDbfs", body.get("refLevelDbm"))
            if ref_level is not None:
                try:
                    self.ref_level_dbfs = float(ref_level)
                except (TypeError, ValueError):
                    pass
            if "repeat" in body:
                try:
                    repeat = int(body["repeat"])
                    if repeat in (1, 255):
                        self.repeat = repeat
                except (TypeError, ValueError):
                    pass
            for setting, value in receiver_settings.items():
                if getattr(self, setting) != value:
                    setattr(self, setting, value)
                    changed = True
            if flush_ms is not None and flush_ms != self.flush_ms:
                self.flush_ms = flush_ms
                if self.scanner:
                    self.scanner.flush_seconds = flush_ms / 1000.0
                changed = True
            if changed:
                if self.calibration["status"] != "idle":
                    self.calibration = dict(self.calibration, status="cancelled", canApply=False)
                self.revision += 1
                self.trace = None
                self.progress = None
                self.pending_updates = []
                self._reset_accum()
        return self.configuration()

    def _reset_accum(self):
        self.max_hold = None
        self.min_hold = None
        self.avg_sum = None
        self.avg_count = 0

    def sweep_start(self):
        with self.lock:
            self.calibration_cancel()
            self.revision += 1
            self.sweeping = True
            self.trace = None
            self.progress = None
            self.sweep_count = 0
            self.pending_updates = []
            self._reset_accum()
        return {"sweeping": True, "sweepId": self.sweep_id}

    def sweep_stop(self):
        with self.lock:
            self.calibration_cancel()
            self.revision += 1
            self.sweeping = False
            self.progress = None
        return {"sweeping": False, "sweepId": self.sweep_id}

    def is_sweeping(self):
        with self.lock:
            return self.sweeping

    def begin_pass(self, config):
        with self.lock:
            if config["revision"] != self.revision or not self.sweeping:
                return None
            self.pass_id += 1
            return self.pass_id

    def publish(self, values, config, expected_revision, pass_id=None):
        with self.lock:
            if expected_revision != self.revision or not self.sweeping:
                return False
            if self.repeat == 1:
                self.sweeping = False
            self.sweep_count += 1
            self.sweep_id += 1
            mode = self.trace_mode
            if mode == "max-hold":
                if self.max_hold is None or len(self.max_hold) != len(values):
                    self.max_hold = values[:]
                else:
                    self.max_hold = [max(a, b) for a, b in zip(self.max_hold, values)]
                output = self.max_hold[:]
            elif mode == "min-hold":
                if self.min_hold is None or len(self.min_hold) != len(values):
                    self.min_hold = values[:]
                else:
                    self.min_hold = [min(a, b) for a, b in zip(self.min_hold, values)]
                output = self.min_hold[:]
            elif mode == "average":
                if self.avg_sum is None or len(self.avg_sum) != len(values):
                    self.avg_sum = values[:]
                    self.avg_count = 1
                else:
                    self.avg_sum = [a + b for a, b in zip(self.avg_sum, values)]
                    self.avg_count += 1
                output = [value / self.avg_count for value in self.avg_sum]
            else:
                output = values[:]
            output = self._smooth(output)
            self.trace = {
                "startHz": config["startHz"],
                "stopHz": config["stopHz"],
                "stepHz": config["rbwHz"],
                "pointCount": len(values),
                "sweepId": self.sweep_id,
                "passId": pass_id if pass_id is not None else self.pass_id,
                "sweepCount": self.sweep_count,
                "coverageComplete": True,
                "coveragePct": 100,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
                "unit": "dBFS",
                "amplitudesDbfs": [round(max(FLOOR_DBFS, min(10.0, v)) * 10) / 10 for v in output],
                "series": [{
                    "name": "A",
                    "amplitudesDbfs": [round(max(FLOOR_DBFS, min(10.0, v)) * 10) / 10 for v in output],
                    "coverage": [True] * len(values),
                }],
                "sweeping": self.sweeping,
                "antennaBias": {"A": False},
                "antennaNames": {"A": "RTL-SDR"},
            }
            return True

    def publish_partial(self, values, coverage, config, expected_revision,
                        frequencies_hz, native_values, pass_id):
        """Expose the current output grid and native FFT bins during an in-progress sweep."""
        with self.lock:
            if expected_revision != self.revision or not self.sweeping:
                return False
            captured = sum(1 for covered in coverage if covered)
            amplitudes = [round(max(FLOOR_DBFS, min(10.0, value)) * 10) / 10 for value in values]
            self.sweep_id += 1
            update = {
                "sweepId": self.sweep_id,
                "passId": pass_id,
                "startHz": config["startHz"],
                "stopHz": config["stopHz"],
                "binHz": getattr(self.scanner, "bin_hz", 0),
                "frequenciesHz": frequencies_hz,
                "amplitudesDbfs": [round(max(FLOOR_DBFS, min(10.0, value)) * 10) / 10 for value in native_values],
            }
            self.pending_updates.append(update)
            self.trace = {
                "startHz": config["startHz"],
                "stopHz": config["stopHz"],
                "stepHz": config["rbwHz"],
                "pointCount": len(values),
                "sweepId": self.sweep_id,
                "passId": pass_id,
                "sweepCount": self.sweep_count,
                "coverageComplete": captured == len(coverage),
                "coveragePct": round(100.0 * captured / max(1, len(coverage)), 1),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
                "unit": "dBFS",
                "amplitudesDbfs": amplitudes,
                "series": [{
                    "name": "A",
                    "amplitudesDbfs": amplitudes,
                    "coverage": coverage[:],
                }],
                "sweeping": True,
                "antennaBias": {"A": False},
                "antennaNames": {"A": "RTL-SDR"},
            }
            return True

    def _smooth(self, values):
        vbw = self.vbw_hz
        if not vbw or vbw >= self.rbw_hz or len(values) < 2:
            return values
        window = max(2, int(round(self.rbw_hz / vbw)))
        half = window // 2
        return [
            sum(values[max(0, i - half):min(len(values), i + half + 1)]) /
            len(values[max(0, i - half):min(len(values), i + half + 1)])
            for i in range(len(values))
        ]

    def set_progress(self, config, completed, total, center_hz, started):
        with self.lock:
            if self.sweeping and self.revision == config["revision"]:
                self.progress = {
                    "completedSegments": completed,
                    "totalSegments": total,
                    "percent": round(100.0 * completed / total, 1),
                    "centerHz": center_hz,
                    "elapsedSeconds": round(time.monotonic() - started, 1),
                }

    def get_trace(self, after_sweep_id=-1):
        with self.lock:
            # Progress is live even before the first completed sweep. Never expose an old
            # trace's captured 'sweeping' flag as the current controller state.
            result = dict(self.trace) if self.trace else {
                "startHz": self.start_hz, "stopHz": self.stop_hz,
                "stepHz": self.rbw_hz, "series": [],
                "sweepId": self.sweep_id, "sweepCount": self.sweep_count,
            }
            result["sweeping"] = self.sweeping
            result["calibration"] = dict(self.calibration)
            result["progress"] = dict(self.progress) if self.progress else None
            result["updates"] = [update for update in self.pending_updates if update["sweepId"] > after_sweep_id]
            self.pending_updates = [update for update in self.pending_updates if update["sweepId"] > after_sweep_id]
            return result

    def serve(self):
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _json(self, status, obj):
                payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _body(self):
                length = int(self.headers.get("Content-Length", "0"))
                return json.loads(self.rfile.read(length) or b"{}")

            def do_GET(self):
                route = self.path.split("?", 1)[0]
                if route == "/info":
                    return self._json(200, bridge.info())
                if route == "/configuration":
                    return self._json(200, bridge.configuration())
                if route == "/calibration":
                    return self._json(200, bridge.calibration_status())
                if route == "/bias":
                    return self._json(200, {"A": False})
                if route == "/sweep/start":
                    return self._json(200, bridge.sweep_start())
                if route == "/sweep/stop":
                    return self._json(200, bridge.sweep_stop())
                if route == "/trace":
                    query = parse_qs(self.path.partition("?")[2])
                    try:
                        after_sweep_id = int(query.get("after", ["-1"])[0])
                    except ValueError:
                        after_sweep_id = -1
                    trace = bridge.get_trace(after_sweep_id)
                    if trace is None:
                        return self._json(409, {"error": "no_trace"})
                    return self._json(200, trace)
                return self._json(404, {"error": "not_found"})

            def do_POST(self):
                route = self.path.split("?", 1)[0]
                try:
                    if route == "/calibration":
                        body = self._body()
                        if body.get("action") == "cancel":
                            return self._json(200, bridge.calibration_cancel())
                        if body.get("action") == "start":
                            return self._json(200, bridge.calibration_start(body))
                        raise ValueError("Unknown calibration action")
                    if route == "/configuration":
                        return self._json(200, bridge.apply_configuration(self._body()))
                    if route == "/sweep/start":
                        return self._json(200, bridge.sweep_start())
                    if route == "/sweep/stop":
                        return self._json(200, bridge.sweep_stop())
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    return self._json(400, {"error": str(exc)})
                return self._json(404, {"error": "not_found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", BRIDGE_PORT), Handler)
        self.server.daemon_threads = True
        self.http_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.http_thread.start()
        return self.server.server_address[1]

    def shutdown(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


class Scanner:
    def __init__(self, bridge, host=RTL_HOST, port=RTL_PORT, sample_rate=SAMPLE_RATE):
        self.bridge = bridge
        self.host = host
        self.port = port
        self.sample_rate = sample_rate
        self.bin_hz = sample_rate / FFT_SIZE
        self.window = [0.5 - 0.5 * math.cos(2.0 * math.pi * i / (FFT_SIZE - 1)) for i in range(FFT_SIZE)]
        self.window_energy = sum(value * value for value in self.window)
        self.running = True
        self.sock = None
        self.tuner_type = None
        self.thread = None
        self.reader_thread = None
        self.iq_condition = threading.Condition()
        self.iq_buffer = bytearray()
        self.iq_bytes = 0
        self.iq_keep_bytes = FFT_SIZE * 2
        self.reader_error = None
        self.settle_seconds = SETTLE_SECONDS
        self.flush_seconds = FLUSH_MS / 1000.0
        self.capture_timeout_seconds = 5.0
        self.last_pass_id = None
        self.applied_ppm_correction = None
        self.calibration_ppm_override = None
        self.applied_tuner_agc = None
        self.applied_digital_agc = None

    def start(self):
        self.thread = threading.Thread(target=self._run, name="rtl-tcp-scanner", daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        with self.iq_condition:
            self.iq_condition.notify_all()
        sock = self.sock
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _command(self, command, value):
        self.sock.sendall(struct.pack(">BI", command, value & 0xFFFFFFFF))

    def _connect(self):
        self.applied_ppm_correction = None
        self.applied_tuner_agc = None
        self.applied_digital_agc = None
        sock = socket.create_connection((self.host, self.port), timeout=5)
        sock.settimeout(0.25)
        self.sock = sock
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        banner = bytearray()
        while len(banner) < 12:
            piece = sock.recv(12 - len(banner))
            if not piece:
                raise ConnectionError("short rtl_tcp handshake")
            banner.extend(piece)
        if bytes(banner[:4]) != b"RTL0":
            raise ConnectionError("unexpected rtl_tcp handshake %r" % bytes(banner[:4]))
        self.tuner_type = struct.unpack(">I", banner[4:8])[0]
        gain_count = struct.unpack(">I", banner[8:12])[0]
        self._command(2, self.sample_rate)
        self._apply_pending_receiver_settings()
        label = TUNER_NAMES.get(self.tuner_type, "tuner-%d" % self.tuner_type)
        settings = self.bridge.configuration()
        tuner_gain = "AGC" if settings["tunerAgc"] else "%.1f dB" % TUNER_GAIN_DB
        print("[RTL TCP] CONNECTED %s:%d tuner=%s gain_steps=%d sample_rate=%d tuner_agc=%s tuner_gain=%s digital_agc=%s ppm=%d" % (
            self.host, self.port, label, gain_count, self.sample_rate,
            "on" if settings["tunerAgc"] else "off", tuner_gain,
            "on" if settings["digitalAgc"] else "off", settings["ppmCorrection"]), flush=True)

    def _apply_pending_receiver_settings(self):
        settings = self.bridge.configuration()
        if self.calibration_ppm_override is not None:
            settings["ppmCorrection"] = self.calibration_ppm_override
        if settings["tunerAgc"] != self.applied_tuner_agc:
            if self.applied_tuner_agc is not None:
                print("[RTL TCP] Tuner AGC %s" % ("enabled" if settings["tunerAgc"] else "disabled"), flush=True)
            self._command(3, 0 if settings["tunerAgc"] else 1)
            if not settings["tunerAgc"]:
                self._command(4, int(round(TUNER_GAIN_DB * 10)))
            self.applied_tuner_agc = settings["tunerAgc"]
        if settings["digitalAgc"] != self.applied_digital_agc:
            if self.applied_digital_agc is not None:
                print("[RTL TCP] Digital AGC %s" % ("enabled" if settings["digitalAgc"] else "disabled"), flush=True)
            self._command(8, 1 if settings["digitalAgc"] else 0)
            self.applied_digital_agc = settings["digitalAgc"]
        if settings["ppmCorrection"] != self.applied_ppm_correction:
            # rtl_tcp command 0x05 accepts the signed PPM value in its 32-bit parameter.
            self._command(5, settings["ppmCorrection"])
            self.applied_ppm_correction = settings["ppmCorrection"]

    def _read_iq(self, sock):
        """Drain rtl_tcp during both FFT computation and idle time; retain only fresh IQ."""
        pending = b""
        try:
            while self.running and self.sock is sock:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    raise ConnectionError("rtl_tcp closed the stream")
                data = pending + data
                even_length = len(data) & ~1
                pending = data[even_length:]
                with self.iq_condition:
                    self.iq_bytes += even_length
                    self.iq_buffer.extend(data[:even_length])
                    del self.iq_buffer[:-self.iq_keep_bytes]
                    self.iq_condition.notify_all()
        except OSError as exc:
            with self.iq_condition:
                self.reader_error = exc
                self.iq_condition.notify_all()

    def _capture(self, center_hz, config, calibration=False):
        self._apply_pending_receiver_settings()
        self._command(1, center_hz)
        commanded_at = time.monotonic()
        settled_at = commanded_at + self.settle_seconds
        # Bytes received after a command can still be queued pre-tune USB/TCP IQ.
        # Drain a sample budget after settling, then require a complete new frame.
        # This is a conservative guard, not a tune acknowledgement: rtl_tcp has none.
        flush_bytes = math.ceil(self.sample_rate * self.flush_seconds) * 2
        frame_bytes = FFT_SIZE * 2
        deadline = settled_at + self.flush_seconds + self.capture_timeout_seconds
        fresh_after = None
        with self.iq_condition:
            command_bytes = self.iq_bytes
            while self.running:
                active = self.bridge.calibration_active(config["revision"]) if calibration else self.bridge.is_sweeping()
                if not active or self.bridge.config_snapshot()["revision"] != config["revision"]:
                    return None
                if self.reader_error:
                    raise self.reader_error
                now = time.monotonic()
                if now >= settled_at and fresh_after is None:
                    fresh_after = self.iq_bytes
                if fresh_after is not None and self.iq_bytes - fresh_after >= flush_bytes + frame_bytes:
                    if CAPTURE_DIAGNOSTICS:
                        print("[RTL CAPTURE] " + json.dumps({
                            "centerHz": center_hz, "commandMonotonic": commanded_at,
                            "captureMonotonic": now, "elapsedMs": round((now - commanded_at) * 1000, 1),
                            "receivedBytes": self.iq_bytes - command_bytes,
                            "discardedBytes": self.iq_bytes - command_bytes - frame_bytes,
                            "flushBytes": flush_bytes, "passId": self.last_pass_id,
                            "revision": config["revision"],
                        }), flush=True)
                    return bytes(self.iq_buffer[-frame_bytes:])
                if now >= deadline:
                    raise TimeoutError("rtl_tcp stopped delivering IQ samples")
                self.iq_condition.wait(timeout=0.02)
        return None

    def _run(self):
        retry = 1.0
        while self.running:
            try:
                self._connect()
                with self.iq_condition:
                    self.iq_buffer.clear()
                    self.iq_bytes = 0
                    self.reader_error = None
                self.reader_thread = threading.Thread(target=self._read_iq, args=(self.sock,), daemon=True)
                self.reader_thread.start()
                retry = 1.0
                while self.running:
                    self._apply_pending_receiver_settings()
                    job = self.bridge.calibration_status()
                    if job["status"] == "queued":
                        self._calibrate(job)
                        continue
                    if not self.bridge.is_sweeping():
                        with self.iq_condition:
                            if self.reader_error:
                                raise self.reader_error
                            self.iq_condition.wait(timeout=0.1)
                        continue
                    config = self.bridge.config_snapshot()
                    values = self._scan(config)
                    if values is not None:
                        published = self.bridge.publish(values, config, config["revision"], self.last_pass_id)
                        if published and (self.bridge.sweep_count == 1 or self.bridge.sweep_count % 25 == 0):
                            print("[RTL TCP] SWEEP %d complete (%d points, %d MHz span, %d kHz bins)" % (
                                self.bridge.sweep_count,
                                len(values),
                                round((config["stopHz"] - config["startHz"]) / 1e6),
                                config["rbwHz"] // 1000), flush=True)
            except InterruptedError:
                pass
            except Exception as exc:
                with self.bridge.lock:
                    if self.bridge.calibration["status"] in ("queued", "measuring"):
                        self.bridge.calibration = dict(self.bridge.calibration, status="error", message=str(exc), canApply=False)
                if self.running:
                    print("[RTL TCP] DISCONNECTED %s" % exc, flush=True)
            finally:
                sock = self.sock
                self.sock = None
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                if self.reader_thread:
                    self.reader_thread.join(timeout=1.0)
                    self.reader_thread = None
            if self.running:
                print("[RTL TCP] CONNECTING %s:%d" % (self.host, self.port), flush=True)
                time.sleep(retry)
                retry = min(retry * 2.0, 10.0)

    def _calibrate(self, job):
        if job.get("method") == "gsm":
            return self._calibrate_gsm(job)
        revision = job["revision"]
        buckets, snrs = {}, []
        rejected, accepted = 0, 0
        self.iq_keep_bytes = CALIBRATION_FFT_SIZE * 2
        try:
            for side, offset in enumerate((-250000, 250000)):
                center = job["referenceHz"] + offset
                if self._capture(center, job, calibration=True) is None:
                    return
                started = time.monotonic()
                after = self.iq_bytes
                last_data = started
                while time.monotonic() - started < job["durationSeconds"] / 2:
                    if not self.running or not self.bridge.calibration_active(revision):
                        return
                    with self.iq_condition:
                        if self.reader_error:
                            raise self.reader_error
                        if self.iq_bytes - after < CALIBRATION_FFT_SIZE * 2:
                            if time.monotonic() - last_data > 5:
                                raise TimeoutError("No IQ received during calibration")
                            self.iq_condition.wait(timeout=0.02)
                            continue
                        raw = bytes(self.iq_buffer)
                        after = self.iq_bytes
                    last_data = time.monotonic()
                    try:
                        residual, snr = fm_offset_hz(raw, self.sample_rate, -offset)
                        bucket = (side, int(last_data - started))
                        buckets.setdefault(bucket, []).append(residual)
                        snrs.append(snr)
                        accepted += 1
                    except ValueError:
                        rejected += 1
                    with self.bridge.lock:
                        if self.bridge.calibration_active(revision):
                            progress = (side / 2 + min(0.5, (time.monotonic() - started) / job["durationSeconds"])) * 100
                            self.bridge.calibration.update(status="measuring", progress=round(progress),
                                                           acceptedFrames=accepted, rejectedFrames=rejected)
            if accepted < 40 or rejected > accepted / 3:
                raise ValueError("Too few clean samples: weak signal, interference or clipping. Try another station.")
            result = summarize_fm_calibration(buckets, job["referenceHz"], job["basePpm"])
            with self.bridge.lock:
                if self.bridge.calibration_active(revision):
                    self.bridge.calibration.update(result, status="ready", progress=100,
                                                   completedAtMs=round(time.time() * 1000),
                                                   snrDb=round(statistics.median(snrs), 1))
        except ValueError as exc:
            with self.bridge.lock:
                if self.bridge.calibration_active(revision):
                    self.bridge.calibration.update(status="error", message=str(exc), canApply=False)
        finally:
            self.iq_keep_bytes = FFT_SIZE * 2

    def _gsm_block(self, revision):
        """A whole contiguous block received after this call; never concatenate ring snapshots."""
        size = gsm.FRAME_SAMPLES * 2
        with self.iq_condition:
            after = self.iq_bytes
            deadline = time.monotonic() + self.capture_timeout_seconds
            while self.running and self.bridge.calibration_active(revision):
                if self.reader_error:
                    raise self.reader_error
                if self.iq_bytes - after >= size and len(self.iq_buffer) >= size:
                    return bytes(self.iq_buffer[-size:])
                if time.monotonic() >= deadline:
                    raise TimeoutError("No IQ received during GSM calibration")
                self.iq_condition.wait(timeout=0.02)
        return None

    def _calibrate_gsm(self, job):
        revision = job["revision"]
        original_rate = self.sample_rate
        original_flush = self.flush_seconds
        channels, powers = [], {}
        started = time.monotonic()

        def update(**values):
            with self.bridge.lock:
                if self.bridge.calibration_active(revision):
                    self.bridge.calibration.update(status="measuring", **values)

        try:
            # Rank all EGSM900 downlink channels using the existing wideband scanner.
            segments = list(scan_segments(925000000, 960000000, original_rate))
            for index, (center, left, right) in enumerate(segments):
                update(phase="survey", progress=round(20*index/len(segments)),
                       message="Finding GSM900 reference channels", currentHz=center)
                raw = self._capture(center, job, calibration=True)
                if raw is None:
                    return
                bins = _fft([complex(raw[2*i]-127.5, raw[2*i+1]-127.5)*self.window[i] for i in range(FFT_SIZE)])
                for arfcn, frequency in gsm.CHANNELS:
                    if left <= frequency < right:
                        indices = [i for i in range(FFT_SIZE) if abs(center +
                                   (i if i < FFT_SIZE//2 else i-FFT_SIZE)*original_rate/FFT_SIZE-frequency) < 75000]
                        if indices:
                            powers[arfcn] = sum(abs(bins[i])**2 for i in indices)/len(indices)
            ranked = sorted(gsm.CHANNELS, key=lambda item: powers.get(item[0], 0), reverse=True)
            self.sample_rate = gsm.SAMPLE_RATE
            self._command(2, self.sample_rate)
            self.iq_keep_bytes = gsm.FRAME_SAMPLES * 2
            self.flush_seconds = max(1.0, original_flush)
            for index, (arfcn, frequency) in enumerate(ranked):
                if time.monotonic()-started > 180:
                    break
                if len([c for c in channels if c["uncertaintyPpm"] <= 0.35]) >= 2 and (index >= 10 or time.monotonic()-started > 60):
                    break
                update(phase="fcch", progress=20+round(79*index/len(ranked)), currentHz=frequency,
                       testedChannels=index, channels=list(channels),
                       message="Measuring FCCH bursts on ARFCN %d (%.1f MHz)" % (arfcn, frequency/1e6))
                if self._capture(frequency, job, calibration=True) is None:
                    return
                self.flush_seconds = max(0.4, original_flush)
                offsets = []
                for attempt in range(50):
                    if time.monotonic()-started > 180:
                        break
                    raw = self._gsm_block(revision)
                    if raw is None:
                        return
                    offsets.extend(gsm.fcch_offsets(raw, _fft, self.sample_rate))
                    update(acceptedFrames=len(offsets))
                    if len(offsets) >= 40 or (attempt >= 2 and len(offsets) < 2):
                        break
                result = gsm.channel_summary(arfcn, frequency, offsets, job["basePpm"])
                if result:
                    channels.append(result)
                if len([c for c in channels if c["uncertaintyPpm"] <= 0.35]) >= 3:
                    break
            result = gsm.consensus(channels, job["basePpm"])
            if result["canApply"]:
                # Tuner PLL quantization can make rounding the calculated estimate
                # oscillate between adjacent integers. Compare the actual RF residual.
                references = [c for c in channels if c["uncertaintyPpm"] <= 0.35][:3]
                lower = math.floor(result["estimatedPpm"])
                candidates = [lower, lower+1]
                verified = []
                for candidate in candidates:
                    if not -1000 <= candidate <= 1000:
                        raise ValueError("GSM correction is outside the supported range")
                    self.calibration_ppm_override = candidate
                    measurements = []
                    for reference in references:
                        update(phase="verify", progress=90, verification=verified, currentHz=reference["referenceHz"],
                               message="Checking %d ppm on ARFCN %d; saved PPM is unchanged" % (candidate, reference["arfcn"]))
                        if self._capture(reference["referenceHz"], job, calibration=True) is None:
                            return
                        offsets = []
                        for attempt in range(24):
                            raw = self._gsm_block(revision)
                            if raw is None:
                                return
                            offsets.extend(gsm.fcch_offsets(raw, _fft, self.sample_rate))
                            if len(offsets) >= 12:
                                break
                        measured = gsm.channel_summary(reference["arfcn"], reference["referenceHz"], offsets, candidate, 12)
                        if measured is None:
                            raise ValueError("Lost GSM reference during PPM verification; try again")
                        measurements.append(measured)
                    verified.append({"ppm": candidate, "channels": measurements})
                best = gsm.verified_setting(verified)
                result.update(suggestedPpm=best["ppm"], verification=verified,
                              verifiedResidualPpm=best["rmsResidualPpm"],
                              message="Neighboring integer settings checked against GSM references. Apply saves the setting with the smallest measured residual.")
            with self.bridge.lock:
                if self.bridge.calibration_active(revision):
                    self.bridge.calibration.update(result, status="ready", progress=100,
                                                   elapsedSeconds=round(time.monotonic()-started, 2),
                                                   completedAtMs=round(time.time()*1000))
        except ValueError as exc:
            update(message=str(exc), channels=channels)
            with self.bridge.lock:
                if self.bridge.calibration_active(revision):
                    self.bridge.calibration.update(status="error", canApply=False)
        finally:
            self.calibration_ppm_override = None
            self.sample_rate = original_rate
            self.flush_seconds = original_flush
            self.iq_keep_bytes = FFT_SIZE * 2
            if self.running and self.sock:
                self._command(2, original_rate)
                self._apply_pending_receiver_settings()

    def _scan(self, config):
        start_hz, stop_hz, step_hz = config["startHz"], config["stopHz"], config["rbwHz"]
        pass_id = self.bridge.begin_pass(config)
        if pass_id is None:
            return None
        self.last_pass_id = pass_id
        count = max(1, (stop_hz - start_hz) // step_hz + 1)
        powers = [0.0] * count
        coverage = [False] * count
        segments = list(scan_segments(start_hz, stop_hz, self.sample_rate))
        started = time.monotonic()
        for segment_index, (center_hz, left, right) in enumerate(segments):
            if not self.running or not self.bridge.is_sweeping():
                return None
            if self.bridge.config_snapshot()["revision"] != config["revision"]:
                return None
            self.bridge.set_progress(config, segment_index, len(segments), center_hz, started)
            raw = self._capture(center_hz, config)
            if raw is None:
                return None
            bins = [0j] * FFT_SIZE
            mean_i = sum(raw[0::2]) / FFT_SIZE
            mean_q = sum(raw[1::2]) / FFT_SIZE
            for i in range(FFT_SIZE):
                iv = (raw[i * 2] - mean_i) / 127.5
                qv = (raw[i * 2 + 1] - mean_q) / 127.5
                bins[i] = complex(iv, qv) * self.window[i]
            _fft(bins)
            native_points = []
            for fft_index, sample in enumerate(bins):
                signed_index = fft_index if fft_index < FFT_SIZE // 2 else fft_index - FFT_SIZE
                frequency = center_hz + signed_index * self.bin_hz
                # Each FFT owns only its assigned interval; clamping the last center must not
                # double-count the overlapping part of the previous tuning window.
                if frequency < left or frequency > right or (frequency == right and right != stop_hz):
                    continue
                power = (sample.real * sample.real + sample.imag * sample.imag) / (FFT_SIZE * self.window_energy)
                native_points.append((frequency, power))
                point = int(round((frequency - start_hz) / step_hz))
                if 0 <= point < count:
                    # Parseval normalization makes the sum of FFT-bin power match the captured
                    # complex-sample power. Summing bins gives selected-bin power in dBFS.
                    powers[point] += power
                    coverage[point] = True
            self.bridge.set_progress(config, segment_index + 1, len(segments), center_hz, started)
            partial_values = [10.0 * math.log10(power) if power > 1e-12 else FLOOR_DBFS for power in powers]
            native_points.sort(key=lambda point: point[0])
            native_frequencies = [point[0] for point in native_points]
            native_values = [10.0 * math.log10(point[1]) if point[1] > 1e-12 else FLOOR_DBFS
                             for point in native_points]
            self.bridge.publish_partial(partial_values, coverage, config, config["revision"],
                                        native_frequencies, native_values, pass_id)

        return [10.0 * math.log10(power) if power > 1e-12 else FLOOR_DBFS for power in powers]


def main():
    bridge = Bridge()
    scanner = Scanner(bridge)
    bridge.scanner = scanner
    bridge.serve()
    print("[RTL TCP] BRIDGE listening on 127.0.0.1:%d" % BRIDGE_PORT, flush=True)

    if os.environ.get("RTL_START_SWEEP", "0") == "1":
        bridge.sweep_start()
    scanner.start()

    stopped = threading.Event()

    def shutdown(*_args):
        stopped.set()
        scanner.stop()
        bridge.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        while not stopped.wait(1.0):
            pass
    finally:
        scanner.stop()
        bridge.shutdown()


if __name__ == "__main__":
    main()
