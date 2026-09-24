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
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


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
FFT_SIZE = 4096
SCAN_STEP_FACTOR = 0.8
SETTLE_SECONDS = float(os.environ.get("RTL_SETTLE_MS", "100")) / 1000.0
if not math.isfinite(SETTLE_SECONDS) or not 0.01 <= SETTLE_SECONDS <= 2.0:
    raise ValueError("RTL_SETTLE_MS must be between 10 and 2000")
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
        self.ref_level_dbfs = 0.0
        self.start_hz = int(os.environ.get("RTL_START_HZ", "470000000"))
        self.stop_hz = int(os.environ.get("RTL_STOP_HZ", "524000000"))
        self.rbw_hz = int(os.environ.get("RTL_RBW_HZ", "350000"))
        if self.rbw_hz not in SUPPORTED_RBWS:
            self.rbw_hz = 350_000
        self.trace = None
        self.sweep_id = 0
        self.sweep_count = 0
        self.revision = 0
        self.max_hold = None
        self.min_hold = None
        self.avg_sum = None
        self.avg_count = 0
        self.server = None
        self.http_thread = None
        self.scanner = None
        self.progress = None

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
                "antennaBias": {"A": False},
                "antennaNames": {"A": "RTL-SDR"},
                "unit": "dBFS",
            }

    def apply_configuration(self, body):
        changed = False
        with self.lock:
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
            if changed:
                self.revision += 1
                self.trace = None
                self.progress = None
                self._reset_accum()
        return self.configuration()

    def _reset_accum(self):
        self.max_hold = None
        self.min_hold = None
        self.avg_sum = None
        self.avg_count = 0

    def sweep_start(self):
        with self.lock:
            self.revision += 1
            self.sweeping = True
            self.trace = None
            self.progress = None
            self.sweep_count = 0
            self._reset_accum()
        return {"sweeping": True, "sweepId": self.sweep_id}

    def sweep_stop(self):
        with self.lock:
            self.revision += 1
            self.sweeping = False
            self.progress = None
        return {"sweeping": False, "sweepId": self.sweep_id}

    def is_sweeping(self):
        with self.lock:
            return self.sweeping

    def publish(self, values, config, expected_revision):
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
                "sweepCount": self.sweep_count,
                "coverageComplete": True,
                "coveragePct": 100,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
                "unit": "dBFS",
                "amplitudesDbfs": [round(max(FLOOR_DBFS, min(10.0, v)) * 10) / 10 for v in output],
                "series": [{
                    "name": "A",
                    "amplitudesDbfs": [round(max(FLOOR_DBFS, min(10.0, v)) * 10) / 10 for v in output],
                }],
                "sweeping": self.sweeping,
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

    def get_trace(self):
        with self.lock:
            # Progress is live even before the first completed sweep. Never expose an old
            # trace's captured 'sweeping' flag as the current controller state.
            result = dict(self.trace) if self.trace else {
                "startHz": self.start_hz, "stopHz": self.stop_hz,
                "stepHz": self.rbw_hz, "series": [],
                "sweepId": self.sweep_id, "sweepCount": self.sweep_count,
            }
            result["sweeping"] = self.sweeping
            result["progress"] = dict(self.progress) if self.progress else None
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
                if route == "/bias":
                    return self._json(200, {"A": False})
                if route == "/sweep/start":
                    return self._json(200, bridge.sweep_start())
                if route == "/sweep/stop":
                    return self._json(200, bridge.sweep_stop())
                if route == "/trace":
                    trace = bridge.get_trace()
                    if trace is None:
                        return self._json(409, {"error": "no_trace"})
                    return self._json(200, trace)
                return self._json(404, {"error": "not_found"})

            def do_POST(self):
                route = self.path.split("?", 1)[0]
                try:
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
        self.reader_error = None
        self.settle_seconds = SETTLE_SECONDS

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
        sock = socket.create_connection((self.host, self.port), timeout=5)
        sock.settimeout(0.25)
        self.sock = sock
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
        self._command(3, 0 if TUNER_AGC else 1)
        self._command(4, int(round(TUNER_GAIN_DB * 10)))
        self._command(8, 1 if DIGITAL_AGC else 0)
        label = TUNER_NAMES.get(self.tuner_type, "tuner-%d" % self.tuner_type)
        print("[RTL TCP] CONNECTED %s:%d tuner=%s gain_steps=%d sample_rate=%d tuner_agc=%s tuner_gain=%.1f dB digital_agc=%s" % (
            self.host, self.port, label, gain_count, self.sample_rate,
            "on" if TUNER_AGC else "off", TUNER_GAIN_DB,
            "on" if DIGITAL_AGC else "off"), flush=True)

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
                    del self.iq_buffer[:-FFT_SIZE * 2]
                    self.iq_condition.notify_all()
        except OSError as exc:
            with self.iq_condition:
                self.reader_error = exc
                self.iq_condition.notify_all()

    def _capture(self, center_hz, config):
        self._command(1, center_hz)
        settled_at = time.monotonic() + self.settle_seconds
        deadline = settled_at + 5.0
        fresh_after = None
        with self.iq_condition:
            while self.running:
                if not self.bridge.is_sweeping() or self.bridge.config_snapshot()["revision"] != config["revision"]:
                    return None
                if self.reader_error:
                    raise self.reader_error
                now = time.monotonic()
                if now >= settled_at and fresh_after is None:
                    # Require a full new FFT frame after settling, not bytes left from the
                    # previous center. rtl_tcp has no tune acknowledgement or IQ timestamps.
                    fresh_after = self.iq_bytes
                if fresh_after is not None and self.iq_bytes - fresh_after >= FFT_SIZE * 2:
                    return bytes(self.iq_buffer)
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
                    if not self.bridge.is_sweeping():
                        with self.iq_condition:
                            if self.reader_error:
                                raise self.reader_error
                            self.iq_condition.wait(timeout=0.1)
                        continue
                    config = self.bridge.config_snapshot()
                    values = self._scan(config)
                    if values is not None:
                        published = self.bridge.publish(values, config, config["revision"])
                        if published and (self.bridge.sweep_count == 1 or self.bridge.sweep_count % 25 == 0):
                            print("[RTL TCP] SWEEP %d complete (%d points, %d MHz span, %d kHz bins)" % (
                                self.bridge.sweep_count,
                                len(values),
                                round((config["stopHz"] - config["startHz"]) / 1e6),
                                config["rbwHz"] // 1000), flush=True)
            except InterruptedError:
                pass
            except Exception as exc:
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

    def _scan(self, config):
        start_hz, stop_hz, step_hz = config["startHz"], config["stopHz"], config["rbwHz"]
        count = max(1, (stop_hz - start_hz) // step_hz + 1)
        powers = [0.0] * count
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
            for fft_index, sample in enumerate(bins):
                signed_index = fft_index if fft_index < FFT_SIZE // 2 else fft_index - FFT_SIZE
                frequency = center_hz + signed_index * self.bin_hz
                # Each FFT owns only its assigned interval; clamping the last center must not
                # double-count the overlapping part of the previous tuning window.
                if frequency < left or frequency > right or (frequency == right and right != stop_hz):
                    continue
                point = int(round((frequency - start_hz) / step_hz))
                if 0 <= point < count:
                    # Parseval normalization makes the sum of FFT-bin power match the captured
                    # complex-sample power. Summing bins gives selected-bin power in dBFS.
                    powers[point] += (sample.real * sample.real + sample.imag * sample.imag) / (FFT_SIZE * self.window_energy)
            self.bridge.set_progress(config, segment_index + 1, len(segments), center_hz, started)

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
