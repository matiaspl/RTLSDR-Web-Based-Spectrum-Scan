"""Band coverage and sweep lifecycle checks using synthetic IQ, without RF hardware."""
import importlib.util
import math
import socket
import struct
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("rtl_backend", Path(__file__).parents[1] / "engine/rtl_tcp_backend.py")
rtl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rtl)


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("Timed out waiting for simulated receiver")


def tone_iq(center, tone, sample_rate):
    if abs(tone - center) >= sample_rate * 0.4:
        return bytes([128, 128]) * rtl.FFT_SIZE
    result = bytearray()
    for i in range(rtl.FFT_SIZE):
        phase = 2 * math.pi * (tone - center) * i / sample_rate
        result.extend((round(127.5 + 38 * math.cos(phase)), round(127.5 + 38 * math.sin(phase))))
    return bytes(result)


class FakeRtlTcp:
    """Continuous paced IQ stream with real rtl_tcp command framing."""
    def __init__(self, tone=471_000_000, tune_delay=0, queued_seconds=0):
        self.tone = tone
        self.center = 470_000_000
        self.rate = 1_800_000
        self.tunes = []
        self.tune_delay = tune_delay
        self.queued_seconds = queued_seconds
        self.pending_tunes = []
        self.done = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.conn = None
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        try:
            self.conn, _ = self.listener.accept()
            self.conn.settimeout(0.2)
            self.conn.sendall(b'RTL0' + struct.pack('>II', 5, 29))
            producer = threading.Thread(target=self.stream, daemon=True)
            producer.start()
            pending = bytearray()
            while not self.done.is_set():
                try:
                    data = self.conn.recv(1024)
                except socket.timeout:
                    continue
                if not data:
                    break
                pending.extend(data)
                while len(pending) >= 5:
                    command, value = struct.unpack('>BI', pending[:5])
                    del pending[:5]
                    if command == 1:
                        self.pending_tunes.append((time.monotonic() + self.tune_delay + self.queued_seconds, value))
                        self.tunes.append(value)
                    elif command == 2:
                        self.rate = value
        except OSError:
            pass

    def stream(self):
        cache = {}
        while not self.done.is_set():
            while self.pending_tunes and self.pending_tunes[0][0] <= time.monotonic():
                _, self.center = self.pending_tunes.pop(0)
            key = (self.center, self.rate)
            if key not in cache:
                cache[key] = tone_iq(key[0], self.tone, key[1])
            # USB-sized bursts, split at an odd TCP boundary, retain pre-tune IQ
            # for the configured command delay plus simulated server queue age.
            copies = 8 if self.queued_seconds else 1
            block = cache[key] * copies
            try:
                self.conn.sendall(block[:1001])
                self.conn.sendall(block[1001:])
            except OSError:
                break
            self.done.wait(copies * rtl.FFT_SIZE / self.rate)

    def close(self):
        self.done.set()
        if self.conn:
            self.conn.close()
        self.listener.close()
        self.worker.join(timeout=1)


class SweepTests(unittest.TestCase):
    def test_capture_discards_delayed_pre_tune_bursts(self):
        fake = FakeRtlTcp(tone=472_000_000, tune_delay=0.06, queued_seconds=0.12)
        bridge = self.bridge()
        scanner = rtl.Scanner(bridge, host='127.0.0.1', port=fake.port)
        scanner.settle_seconds = 0.02
        scanner.flush_seconds = 0.25
        reader = None
        try:
            scanner._connect()
            self.assertNotEqual(scanner.sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 0)
            reader = threading.Thread(target=scanner._read_iq, args=(scanner.sock,), daemon=True)
            reader.start()
            for center in (471_500_000, 472_500_000, 471_500_000):
                raw = scanner._capture(center, bridge.config_snapshot())
                bins = rtl._fft([complex(raw[i] - 127.5, raw[i + 1] - 127.5)
                                 for i in range(0, len(raw), 2)])
                peak = max(range(len(bins)), key=lambda i: abs(bins[i]))
                signed_peak = peak if peak < rtl.FFT_SIZE // 2 else peak - rtl.FFT_SIZE
                self.assertLessEqual(abs(center + signed_peak * scanner.bin_hz - fake.tone), scanner.bin_hz)
        finally:
            scanner.stop()
            fake.close()
            if reader:
                reader.join(timeout=1)

    def test_receiver_setting_changes_invalidate_pass_but_noops_do_not(self):
        for setting, value in [('ppmCorrection', 66), ('tunerAgc', True), ('digitalAgc', True)]:
            with self.subTest(setting=setting):
                bridge = self.bridge()
                bridge.apply_configuration({'ppmCorrection': 0, 'tunerAgc': False, 'digitalAgc': False})
                old = bridge.config_snapshot()
                pass_id = bridge.begin_pass(old)
                bridge.publish_partial([-30], [True], old, old['revision'], [470e6], [-30], pass_id)
                bridge.apply_configuration({setting: value})
                self.assertGreater(bridge.revision, old['revision'])
                self.assertEqual(bridge.pending_updates, [])
                self.assertFalse(bridge.publish([-30], old, old['revision']))
                revision = bridge.revision
                bridge.apply_configuration({setting: value})
                self.assertEqual(bridge.revision, revision)

    def test_capture_cancels_promptly_during_flush(self):
        for action in ('stop', 'range', 'ppm', 'agc', 'shutdown'):
            with self.subTest(action=action):
                bridge = self.bridge()
                scanner = rtl.Scanner(bridge)
                scanner._apply_pending_receiver_settings = lambda: None
                scanner._command = lambda *args: None
                scanner.settle_seconds = 0
                scanner.flush_seconds = 5
                result = []
                config = bridge.config_snapshot()
                worker = threading.Thread(target=lambda: result.append(scanner._capture(471_000_000, config)))
                worker.start()
                time.sleep(0.03)
                if action == 'stop':
                    bridge.sweep_stop()
                elif action == 'range':
                    bridge.apply_configuration({'startHz': 480_000_000, 'stopHz': 483_000_000})
                elif action == 'ppm':
                    bridge.apply_configuration({'ppmCorrection': bridge.ppm_correction + 1})
                elif action == 'agc':
                    bridge.apply_configuration({'tunerAgc': not bridge.tuner_agc})
                else:
                    scanner.stop()
                worker.join(timeout=0.5)
                try:
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(result, [None])
                finally:
                    scanner.stop()
                    worker.join(timeout=1)

    def test_stalled_capture_timeout_includes_flush_budget(self):
        bridge = self.bridge()
        scanner = rtl.Scanner(bridge)
        scanner._apply_pending_receiver_settings = lambda: None
        scanner._command = lambda *args: None
        scanner.settle_seconds = 0.1
        scanner.flush_seconds = 0.2
        scanner.capture_timeout_seconds = 0.3
        # Virtual clock keeps this deterministic and avoids real stall delays.
        with patch.object(rtl.time, 'monotonic', side_effect=[10, 10.1, 10.59, 10.61]), \
                patch.object(scanner.iq_condition, 'wait') as wait:
            with self.assertRaises(TimeoutError):
                scanner._capture(471_000_000, bridge.config_snapshot())
            self.assertEqual(wait.call_count, 2)

    def test_capture_propagates_reader_error(self):
        bridge = self.bridge()
        scanner = rtl.Scanner(bridge)
        scanner._apply_pending_receiver_settings = lambda: None
        scanner._command = lambda *args: None
        scanner.reader_error = ConnectionError('stream closed')
        with self.assertRaisesRegex(ConnectionError, 'stream closed'):
            scanner._capture(471_000_000, bridge.config_snapshot())

    def test_flush_environment_validation(self):
        for value in ('0', '1000', '5000', '-1', '5001', '1.5', 'nan', 'invalid'):
            with self.subTest(value=value), patch.dict(rtl.os.environ, {'RTL_FLUSH_MS': value}):
                module = importlib.util.module_from_spec(spec)
                if value in ('0', '1000', '5000'):
                    spec.loader.exec_module(module)
                    self.assertEqual(module.FLUSH_MS, int(value))
                else:
                    with self.assertRaisesRegex(ValueError, 'RTL_FLUSH_MS'):
                        spec.loader.exec_module(module)

    def test_live_flush_budget_validation_and_invalidation(self):
        bridge = self.bridge()
        bridge.scanner = rtl.Scanner(bridge)
        old = bridge.config_snapshot()
        result = bridge.apply_configuration({'flushMs': 125})
        self.assertEqual(result['flushMs'], 125)
        self.assertEqual(bridge.scanner.flush_seconds, 0.125)
        self.assertFalse(bridge.publish([-30], old, old['revision']))
        for value in (-1, 5001, 0.5, True, '125'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'flushMs'):
                bridge.apply_configuration({'flushMs': value})

    def bridge(self):
        bridge = rtl.Bridge()
        bridge.apply_configuration({'startHz': 470_000_000, 'stopHz': 473_000_000, 'rbwHz': 50_000, 'repeat': 255})
        bridge.sweep_start()
        return bridge

    def test_continuous_repeats_single_stops(self):
        bridge = self.bridge()
        config = bridge.config_snapshot()
        for _ in range(3):
            self.assertTrue(bridge.publish([-40], config, config['revision']))
            self.assertTrue(bridge.is_sweeping())
        bridge.apply_configuration({'repeat': 1})
        self.assertTrue(bridge.publish([-40], config, config['revision']))
        self.assertFalse(bridge.is_sweeping())
        self.assertFalse(bridge.publish([-40], config, config['revision']))

    def test_restart_rejects_inflight_sweep_and_clears_old_trace(self):
        bridge = self.bridge()
        old = bridge.config_snapshot()
        bridge.publish([-40], old, old['revision'])
        previous_id = bridge.sweep_id
        bridge.sweep_stop()
        bridge.sweep_start()
        self.assertEqual(bridge.get_trace()['series'], [])
        self.assertFalse(bridge.publish([-20], old, old['revision']))
        current = bridge.config_snapshot()
        self.assertTrue(bridge.publish([-60], current, current['revision']))
        self.assertGreater(bridge.sweep_id, previous_id)
        self.assertEqual(bridge.sweep_count, 1)

    def test_reconfigure_rejects_previous_band(self):
        bridge = self.bridge()
        old = bridge.config_snapshot()
        bridge.apply_configuration({'startHz': 800_000_000, 'stopHz': 801_000_000})
        self.assertFalse(bridge.publish([-40], old, old['revision']))

    def test_segments_cover_band_without_overlap_or_out_of_range_tuning(self):
        for rate in (250_000, 1_800_000, 3_200_000):
            for start, stop in ((24_000_000, 24_100_000), (470_000_000, 524_000_000),
                                (1_765_900_000, 1_766_000_000), (24_000_000, 1_766_000_000)):
                previous = start
                for center, left, right in rtl.scan_segments(start, stop, rate):
                    self.assertEqual(left, previous)
                    self.assertGreater(right, left)
                    self.assertGreaterEqual(center, rtl.MIN_FREQUENCY_HZ)
                    self.assertLessEqual(center, rtl.MAX_FREQUENCY_HZ)
                    self.assertGreaterEqual(left, center - rate * 0.4)
                    self.assertLessEqual(right, center + rate * 0.4)
                    previous = right
                self.assertEqual(previous, stop)

    def test_tones_land_in_correct_band_bins_including_upper_limit(self):
        for start, stop, tone in ((470_000_000, 474_500_000, 473_700_000),
                                 (1_764_000_000, 1_766_000_000, 1_765_900_000)):
            bridge = self.bridge()
            bridge.apply_configuration({'startHz': start, 'stopHz': stop})
            scanner = rtl.Scanner(bridge)
            scanner._capture = lambda center, config: tone_iq(center, tone, scanner.sample_rate)
            values = scanner._scan(bridge.config_snapshot())
            peak = max(range(len(values)), key=values.__getitem__)
            self.assertLessEqual(abs(start + peak * 50_000 - tone), 25_000)
            self.assertGreater(values[peak], -15)

    def test_reader_drains_during_processing_and_preserves_iq_alignment(self):
        bridge = self.bridge()
        scanner = rtl.Scanner(bridge)
        reader, writer = socket.socketpair()
        reader.settimeout(0.1)
        scanner.sock = reader
        thread = threading.Thread(target=scanner._read_iq, args=(reader,), daemon=True)
        thread.start()
        try:
            # Odd TCP packet boundaries must not swap I and Q. No FFT consumer runs here.
            data = bytes([17, 238]) * (rtl.FFT_SIZE * 4)
            for offset in range(0, len(data), 1001):
                writer.sendall(data[offset:offset + 1001])
            wait_for(lambda: scanner.iq_bytes == len(data))
            with scanner.iq_condition:
                self.assertEqual(len(scanner.iq_buffer), rtl.FFT_SIZE * 2)
                self.assertEqual(bytes(scanner.iq_buffer), bytes([17, 238]) * rtl.FFT_SIZE)
        finally:
            scanner.stop()
            writer.close()
            thread.join(timeout=1)

    def test_continuous_tcp_stream_repeats_and_switches_modes(self):
        fake = FakeRtlTcp()
        bridge = self.bridge()
        scanner = rtl.Scanner(bridge, host='127.0.0.1', port=fake.port)
        scanner.settle_seconds = 0.02
        scanner.flush_seconds = 0
        scanner.start()
        try:
            wait_for(lambda: bridge.sweep_count >= 3)
            trace = bridge.get_trace()
            values = trace['series'][0]['amplitudesDbfs']
            peak = max(range(len(values)), key=values.__getitem__)
            self.assertEqual(trace['startHz'] + peak * trace['stepHz'], fake.tone)
            self.assertTrue(trace['sweeping'])
            previous_id = trace['sweepId']
            bridge.apply_configuration({'repeat': 1})
            bridge.sweep_start()
            wait_for(lambda: not bridge.is_sweeping())
            self.assertEqual(bridge.sweep_count, 1)
            self.assertGreater(bridge.sweep_id, previous_id)
            bridge.apply_configuration({'repeat': 255})
            bridge.sweep_start()
            wait_for(lambda: bridge.sweep_count >= 2)
            self.assertTrue(bridge.is_sweeping())
            self.assertGreater(len(fake.tunes), 12)
        finally:
            scanner.stop()
            scanner.thread.join(timeout=2)
            fake.close()


if __name__ == '__main__':
    unittest.main()
