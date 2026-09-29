"""Kalibrate detector, consensus and receiver-state regression tests."""
import math
import random
import threading
import time
import unittest
from unittest.mock import patch
from engine import gsm_calibration as gsm
from engine import rtl_tcp_backend as rtl


def iq(offset=0, bursts=True, noise=6):
    rng = random.Random(4)
    data = bytearray()
    for i in range(gsm.FRAME_SAMPLES):
        on = not bursts or any(s <= i < s+148 for s in (1000, 13500))
        phase = 2*math.pi*(gsm.TONE_HZ+offset)*i/gsm.SAMPLE_RATE
        amplitude = 40 if on else 0
        for value in (amplitude*math.cos(phase), amplitude*math.sin(phase)):
            data.append(max(0, min(255, round(127.5+value+rng.gauss(0, noise)))))
    return bytes(data)


class GsmCalibrationTests(unittest.TestCase):
    def test_offsets_and_sign(self):
        for residual in (-3000, 0, 3000):
            offsets = gsm.fcch_offsets(iq(residual), rtl._fft)
            self.assertGreaterEqual(len(offsets), 2)
            for value in offsets:
                self.assertAlmostEqual(value, residual, delta=150)
        result = gsm.channel_summary(25, 940000000, [940]*40, 66)
        self.assertEqual(result['estimatedPpm'], 65)

    def test_reject_cw_clipping_and_noise(self):
        rng = random.Random(23)
        for raw in (iq(bursts=False), bytes([0, 255])*gsm.FRAME_SAMPLES,
                    bytes(rng.randrange(100, 155) for _ in range(gsm.FRAME_SAMPLES*2))):
            self.assertEqual(gsm.fcch_offsets(raw, rtl._fft), [])
        with self.assertRaises(ValueError):
            gsm.fcch_offsets(b'odd', rtl._fft)

    def test_band_and_consensus(self):
        frequencies = [f for _, f in gsm.CHANNELS]
        self.assertEqual(len(set(frequencies)), 174)
        self.assertEqual(min(frequencies), 925200000)
        self.assertEqual(max(frequencies), 959800000)
        a = gsm.channel_summary(25, 940000000, [940]*40, 66)
        b = gsm.channel_summary(50, 945000000, [945]*40, 66)
        result = gsm.consensus([a, b], 66)
        self.assertTrue(result['canApply'])
        self.assertEqual(result['suggestedPpm'], 65)
        with self.assertRaises(ValueError):
            gsm.consensus([a], 66)
        b['estimatedPpm'] = 70
        self.assertFalse(gsm.consensus([a, b], 66)['canApply'])
        self.assertIsNone(gsm.channel_summary(25, 940000000, [0]*29, 66))

    def test_capture_cancellation_restores_sample_rate(self):
        bridge = rtl.Bridge()
        bridge.apply_configuration({'tunerAgc': False, 'digitalAgc': False})
        scanner = rtl.Scanner(bridge)
        bridge.scanner = scanner
        scanner.running = True
        scanner.sock = object()
        original_rate = scanner.sample_rate
        job = bridge.calibration_start({'method': 'gsm'})
        calls = []
        def capture(*args, **kwargs):
            if scanner.sample_rate == gsm.SAMPLE_RATE:
                bridge.calibration_cancel()
                return None
            return bytes([127, 128])*rtl.FFT_SIZE
        with patch.object(scanner, '_capture', side_effect=capture), patch.object(scanner, '_command', side_effect=lambda *args: calls.append(args)):
            scanner._calibrate(job)
        self.assertIn((2, gsm.SAMPLE_RATE), calls)
        self.assertIn((2, original_rate), calls)
        self.assertIn((5, bridge.ppm_correction), calls)
        self.assertIsNone(scanner.calibration_ppm_override)
        self.assertEqual(scanner.sample_rate, original_rate)
        self.assertEqual(scanner.iq_keep_bytes, rtl.FFT_SIZE*2)
        self.assertEqual(bridge.calibration_status()['status'], 'cancelled')

    def test_block_stall_and_cancel(self):
        bridge = rtl.Bridge()
        bridge.apply_configuration({'tunerAgc': False, 'digitalAgc': False})
        scanner = rtl.Scanner(bridge)
        scanner.running = True
        job = bridge.calibration_start({'method': 'gsm'})
        scanner.capture_timeout_seconds = .05
        with self.assertRaises(TimeoutError):
            scanner._gsm_block(job['revision'])
        timer = threading.Timer(.03, bridge.calibration_cancel)
        timer.start()
        started = time.monotonic()
        self.assertIsNone(scanner._gsm_block(job['revision']))
        self.assertLess(time.monotonic()-started, .1)
        timer.join()

    def test_success_and_error_restore_settings(self):
        for fail in (False, True):
            bridge = rtl.Bridge()
            bridge.apply_configuration({'tunerAgc': False, 'digitalAgc': False})
            scanner = rtl.Scanner(bridge)
            bridge.scanner = scanner
            scanner.running, scanner.sock = True, object()
            rate, flush, ppm = scanner.sample_rate, scanner.flush_seconds, bridge.ppm_correction
            job = bridge.calibration_start({'method': 'gsm'})
            channels = gsm.CHANNELS[:3]
            with patch.object(scanner, '_command'), patch.object(scanner, '_capture', return_value=bytes([127,128])*rtl.FFT_SIZE), \
                 patch.object(scanner, '_gsm_block', return_value=b''), patch.object(gsm, 'CHANNELS', channels), \
                 patch.object(gsm, 'fcch_offsets', return_value=[] if fail else [0]*40):
                scanner._calibrate(job)
            self.assertEqual(bridge.calibration_status()['status'], 'error' if fail else 'ready')
            self.assertEqual(scanner.sample_rate, rate)
            self.assertEqual(scanner.flush_seconds, flush)
            self.assertEqual(bridge.ppm_correction, ppm)
            self.assertFalse(bridge.is_sweeping())

    def test_method_validation_and_setting_invalidation(self):
        bridge = rtl.Bridge()
        bridge.apply_configuration({'tunerAgc': False, 'digitalAgc': False})
        with self.assertRaises(ValueError):
            bridge.calibration_start({'method': 'lte'})
        job = bridge.calibration_start({'method': 'gsm'})
        bridge.apply_configuration({'ppmCorrection': bridge.ppm_correction+1})
        self.assertFalse(bridge.calibration_active(job['revision']))

    def test_integer_verification_uses_measured_error(self):
        def channel(frequency, error):
            return {'referenceHz': frequency, 'residualHz': error*frequency/1e6, 'uncertaintyPpm': .05}
        measurements = [
            {'ppm': 68, 'channels': [channel(937800000, -.72), channel(959800000, -1.26)]},
            {'ppm': 69, 'channels': [channel(937800000, 1.08), channel(959800000, .50)]}]
        self.assertEqual(gsm.verified_setting(measurements)['ppm'], 69)
        measurements[1]['channels'].pop()
        with self.assertRaises(ValueError):
            gsm.verified_setting(measurements)

    def test_cancel_during_temporary_ppm_restores_saved_value(self):
        bridge = rtl.Bridge()
        bridge.apply_configuration({'tunerAgc': False, 'digitalAgc': False, 'ppmCorrection': 64})
        scanner = rtl.Scanner(bridge)
        bridge.scanner = scanner
        scanner.running, scanner.sock = True, object()
        job = bridge.calibration_start({'method': 'gsm'})
        commands = []
        def capture(*args, **kwargs):
            if scanner.calibration_ppm_override is not None:
                bridge.calibration_cancel()
                return None
            return bytes([127,128])*rtl.FFT_SIZE
        with patch.object(scanner, '_command', side_effect=lambda *args: commands.append(args)), \
             patch.object(scanner, '_capture', side_effect=capture), patch.object(scanner, '_gsm_block', return_value=b''), \
             patch.object(gsm, 'fcch_offsets', return_value=[-4000]*40):
            scanner._calibrate(job)
        self.assertEqual(bridge.calibration_status()['status'], 'cancelled')
        self.assertIsNone(scanner.calibration_ppm_override)
        self.assertEqual(scanner.applied_ppm_correction, 64)
        self.assertEqual(bridge.ppm_correction, 64)


if __name__ == '__main__':
    unittest.main()
