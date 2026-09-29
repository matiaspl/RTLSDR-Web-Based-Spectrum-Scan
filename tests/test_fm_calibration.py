"""FM offset estimation and calibration lifecycle without RF hardware."""
import importlib.util
import math
import random
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('rtl_fm_test', Path(__file__).parents[1] / 'engine/rtl_tcp_backend.py')
rtl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rtl)


def fm_iq(offset, residual=0, deviation=30000, amplitude=45):
    rate = 1800000
    modulation = rate / 2048
    data = bytearray()
    for i in range(rtl.CALIBRATION_FFT_SIZE):
        phase = 2 * math.pi * (offset + residual) * i / rate + deviation / modulation * math.sin(2 * math.pi * modulation * i / rate)
        data.extend((round(127.5 + amplitude * math.cos(phase)), round(127.5 + amplitude * math.sin(phase))))
    return bytes(data)


class CalibrationTests(unittest.TestCase):
    def test_discriminator_tracks_offset_on_both_sides_of_dc(self):
        for offset in (-250000, 250000):
            for residual in (-2500, 0, 2500):
                with self.subTest(offset=offset, residual=residual):
                    measured, snr = rtl.fm_offset_hz(fm_iq(offset, residual), 1800000, offset)
                    self.assertAlmostEqual(measured, residual, delta=100)
                    self.assertGreater(snr, 8)

    def test_rejects_noise_and_clipping(self):
        rng = random.Random(1)
        noise = bytes(round(rng.uniform(90, 165)) for _ in range(rtl.CALIBRATION_FFT_SIZE * 2))
        for raw in (noise, bytes([0, 255]) * rtl.CALIBRATION_FFT_SIZE):
            with self.assertRaises(ValueError):
                rtl.fm_offset_hz(raw, 1800000, 250000)

    def test_correction_sign_includes_existing_ppm(self):
        for residual, expected in ((1000, 56), (-1000, 76)):
            buckets = {(side, second): [residual - 1, residual + 1] for side in (0, 1) for second in range(10)}
            result = rtl.summarize_fm_calibration(buckets, 100000000, 66)
            self.assertEqual(result['suggestedPpm'], expected)
            self.assertTrue(result['canApply'])

    def test_rejects_inconsistent_lo_positions_and_out_of_range(self):
        buckets = {(side, second): [side * 5000] for side in (0, 1) for second in range(10)}
        self.assertFalse(rtl.summarize_fm_calibration(buckets, 100000000, 66)['canApply'])
        buckets = {(side, second): [-1000] for side in (0, 1) for second in range(10)}
        self.assertFalse(rtl.summarize_fm_calibration(buckets, 100000000, 1000)['canApply'])

    def test_job_validation_and_cancellation(self):
        bridge = rtl.Bridge()
        bridge.apply_configuration({'tunerAgc': False, 'digitalAgc': False})
        for frequency in (None, True, '93.5', float('nan'), 86000000, 109000000):
            with self.assertRaises(ValueError):
                bridge.calibration_start({'referenceHz': frequency})
        job = bridge.calibration_start({'referenceHz': 93500000})
        self.assertTrue(bridge.calibration_active(job['revision']))
        with self.assertRaises(ValueError):
            bridge.calibration_start({'referenceHz': 93500000})
        bridge.calibration_cancel()
        self.assertEqual(bridge.calibration_status()['status'], 'cancelled')
        self.assertFalse(bridge.calibration_active(job['revision']))
        job = bridge.calibration_start({'referenceHz': 93500000})
        bridge.apply_configuration({'ppmCorrection': bridge.ppm_correction + 1})
        self.assertFalse(bridge.calibration_active(job['revision']))
        bridge.apply_configuration({'tunerAgc': True})
        with self.assertRaises(ValueError):
            bridge.calibration_start({'referenceHz': 93500000})


if __name__ == '__main__':
    unittest.main()
