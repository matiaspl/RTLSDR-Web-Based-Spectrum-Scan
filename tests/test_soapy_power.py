"""Spectrum parser and process lifecycle tests with synthetic local/SSH producers."""
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from engine.soapy_power_backend import Bridge, SpectrumParser, acquisition_range, soapy_command, worker_command

ROOT = Path(__file__).resolve().parents[1]
FAKE = str(ROOT / 'tests/fixtures/fake_soapy_power.py')
SSH = str(ROOT / 'tests/fixtures/fake_ssh.py')


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.02)
    raise AssertionError('Timed out waiting for test condition')


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class ParserTests(unittest.TestCase):
    def test_hop_and_pass_markers_are_distinct(self):
        hops, passes = [], []
        parser = SpectrumParser(lambda p, s: hops.append((p[:], s)), lambda: passes.append(True))
        for line in ['# header', '470000000 -90', '470000100 -inf', '']:
            parser.feed(line)
        self.assertEqual(len(hops), 1)
        self.assertEqual(passes, [])
        parser.feed('')
        self.assertEqual(passes, [True])
        self.assertEqual(hops[0][1], 100)

    def test_invalid_data_and_missing_hops_fail(self):
        for row in ['470000000 nan', '470000000 inf', 'nan -90', 'bad row', '1 -90']:
            with self.subTest(row=row), self.assertRaises(ValueError):
                SpectrumParser(lambda *_: None, lambda: None).feed(row)
        parser = SpectrumParser(lambda *_: None, lambda: None)
        for row in ['470000000 -90', '470000100 -90', '', '470001000 -90', '470001100 -90']:
            parser.feed(row)
        with self.assertRaisesRegex(ValueError, 'missing'):
            parser.feed('')

    def test_nonuniform_grid_fails(self):
        parser = SpectrumParser(lambda *_: None, lambda: None)
        for row in ['470000000 -90', '470000100 -90', '470000201 -90']:
            parser.feed(row)
        with self.assertRaisesRegex(ValueError, 'uniform'):
            parser.feed('')


class BridgeTests(unittest.TestCase):
    def make_bridge(self, mode='local', binary=FAKE):
        profile = dict(mode=mode, serial='TEST0001', binary=binary,
                       host='receiver.example', port=2222, sshUser='operator', remotePython=sys.executable)
        bridge = Bridge(profile)
        bridge.apply_configuration({'startHz': 470000000, 'stopHz': 474000000, 'repeat': 1})
        bridge.serve(0)
        self.addCleanup(bridge.shutdown)
        return bridge

    def test_local_single_streams_partial_and_converts_density(self):
        bridge = self.make_bridge()
        bridge.sweep_start()
        partial = wait_for(lambda: (t if (t := bridge.get_trace()).get('updates') else None))
        self.assertFalse(partial['coverageComplete'])
        self.assertLess(partial['coveragePct'], 100)
        self.assertTrue(partial['sweeping'])
        self.assertTrue(any(not x for x in partial['series'][0]['coverage']))
        completed = wait_for(lambda: (t if (t := bridge.get_trace()).get('coverageComplete') else None))
        self.assertFalse(completed['sweeping'])
        self.assertEqual(completed['sweepCount'], 1)
        values = completed['updates'][0]['amplitudesDbfs']
        self.assertAlmostEqual(max(values), -45 + 10 * math.log10(1800000 / 4096), places=6)
        self.assertEqual(len({u['passId'] for u in completed['updates']}), 1)
        wait_for(lambda: bridge.process is None)

    def test_remote_quoted_worker_pipeline(self):
        with patch.dict(os.environ, {'SSH_BIN': SSH}):
            bridge = self.make_bridge('remote')
            command = worker_command(bridge.configuration(), bridge.profile)
            self.assertIn('BatchMode=yes', command)
            self.assertIn('StrictHostKeyChecking=yes', command)
            remote = shlex.split(command[-1])
            soapy = json.loads(remote[-1])
            self.assertEqual(soapy[soapy.index('-d') + 1], 'driver=rtlsdr,serial=TEST0001')
            bridge.sweep_start()
            wait_for(lambda: bridge.get_trace().get('coverageComplete'))
            self.assertEqual(bridge.sweep_count, 1)
            wait_for(lambda: bridge.process is None)

    def test_continuous_pass_ids_and_stop_reap_child(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'FAKE_SOAPY_PID_FILE': folder + '/pid'}):
            bridge = self.make_bridge()
            bridge.apply_configuration({'repeat': 255})
            bridge.sweep_start()
            wait_for(lambda: bridge.sweep_count >= 2)
            pid = int(Path(folder, 'pid').read_text())
            trace = bridge.get_trace()
            self.assertGreaterEqual(trace['updates'][-1]['passId'], 2)
            bridge.sweep_stop()
            wait_for(lambda: bridge.process is None)
            self.assertFalse(alive(pid))
            self.assertFalse(bridge.get_trace()['sweeping'])

    def test_reconfigure_restarts_and_rejects_old_trace(self):
        bridge = self.make_bridge()
        bridge.apply_configuration({'repeat': 255})
        bridge.sweep_start()
        wait_for(lambda: bool(bridge.get_trace()['updates']))
        bridge.apply_configuration({'startHz': 500000000, 'stopHz': 503000000, 'ppmCorrection': 12})
        self.assertEqual(bridge.get_trace()['updates'], [])
        result = wait_for(lambda: (t if (t := bridge.get_trace())['updates'] else None))
        self.assertTrue(all(u['startHz'] == 500000000 for u in result['updates']))
        self.assertTrue(all(f >= 500000000 for u in result['updates'] for f in u['frequenciesHz']))

    def test_failures_never_report_complete(self):
        for behavior in ('failure', 'malformed', 'truncated'):
            with self.subTest(behavior=behavior), patch.dict(os.environ, {'FAKE_SOAPY_BEHAVIOR': behavior}):
                bridge = self.make_bridge()
                bridge.sweep_start()
                result = wait_for(lambda: (t if (t := bridge.get_trace())['state'] == 'ERROR' else None))
                self.assertEqual(result['sweepCount'], 0)
                self.assertFalse(result.get('coverageComplete', False))
                self.assertFalse(result['sweeping'])
                self.assertTrue(result['error'])
                bridge.shutdown()

    def test_missing_dependency_is_actionable(self):
        bridge = self.make_bridge(binary='/nonexistent/soapy_power')
        bridge.sweep_start()
        wait_for(lambda: bridge.state == 'ERROR')
        self.assertIn('/nonexistent/soapy_power', bridge.error)

    def test_stop_stalled_worker_and_restart(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'FAKE_SOAPY_BEHAVIOR': 'stall', 'FAKE_SOAPY_PID_FILE': folder + '/pid'}):
            bridge = self.make_bridge()
            bridge.sweep_start()
            wait_for(lambda: Path(folder, 'pid').exists())
            pid = int(Path(folder, 'pid').read_text())
            bridge.sweep_stop()
            wait_for(lambda: bridge.process is None)
            self.assertFalse(alive(pid))
        bridge.sweep_start()
        wait_for(lambda: bridge.get_trace().get('coverageComplete'))

    def test_configuration_is_atomic_and_validated(self):
        bridge = Bridge()
        before = bridge.configuration()
        for change in ({'repeat': True}, {'averages': 0}, {'startHz': 100}, {'digitalAgc': True},
                       {'gainDb': float('nan')}, {'startHz': 480000000, 'stopHz': 470000000}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                bridge.apply_configuration(change)
            self.assertEqual(before, bridge.configuration())
        bridge.apply_configuration({'ppmCorrection': -42, 'tunerAgc': True, 'averages': 16})
        args = soapy_command(bridge.configuration(), {'mode': 'local'})
        self.assertIn('-a', args)
        self.assertNotIn('-g', args)
        self.assertEqual(args[args.index('-p') + 1], '-42')

    def test_rejects_ssh_and_driver_argument_injection(self):
        bridge = Bridge()
        for profile in ({'mode': 'remote', 'host': '-oProxyCommand=bad'},
                        {'mode': 'remote', 'host': 'host;touch bad'},
                        {'mode': 'remote', 'host': 'host', 'sshUser': 'x;bad'},
                        {'mode': 'local', 'serial': 'x,driver=remote'}):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                worker_command(bridge.configuration(), profile)

    def test_planner_keeps_tuner_centers_in_range(self):
        for rate in (250000, 1800000, 2400000, 3200000):
            width = 3276 * rate / 4096
            for start, stop in ((24000000, 1766000000), (1759000000, 1766000000),
                                (1765500000, 1766000000), (24000000, 24001000)):
                with self.subTest(rate=rate, start=start):
                    low, high = acquisition_range(dict(startHz=start, stopHz=stop, sampleRate=rate))
                    hops = math.ceil((high - low) / width)
                    first_center = low + width / 2 if hops > 1 else (low + high) / 2
                    last_center = first_center + (hops - 1) * width
                    self.assertGreaterEqual(first_center, 24000000)
                    self.assertLessEqual(last_center, 1766000000)
                    self.assertLessEqual(first_center - width / 2, start)
                    self.assertGreaterEqual(last_center + width / 2, stop)

    def test_narrow_and_upper_edge_sweeps_complete(self):
        for start, stop in ((470000000, 470100000), (1759000000, 1766000000)):
            with self.subTest(start=start):
                bridge = self.make_bridge()
                bridge.apply_configuration(dict(startHz=start, stopHz=stop))
                bridge.sweep_start()
                trace = wait_for(lambda: (t if (t := bridge.get_trace()).get('coverageComplete') else None))
                self.assertTrue(all(start <= f <= stop for u in trace['updates'] for f in u['frequenciesHz']))
                bridge.shutdown()


if __name__ == '__main__':
    unittest.main()
