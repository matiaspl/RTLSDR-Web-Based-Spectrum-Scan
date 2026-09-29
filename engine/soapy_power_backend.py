#!/usr/bin/env python3
"""Local HTTP bridge for local USB or SSH-hosted soapy_power spectrum scans.

IQ stays on the acquisition host. The bridge parses upstream rtl_power_fftw
output: one blank line ends a hop, and the second ends a complete sweep.
"""
import json
import math
import os
from pathlib import Path
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

FFT_SIZE = 4096
FLOOR = -125.0
WORKER = Path(__file__).with_name('soapy_worker.py')


def acquisition_range(config):
    """Keep upstream's last tuner center inside the RTL-SDR upper limit.

    Upstream rounds the number of hops up. Shift its input span slightly left
    when necessary; publication still clips to the exact requested range.
    """
    width = (FFT_SIZE - 2 * math.ceil(.2 * FFT_SIZE / 2)) * config['sampleRate'] / FFT_SIZE
    start, stop = config['startHz'], config['stopHz']
    hops = math.ceil((stop - start) / width)
    if hops > 1:
        last_center = start + (hops - .5) * width
        start -= max(0, last_center - 1_766_000_000)
    return start, stop


def soapy_command(config, profile):
    """Only local RTL-SDR drivers are permitted, on either acquisition host."""
    device = 'driver=rtlsdr'
    serial = profile.get('serial', '')
    if serial:
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', serial):
            raise ValueError('Invalid RTL-SDR serial')
        device += ',serial=' + serial
    command = [profile.get('binary', 'soapy_power'), '-d', device,
               '-f', '%.9f:%.9f' % acquisition_range(config),
               '-r', str(config['sampleRate']), '-b', str(FFT_SIZE),
               '-n', str(config['averages']), '-k', '20', '--fft-window', 'hann',
               '--fft-overlap', '0', '-D', 'constant', '--reset-stream',
               '--tune-delay', str(config['settleMs'] / 1000),
               '-p', str(config['ppmCorrection']), '-F', 'rtl_power_fftw',
               '--max-queue-size', '4', '--max-threads', '1']
    command += ['-a'] if config['tunerAgc'] else ['-g', str(config['gainDb'])]
    command += ['-u', '1'] if config['repeat'] == 1 else ['-c']
    return command


def worker_command(config, profile):
    command_json = json.dumps(soapy_command(config, profile))
    if profile['mode'] == 'local':
        return [sys.executable, '-u', str(WORKER), command_json]
    if profile['mode'] != 'remote':
        raise ValueError('Mode must be local or remote')
    host = profile.get('host', '')
    user = profile.get('sshUser', '')
    port = profile.get('port', 22)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', host):
        raise ValueError('Invalid SSH host')
    if user and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', user):
        raise ValueError('Invalid SSH user')
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Invalid SSH port')
    remote = shlex.join([profile.get('remotePython', 'python3'), '-u', '-c',
                         WORKER.read_text(), command_json])
    command = [os.environ.get('SSH_BIN', 'ssh'), '-T', '-o', 'BatchMode=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
               '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3',
               '-p', str(port)]
    if user:
        command += ['-l', user]
    return command + ['--', host, remote]


class SpectrumParser:
    """Validate hop framing and frequency grids before publishing spectrum data."""
    def __init__(self, hop, complete):
        self.hop = hop
        self.complete = complete
        self.points = []
        self.hops = 0
        self.previous_end = None

    def feed(self, line):
        text = line.strip()
        if text.startswith('#'):
            return
        if not text:
            if self.points:
                if len(self.points) < 2:
                    raise ValueError('Spectrum hop contains fewer than two bins')
                spacing = self.points[1][0] - self.points[0][0]
                if spacing <= 0 or any(abs((b[0] - a[0]) - spacing) > max(.1, spacing * 1e-5)
                                       for a, b in zip(self.points, self.points[1:])):
                    raise ValueError('Spectrum frequency grid is not uniform')
                if self.previous_end is not None and abs(self.points[0][0] - self.previous_end) > max(1, spacing * .05):
                    raise ValueError('Spectrum has missing, duplicate or out-of-order hops')
                self.hop(self.points, spacing)
                self.previous_end = self.points[-1][0] + spacing
                self.points = []
                self.hops += 1
            elif self.hops:
                self.complete()
                self.hops = 0
                self.previous_end = None
            return
        fields = text.split()
        if len(fields) != 2:
            raise ValueError('Invalid soapy_power spectrum row')
        frequency, density = map(float, fields)
        if not math.isfinite(frequency) or not (24e6 - 3.2e6 <= frequency <= 1766e6 + 3.2e6):
            raise ValueError('Invalid spectrum frequency')
        if not math.isfinite(density) and density != -math.inf:
            raise ValueError('Invalid spectrum power')
        if len(self.points) >= FFT_SIZE:
            raise ValueError('Spectrum hop exceeds configured FFT size')
        self.points.append((frequency, density))


class Bridge:
    def __init__(self, profile=None):
        self.profile = profile or json.loads(os.environ.get('SOAPY_PROFILE', '{"mode":"local"}'))
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.running = True
        self.process = None
        self.server = None
        self.config = {
            'startHz': int(os.environ.get('RTL_START_HZ', '470000000')),
            'stopHz': int(os.environ.get('RTL_STOP_HZ', '524000000')),
            'rbwHz': int(os.environ.get('RTL_RBW_HZ', '350000')),
            'sampleRate': int(os.environ.get('RTL_SAMPLE_RATE', '1800000')),
            'settleMs': int(os.environ.get('RTL_SETTLE_MS', '30')),
            'averages': int(os.environ.get('SOAPY_AVERAGES', '8')),
            'gainDb': float(os.environ.get('RTL_TUNER_GAIN_DB', '25')),
            'ppmCorrection': int(os.environ.get('RTL_PPM_CORRECTION', '0')),
            'tunerAgc': os.environ.get('RTL_TUNER_AGC') == '1',
            'repeat': int(os.environ.get('RTL_REPEAT', '255')),
        }
        self.validate(self.config)
        self.revision = 0
        self.sweeping = False
        self.state = 'READY'
        self.error = None
        self.sweep_id = 0
        self.pass_id = 0
        self.sweep_count = 0
        self.pending = []
        self.trace = None
        self.progress = None
        self.thread = None

    @staticmethod
    def validate(config):
        limits = {'startHz': (24_000_000, 1_766_000_000), 'stopHz': (24_000_000, 1_766_000_000),
                  'rbwHz': (1, 1_000_000), 'sampleRate': (250_000, 3_200_000),
                  'settleMs': (10, 2000), 'averages': (1, 1024), 'ppmCorrection': (-1000, 1000)}
        for key, (low, high) in limits.items():
            value = config[key]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError('%s must be an integer from %d to %d' % (key, low, high))
        if config['stopHz'] <= config['startHz']:
            raise ValueError('stopHz must be greater than startHz')
        if type(config['repeat']) is not int or config['repeat'] not in (1, 255):
            raise ValueError('repeat must be 1 or 255')
        if not isinstance(config['tunerAgc'], bool):
            raise ValueError('tunerAgc must be true or false')
        if isinstance(config['gainDb'], bool) or not isinstance(config['gainDb'], (int, float)) or not math.isfinite(config['gainDb']) or not 0 <= config['gainDb'] <= 50:
            raise ValueError('gainDb must be from 0 to 50')

    def configuration(self):
        with self.lock:
            return dict(self.config, revision=self.revision, sweeping=self.sweeping)

    def apply_configuration(self, body):
        if not isinstance(body, dict):
            raise ValueError('Expected an object')
        if body.get('digitalAgc') or body.get('flushMs') is not None:
            raise ValueError('Digital AGC and rtl_tcp flushing are not supported by this backend')
        with self.lock:
            updated = dict(self.config)
            for key in updated:
                if key in body:
                    updated[key] = body[key]
            self.validate(updated)
            if updated != self.config:
                self.config = updated
                self.revision += 1
                self.trace = self.progress = None
                self.pending = []
                self.wake.set()
            return self.configuration()

    def sweep_start(self):
        with self.lock:
            self.revision += 1
            self.sweeping = True
            self.state = 'STARTING'
            self.error = None
            self.sweep_count = 0
            self.trace = self.progress = None
            self.pending = []
            self.wake.set()
            return {'sweeping': True, 'sweepId': self.sweep_id}

    def sweep_stop(self):
        with self.lock:
            self.revision += 1
            self.sweeping = False
            self.state = 'ERROR' if self.error else 'READY'
            self.progress = None
            self.wake.set()
            return {'sweeping': False, 'sweepId': self.sweep_id}

    def get_trace(self, after=-1):
        with self.lock:
            result = dict(self.trace or {}, startHz=self.config['startHz'], stopHz=self.config['stopHz'],
                          stepHz=self.config['rbwHz'], sweepId=self.sweep_id, sweepCount=self.sweep_count,
                          sweeping=self.sweeping, state=self.state, error=self.error,
                          progress=self.progress, unit='dBFS', series=(self.trace or {}).get('series', []))
            self.pending = [item for item in self.pending if item['sweepId'] > after]
            result['updates'] = list(self.pending)
            return result

    def active(self, revision):
        with self.lock:
            return self.running and self.sweeping and revision == self.revision

    @staticmethod
    def stop_process(process):
        if process is None:
            return
        # EOF reaches the remote worker and terminates its soapy_power child.
        try:
            process.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in (process.stdout, process.stderr):
            stream.close()

    def run_scan(self, config):
        revision = config['revision']
        process = subprocess.Popen(worker_command(config, self.profile), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   encoding='utf-8', errors='replace', bufsize=1)
        self.process = process
        messages = queue.Queue(maxsize=8192)
        finished = threading.Event()
        stderr_tail = []

        def read_output():
            try:
                while True:
                    line = process.stdout.readline(4097)
                    if not line:
                        break
                    while not finished.is_set():
                        try:
                            messages.put(line, timeout=.1)
                            break
                        except queue.Full:
                            continue
                    if finished.is_set():
                        break
            finally:
                while not finished.is_set():
                    try:
                        messages.put(None, timeout=.1)
                        break
                    except queue.Full:
                        continue

        def read_errors():
            for line in iter(lambda: process.stderr.readline(4097), ''):
                stderr_tail.append(line.strip()[:1000])
                del stderr_tail[:-8]

        readers = [threading.Thread(target=read_output, daemon=True), threading.Thread(target=read_errors, daemon=True)]
        for reader in readers:
            reader.start()
        powers = {}
        first_frequency = None
        last_frequency = None
        segments = 0
        started = time.monotonic()
        completed = False
        fresh_pass = True

        def on_hop(points, spacing):
            nonlocal first_frequency, last_frequency, segments, fresh_pass
            with self.lock:
                if not self.active(revision):
                    return
                if fresh_pass:
                    self.pass_id += 1
                    fresh_pass = False
                first_frequency = points[0][0] if first_frequency is None else first_frequency
                last_frequency = points[-1][0] + spacing
                segments += 1
                frequencies, values = [], []
                for frequency, density in points:
                    if config['startHz'] <= frequency <= config['stopHz']:
                        # Welch reports density per Hz. Integrate one FFT-bin width to
                        # preserve the dashboard's relative per-bin power convention.
                        value = max(FLOOR, min(10, density + 10 * math.log10(spacing)))
                        frequencies.append(frequency)
                        values.append(value)
                        index = round((frequency - config['startHz']) / config['rbwHz'])
                        powers[index] = powers.get(index, 0) + 10 ** (value / 10)
                count = (config['stopHz'] - config['startHz']) // config['rbwHz'] + 1
                amplitudes = [10 * math.log10(powers[i]) if i in powers else FLOOR for i in range(count)]
                coverage = [i in powers for i in range(count)]
                percent = min(100, max(0, (last_frequency - config['startHz']) * 100 / (config['stopHz'] - config['startHz'])))
                self.sweep_id += 1
                self.pending.append(dict(sweepId=self.sweep_id, passId=self.pass_id,
                                         startHz=config['startHz'], stopHz=config['stopHz'], binHz=spacing,
                                         frequenciesHz=frequencies, amplitudesDbfs=values))
                # Keep at most the current and previous pass for slow viewers.
                self.pending = [u for u in self.pending if u['passId'] >= self.pass_id - 1]
                self.trace = dict(pointCount=count, passId=self.pass_id, coverageComplete=False,
                                  coveragePct=round(percent, 1), series=[dict(name='A', amplitudesDbfs=amplitudes, coverage=coverage)])
                self.progress = dict(completedSegments=segments, percent=round(percent, 1),
                                     centerHz=(points[0][0] + last_frequency) / 2,
                                     elapsedSeconds=round(time.monotonic() - started, 1))
                self.state = 'CONNECTED'
                self.error = None

        def on_complete():
            nonlocal powers, first_frequency, last_frequency, segments, started, completed, fresh_pass
            with self.lock:
                if not self.active(revision):
                    return
                tolerance = config['sampleRate'] / FFT_SIZE
                if first_frequency is None or first_frequency > config['startHz'] + tolerance or last_frequency < config['stopHz'] - tolerance:
                    raise ValueError('soapy_power ended an incomplete frequency sweep')
                self.sweep_count += 1
                self.sweep_id += 1
                self.trace.update(coverageComplete=True, coveragePct=100)
                completed = True
                powers = {}
                first_frequency = last_frequency = None
                segments = 0
                started = time.monotonic()
                fresh_pass = True
                if config['repeat'] == 1:
                    self.sweeping = False
                    self.state = 'READY'

        parser = SpectrumParser(on_hop, on_complete)
        last_output = time.monotonic()
        last_heartbeat = 0
        try:
            while self.active(revision):
                if time.monotonic() - last_heartbeat > 2:
                    process.stdin.write('.')
                    process.stdin.flush()
                    last_heartbeat = time.monotonic()
                try:
                    line = messages.get(timeout=.1)
                except queue.Empty:
                    if time.monotonic() - last_output > 30:
                        raise TimeoutError('No spectrum output for 30 seconds. ' + '; '.join(stderr_tail))
                    continue
                if line is None:
                    process.wait(timeout=3)
                    readers[1].join(timeout=.2)
                    raise RuntimeError('soapy_power exited (%s)%s' % (process.returncode,
                                       ': ' + '; '.join(stderr_tail) if stderr_tail else ' before completing the scan'))
                last_output = time.monotonic()
                parser.feed(line)
        finally:
            finished.set()
            self.stop_process(process)
            for reader in readers:
                reader.join(timeout=1)
            self.process = None
        return completed

    def run(self):
        while self.running:
            self.wake.wait(.2)
            self.wake.clear()
            if not self.sweeping:
                continue
            config = self.configuration()
            try:
                self.run_scan(config)
            except Exception as exc:
                with self.lock:
                    if self.active(config['revision']):
                        self.sweeping = False
                        self.state = 'ERROR'
                        self.error = str(exc)
                        self.progress = None
                        print('[SOAPY] ERROR ' + str(exc), flush=True)

    def serve(self, port=0):
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, status, data):
                raw = json.dumps(data, allow_nan=False).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def handle_request(self):
                route, _, query = self.path.partition('?')
                try:
                    if route == '/trace' and self.command == 'GET':
                        return self.reply(200, bridge.get_trace(int(parse_qs(query).get('after', ['-1'])[0])))
                    if route == '/configuration':
                        if self.command == 'POST':
                            length = int(self.headers.get('Content-Length', '0'))
                            if not 0 <= length <= 65536:
                                raise ValueError('Configuration request too large')
                            bridge.apply_configuration(json.loads(self.rfile.read(length)))
                        return self.reply(200, bridge.configuration())
                    if route == '/sweep/start':
                        return self.reply(200, bridge.sweep_start())
                    if route == '/sweep/stop':
                        return self.reply(200, bridge.sweep_stop())
                    if route == '/bias':
                        return self.reply(200, {'A': False})
                    if route == '/calibration':
                        return self.reply(409, {'error': 'Automatic calibration requires IQ and is unavailable in spectrum-only modes'})
                    return self.reply(404, {'error': 'Not found'})
                except (ValueError, TypeError) as exc:
                    return self.reply(400, {'error': str(exc)})

            do_GET = do_POST = handle_request

        self.server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self.server.server_address[1]

    def shutdown(self):
        self.running = False
        self.wake.set()
        if self.thread:
            self.thread.join(timeout=8)
        if self.server:
            self.server.shutdown()
            self.server.server_close()


def main():
    bridge = Bridge()
    port = bridge.serve(int(os.environ.get('RTL_BRIDGE_PORT', '8088')))
    print('[SOAPY] READY bridge=127.0.0.1:%d mode=%s' % (port, bridge.profile['mode']), flush=True)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    if os.environ.get('RTL_START_SWEEP') == '1':
        bridge.sweep_start()
    try:
        stopped.wait()
    finally:
        bridge.shutdown()


if __name__ == '__main__':
    main()
