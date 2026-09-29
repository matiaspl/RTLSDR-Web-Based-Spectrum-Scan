#!/usr/bin/env python3
"""Synthetic upstream-format spectrum producer; never opens a receiver."""
import math
import os
from pathlib import Path
import sys
import time

args = sys.argv[1:]
def option(key, default=None):
    return args[args.index(key) + 1] if key in args else default

if os.environ.get('FAKE_SOAPY_PID_FILE'):
    Path(os.environ['FAKE_SOAPY_PID_FILE']).write_text(str(os.getpid()))
behavior = os.environ.get('FAKE_SOAPY_BEHAVIOR', '')
if 'serial=FAIL' in option('-d', ''):
    behavior = 'failure'
if behavior == 'failure':
    print('No matching RTL-SDR device', file=sys.stderr, flush=True)
    sys.exit(2)
if behavior == 'stall':
    time.sleep(90)
    sys.exit(0)
if behavior == 'malformed':
    print('470000000 nan', flush=True)
    time.sleep(90)
    sys.exit(0)
start, stop = map(float, option('-f').split(':'))
rate = float(option('-r'))
bins = int(option('-b'))
spacing = rate / bins
crop_half = math.ceil(.2 * bins / 2)
count = bins - 2 * crop_half
width = count * spacing
hops = math.ceil((stop - start) / width)
# Match upstream centering for spans narrower than the cropped bandwidth.
left = start if hops > 1 else (start + stop - width) / 2
while True:
    for hop in range(hops):
        print('# soapy_power output')
        print('# Acquisition start: 2026-09-29 10:00:00')
        print('# Acquisition end: 2026-09-29 10:00:01')
        print('#')
        print('# frequency [Hz] power spectral density [dB/Hz]')
        for i in range(count):
            frequency = left + hop * width + i * spacing
            power = -45 if i == count // 2 else -100
            print('%s %s' % (frequency, power))
        print('', flush=True)
        time.sleep(.08)
        if behavior == 'truncated':
            sys.exit(0)
    print('', flush=True)
    if '-u' in args:
        break
