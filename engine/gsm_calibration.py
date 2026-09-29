# Copyright (c) 2010, Joshua Lackey
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     *  Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#
#     *  Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""GSM900 FCCH calibration over captured IQ; no USB or third-party dependencies.

Adaptive line enhancer and interpolated FFT peak adapted from kalibrate-rtl's
fcch_detector.cc (Joshua Lackey, 2010), commit
340003eb0846b069c3edef19ed3363b8ac7b5215. BSD notice: vendor/kalibrate-rtl/COPYING.
The transport, validation, bounded burst detection and multi-channel consensus are local.
"""
import math
import statistics

GSM_RATE = 1625000 / 6
SAMPLE_RATE = 270833
TONE_HZ = GSM_RATE / 4
FRAME_SAMPLES = 16384  # >12 GSM frames, including a complete FCCH burst
CHANNELS = [(n, 935000000 + n * 200000) for n in range(125)] + [
    (n, 935000000 + (n - 1024) * 200000) for n in range(975, 1024)]


def _interpolate(values, position):
    total = 0j
    for i in range(max(0, math.floor(position) - 10), min(len(values), math.floor(position) + 12)):
        x = math.pi * (i - position)
        total += values[i] * (math.sin(x) / x if abs(x) > 0.0001 else 1)
    return total


def fcch_offsets(raw, fft, sample_rate=SAMPLE_RATE):
    """Return offsets for bounded pure-tone bursts; reject CW, clipping and noise.

    Like kalibrate, compare normalized adaptive-filter error with its block mean,
    then refine each candidate using an interpolated 1024-point FFT. Unlike the
    CLI, reject overlong tones and return every valid burst in this block.
    """
    if len(raw) != FRAME_SAMPLES * 2:
        raise ValueError('Incomplete GSM IQ block')
    if sum(v <= 1 or v >= 254 for v in raw) > len(raw) * 0.005:
        return []
    samples = [complex(raw[i] - 127.5, raw[i+1] - 127.5) / 128 for i in range(0, len(raw), 2)]
    weights = [0j] * 17
    errors = []
    smoothed, gain = 0.0, 1 / 12.5
    delay = 24
    for index in range(delay, len(samples)):
        x = samples[index-delay:index-7][::-1]
        energy = sum(v.real*v.real + v.imag*v.imag for v in x)
        if energy < 1e-12:
            errors.append(1.0)
            continue
        if gain >= 2 / energy:
            gain = 1 / energy
        predicted = sum(w.conjugate() * v for w, v in zip(weights, x))
        error = samples[index] - predicted
        gradient = gain * error.conjugate()
        weights = [w + gradient*v for w, v in zip(weights, x)]
        smoothed = (31 * smoothed + abs(error)**2) / 32
        errors.append(smoothed / (energy / 17))
    threshold = 0.7 * statistics.mean(errors)
    start = None
    offsets = []
    sps = sample_rate / GSM_RATE
    for index, error in enumerate(errors):
        if error <= threshold:
            if start is None:
                start = index
            continue
        if start is None:
            continue
        length = index-start
        if 90*sps <= length <= 210*sps and start > 0:
            # Error smoothing delays the falling edge; use the stable middle.
            begin = start + delay
            tone = samples[begin:begin + min(int(100*sps), length)]
            spectrum = fft(tone + [0j] * (1024 - len(tone)))
            powers = [abs(v)**2 for v in spectrum]
            peak = max(range(1024), key=powers.__getitem__)
            if powers[peak] / max((sum(powers)-powers[peak])/1023, 1e-12) > 50:
                early, step = float(peak-1), 0.5
                while step > 1/1024:
                    a, b = abs(_interpolate(spectrum, early)), abs(_interpolate(spectrum, early+2))
                    early += step if a < b else -step
                    step /= 2
                frequency = (early+1) * sample_rate / 1024
                offset = frequency - TONE_HZ
                if abs(offset) < 40000:
                    offsets.append(offset)
        start = None
    return offsets


def channel_summary(arfcn, frequency, offsets, base_ppm, minimum_bursts=30):
    ordered = sorted(offsets)
    if len(ordered) < minimum_bursts:
        return None
    trim = len(ordered) // 10
    clean = ordered[trim:-trim]
    residual = statistics.mean(clean)
    spread = statistics.stdev(clean)
    # Include full (untrimmed) scatter so competing tones cannot be hidden by trimming.
    uncertainty = max(2*spread/math.sqrt(len(clean)), statistics.stdev(ordered), frequency*0.05e-6)
    return {'arfcn': arfcn, 'referenceHz': frequency, 'bursts': len(offsets),
            'residualHz': round(residual, 2), 'uncertaintyPpm': round(uncertainty/frequency*1e6, 4),
            'estimatedPpm': round(base_ppm-residual/frequency*1e6, 4)}


def consensus(channels, base_ppm):
    good = [c for c in channels if c['uncertaintyPpm'] <= 0.35]
    if len(good) < 2:
        raise ValueError('Need two stable GSM channels. Try a better 900 MHz antenna or a rough FM correction first.')
    estimates = [c['estimatedPpm'] for c in good]
    estimate = statistics.mean(estimates)
    uncertainty = max(max(c['uncertaintyPpm'] for c in good), (max(estimates)-min(estimates))/2)
    suggested = round(estimate)
    can_apply = uncertainty <= 0.35 and -1000 <= suggested <= 1000
    return {'channels': channels, 'estimatedPpm': round(estimate, 4), 'suggestedPpm': suggested,
            'basePpm': base_ppm, 'uncertaintyPpm': round(uncertainty, 4), 'canApply': can_apply,
            'message': ('GSM channels agree. Apply saves the nearest whole ppm; measure again to verify.' if can_apply else
                        'GSM channels disagree; correction was not applied.')}


def verified_setting(measurements):
    """Choose the integer with the smallest measured RMS error across the same references."""
    if len(measurements) < 2:
        raise ValueError('Could not verify neighboring PPM settings; try again.')
    references = {c['referenceHz'] for c in measurements[0]['channels']}
    for result in measurements:
        if len(references) < 2 or {c['referenceHz'] for c in result['channels']} != references:
            raise ValueError('PPM verification needs the same reference channels at each setting.')
        if any(c['uncertaintyPpm'] > 0.35 for c in result['channels']):
            raise ValueError('Unstable GSM bursts during PPM verification; try again.')
        residuals = [c['residualHz']/c['referenceHz']*1e6 for c in result['channels']]
        result['rmsResidualPpm'] = round(math.sqrt(statistics.mean(v*v for v in residuals)), 4)
    best = min(measurements, key=lambda result: result['rmsResidualPpm'])
    if best['rmsResidualPpm'] > 1.5:
        raise ValueError('Remaining frequency error is too large; use another reference or warm up longer.')
    return best
