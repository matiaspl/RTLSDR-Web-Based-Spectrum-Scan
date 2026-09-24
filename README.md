# RTL-SDR Web Spectrum Scanner

A browser dashboard for viewing live RF spectrum from an RTL-SDR receiver exposed over the
`rtl_tcp` protocol. The Node.js server serves the dashboard; a Python backend tunes across the
selected frequency span, computes FFT power bins, and sends completed sweeps to the browser.

The dashboard is designed for several viewers on the same LAN. Only the server needs to reach the
RTL-SDR node.

## Features

- Continuous sweeps or a single sweep snapshot.
- Manage up to six `rtl_tcp` receivers total, mapped to the original AD600 antenna slots and colors.
- Choose an independent frequency preset or custom scan span for each receiver.
- Frequency ranges from 24 MHz to 1766 MHz for the tested R820T tuner.
- Selectable 50, 100, 350, or 900 kHz output-bin width.
- Clear-write, max-hold, min-hold, and average traces.
- Browser access from desktop, tablet, or phone.

Signal levels are shown in **dBFS** (relative to the receiver's ADC full scale). The app does not
calibrate absolute power in dBm.

## Start the App

Requirements: Node.js 16+ and Python 3.8+. The backend uses only the Python standard library.

```sh
node server.js
```

Open [http://localhost:8080](http://localhost:8080), enable one or more receivers in the
`rtl_tcp Receiver Clients` list, then start a sweep. The default receiver uses
`127.0.0.1:1234` unless you set `RTL_TCP_HOST` and `RTL_TCP_PORT`.

Configure another node with environment variables:

```sh
RTL_TCP_HOST=rtl-sdr.local RTL_TCP_PORT=1234 node server.js
```

The scanner defaults to a sample rate of `1800000` samples/s, manual tuner gain of `25` dB,
and both tuner AGC and digital AGC disabled. Override these with `RTL_SAMPLE_RATE`,
`RTL_TUNER_GAIN_DB`, `RTL_TUNER_AGC=1`, or `RTL_DIGITAL_AGC=1` when needed. Set
`RTL_REMOTE_CONTROL=0` to make browser controls available only on the server computer.

Each receiver must run its own `rtl_tcp` server and allow one connection from the app host. The app
opens one client connection for each enabled receiver, then sets the sample rate and tuner frequency
through each server's command stream. Do not add the same host and port more than once. Enabled
receivers scan together with their own frequency spans and the shared bin width. Their spans and
receiver profiles are saved in `~/.rtl_tcp_spectrum_scanner/clients.json`; profiles start disabled
when the app restarts.

## How Scans Work

The backend captures 4096 complex I/Q samples at each tuner position, applies a Hann window, and
computes a radix-2 FFT. It combines FFT power into the selected output-bin width and steps through
the requested range. A sweep covers the complete configured range; wide spans take longer because
the tuner must retune between segments. The receiver's sample rate and tuner hardware limit the
capture bandwidth and sensitivity.

Continuous mode repeats complete sweeps until stopped; Single mode captures one complete sweep.
The chart updates when a sweep finishes. Each antenna shows progress, tuner frequency, and elapsed
time while scanning. The backend drains incoming IQ during FFT processing and waits 100 ms after
each retune before collecting a fresh frame. `RTL_SETTLE_MS` can override this delay (10–2000 ms).
rtl_tcp does not acknowledge tuning or timestamp IQ, so the required delay depends on the receiver
and network. The default 54 MHz span requires 38 tuner positions at 1.8 MS/s, plus processing time.

The frequency range presets are convenience values. Manual scan ranges are limited to 24 MHz
through 1766 MHz, which match the R820T test node. Adjust those limits before using a different
tuner model with a different tuning range.

## Network Access

The dashboard listens on TCP port `8080`. Other devices can open `http://<server-ip>:8080` when
they share a network with the server. The server connects outward to the configured rtl_tcp host
and port; no incoming RTL-SDR connection to the dashboard computer is required.

By default, browsers on the LAN can operate the scanner. Use `RTL_REMOTE_CONTROL=0` to make them
view-only while keeping controls enabled on the server computer.

## Project Structure

- `server.js`: Node.js HTTP server, dashboard, and API.
- `engine/rtl_tcp_backend.py`: rtl_tcp client, FFT scanner, and local trace bridge.
- `vendor/chart.umd.min.js`: bundled Chart.js for offline dashboard use.
- `start_mac.command` and `start_windows.bat`: launch helpers.

The earlier AD600 protocol modules remain in `engine/` for reference. The dashboard uses the
rtl_tcp backend.

## Validation

Syntax checks:

```sh
node --check server.js
python3 -m py_compile engine/rtl_tcp_backend.py
python3 -m unittest discover -s tests -v
node tests/test_sweep_restart.js
```

The regression checks use synthetic IQ and a localhost rtl_tcp simulator. They cover continuous
and single sweeps, restart cancellation, band coverage, upper-limit tuning, IQ buffering, and
configuration-before-start ordering. They do not establish physical receiver tuning performance.

For hardware validation, connect to the configured rtl_tcp node, start a scan, and confirm that
the bridge returns a trace with `unit: "dBFS"` and the configured frequency grid.

## License

This project is licensed under the [MIT License](LICENSE).
