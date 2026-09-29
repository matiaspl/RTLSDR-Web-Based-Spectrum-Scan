# Repository Guidelines

## Project Structure & Module Organization

`server.js` contains the Node.js HTTP server, REST endpoints, and embedded dashboard HTML, CSS, and JavaScript. The Python modules in `engine/` handle AD600 discovery, protocol framing, the hardware session, and the bridge to Node. `vendor/chart.umd.min.js` is the bundled chart library for offline use; `Screenshots/` contains README imagery. The macOS and Windows launchers are `start_mac.command` and `start_windows.bat`. There is currently no dedicated test directory.

## Build, Test, and Development Commands

- `npm start` (or `node server.js`) starts the dashboard at `http://localhost:8080` with Node.js 16+ and Python 3.8+ installed. There is no build step or npm dependency install requirement.
- `./start_mac.command` or `start_windows.bat` checks local prerequisites, launches the server, and opens a browser.
- `node --check server.js` checks JavaScript syntax without starting network discovery.
- `python3 -m compileall -q engine` checks Python syntax; remove generated `__pycache__/` directories if needed (they are gitignored).

## Coding Style & Naming Conventions

Follow the style of the file you edit: two-space indentation and `camelCase` functions in JavaScript; four-space indentation, `snake_case` functions, and module docstrings in Python. Keep AD600 environment variables and protocol constants in their existing `UPPER_SNAKE_CASE` form. Keep UI changes in the embedded dashboard in `server.js` and protocol changes in `engine/`. No formatter or linter is configured.

## Testing Guidelines

There is no automated test runner or coverage target. Run the syntax checks above and manually verify affected dashboard controls and API responses. For discovery, scan, RBW, range, or antenna changes, record whether behavior was checked against a physical AD600; a local server launch alone does not establish hardware behavior. Add focused tests when introducing logic that can be exercised without a device, using names such as `test_<behavior>.py`.

## Commit & Pull Request Guidelines

Recent commits use short imperative subjects (for example, `Add project motivation` and `Sync improvements`). Keep commits focused and describe the user-visible or protocol change. Pull requests should summarize the change, list validation performed, identify any hardware checks still pending, and include screenshots for dashboard changes.

## Network & Configuration

The dashboard listens on TCP port 8080 and can control the AD600 from other devices on the LAN by default. For host-only controls, launch with `AD600_REMOTE_CONTROL=0 node server.js`. Avoid committing local logs, command files, or device-specific network values.
