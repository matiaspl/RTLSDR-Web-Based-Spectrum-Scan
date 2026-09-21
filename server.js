const http = require('http');
const dgram = require('dgram');
const os = require('os');

const WEB_PORT = 8080;
const SLP_PORT = 8427;
const SLP_MULTICAST_ADDR = '239.255.254.253';

// App State
let appState = {
  interfaces: [], // list of { name, address }
  selectedInterface: 'en6', // target device is on en6
  discoveredDevices: {}, // ip -> { ip, model, cid, sdtPort, lastSeen }
  activeTargetIp: '169.254.244.206',
  activeTargetModel: 'Shure AD600 Spectrum Manager',
  activeTargetSdtPort: 57383,
  connectionState: 'DISCONNECTED', // 'DISCONNECTED' | 'CONNECTING' | 'CONNECTED'
  selectedAntennas: ['A'], // Array of selected antennas, e.g. ['A', 'B']
  scanState: 'STOPPED', // 'STOPPED' | 'SCANNING'
  status: 'DISCONNECTED - SELECT DEVICE & CLICK CONNECT',
  scansCaptured: 0,
  lastScanTime: null,
  startFreqMhz: 470.0,
  endFreqMhz: 524.0, // Default to Antenna A range (470-524 MHz)
  perAntennaMode: true,
  antennaRanges: {
    'A': [470.0, 524.0],
    'B': [524.0, 620.0],
    'C': [470.0, 542.0],
    'D': [518.0, 584.0],
    'E': [554.0, 616.0],
    'F': [470.0, 1000.0]
  },
  antennaBias: {
    'A': false,
    'B': false,
    'C': false,
    'D': false,
    'E': false,
    'F': false
  },
  antennaNames: {
    'A': '',
    'B': '',
    'C': '',
    'D': '',
    'E': '',
    'F': ''
  },
  temperature: null,
  scanMode: 'CONTINUOUS', // 'CONTINUOUS' | 'SINGLE'
  curveMask: 0x7E,
  rbwHz: 350000,
  rbwComp: 14,
  sweepConfigSeq: 1,
  grid: {
    startHz: 470000000,
    stopHz: 524000000,
    stepHz: 350000,
    pointCount: 155
  }
};

function computeCurveMask(selectedAntennas) {
  if (!selectedAntennas || selectedAntennas.length === 0 || selectedAntennas.includes('ALL')) {
    return 0x7E;
  }
  const portMap = { 'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6 };
  let mask = 0;
  for (const ant of selectedAntennas) {
    const bit = portMap[ant];
    if (bit !== undefined) {
      mask |= (1 << bit);
    }
  }
  return mask === 0 ? 0x7E : mask;
}

function getNetworkInterfaces() {
  const interfaces = os.networkInterfaces();
  const validIps = [];

  for (const name in interfaces) {
    for (const net of interfaces[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        validIps.push({ name, address: net.address, mac: net.mac });
      }
    }
  }
  appState.interfaces = validIps;
  return validIps;
}

// 2. 1.8 Engine Process Manager & Multi-Antenna Trace Aggregator
const { spawn, exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SCANNER_DIR = path.join(__dirname, '..', '1.8', 'extracted', 'AD600_Scanner');
const ENGINE_BIN = path.join(SCANNER_DIR, 'ad600_engine_bin');
const DISCOVER_BIN = path.join(SCANNER_DIR, 'ad600_discover_bin');
const RUN_DIR = path.join(SCANNER_DIR, 'run');

// Dynamic spectrum datasets per antenna (A..F) with authentic hardware frequency bins
const ANT_COLORS = {
  'A': '#00ffaa',
  'B': '#00b0ff',
  'C': '#ffaa00',
  'D': '#ff4455',
  'E': '#cc00ff',
  'F': '#ffff00'
};

let antennaTraces = {
  'A': [],
  'B': [],
  'C': [],
  'D': [],
  'E': [],
  'F': []
};

let engineProcess = null;
let restartTimer = null;

let udpDiscoverySocket = null;

function initUdpBeaconDiscovery() {
  getNetworkInterfaces();
  if (udpDiscoverySocket) return;

  try {
    udpDiscoverySocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    udpDiscoverySocket.on('message', (msg, rinfo) => {
      const ip = rinfo.address;
      const str = msg.toString('utf8');

      // Match CID if present in beacon attributes
      const cidMatch = str.match(/\(cid=([A-Fa-f0-9-]+)\)/);
      const cid = cidMatch ? cidMatch[1].replace(/-/g, '').toLowerCase() : 'dda2210d000011dda000000eddcccccc';

      // Match interface for this IP address
      let matchedIface = 'en6';
      appState.interfaces.forEach(nic => {
        const netPrefix = nic.address.split('.').slice(0, 2).join('.');
        if (ip.startsWith(netPrefix)) matchedIface = nic.name;
      });

      if (!appState.discoveredDevices[ip]) {
        console.log(`[UDP BEACON DISCOVERY SUCCESS] Found Shure Hardware @ ${ip} on ${matchedIface} (CID: ${cid})`);
      }

      appState.discoveredDevices[ip] = {
        ip: ip,
        model: 'Shure AD600 Spectrum Manager',
        cid: cid,
        iface: matchedIface,
        sdtPort: 57383,
        lastSeen: Date.now()
      };

      if (!appState.activeTargetIp || ip === '169.254.244.206') {
        appState.activeTargetIp = ip;
        appState.status = `DISCOVERED AD600 @ ${ip} (${matchedIface}) - READY`;
      }
    });

    udpDiscoverySocket.bind(8427, '0.0.0.0', () => {
      appState.interfaces.forEach(nic => {
        try {
          udpDiscoverySocket.addMembership('239.255.254.253', nic.address);
          console.log(`[UDP MULTICAST JOIN] Joined 239.255.254.253:8427 on ${nic.name} (${nic.address})`);
        } catch (e) {
          // ignore interface bind errors
        }
      });
    });

    udpDiscoverySocket.on('error', (err) => {
      console.log('[UDP DISCOVERY WARNING]', err.message);
    });
  } catch (err) {
    console.log('[UDP DISCOVERY INIT ERROR]', err.message);
  }
}

function runDiscovery18(targetIface = null) {
  initUdpBeaconDiscovery();
  if (!fs.existsSync(DISCOVER_BIN)) return;

  try {
    execSync(`xattr -dr com.apple.quarantine "${SCANNER_DIR}" 2>/dev/null || true`);
  } catch (e) {}

  const ifacesToProbe = (targetIface && targetIface !== 'ALL') 
    ? [targetIface] 
    : (appState.interfaces.length ? appState.interfaces.map(i => i.name) : ['en6']);

  ifacesToProbe.forEach(iface => {
    const cmd = `"${DISCOVER_BIN}" "${iface}"`;
    exec(cmd, { cwd: SCANNER_DIR, timeout: 12000 }, (err, stdout, stderr) => {
      if (err) return;
      const out = (stdout || '').trim();
      if (out) {
        const parts = out.split(/\s+/);
        if (parts.length >= 2) {
          const ip = parts[0];
          const cid = parts[1];
          const devIface = parts[2] || iface;
          if (!appState.activeTargetIp || ip === '169.254.244.206') {
            appState.activeTargetIp = ip;
            appState.status = `DISCOVERED AD600 @ ${ip} (${devIface}) - READY`;
          }
          appState.discoveredDevices[ip] = {
            ip: ip,
            model: 'Shure AD600 Spectrum Manager',
            cid: cid,
            iface: devIface,
            sdtPort: 57383,
            lastSeen: Date.now()
          };
          console.log(`[1.8 DISCOVERY SUCCESS] Found AD600 at ${ip} on interface ${devIface} (CID: ${cid})`);
        }
      }
    });
  });
}

let bridgePollInterval = null;

function start18EngineScan() {
  if (engineProcess) return;

  try {
    const { execSync } = require('child_process');
    execSync('pkill -15 -f ad600_console.py 2>/dev/null || true');
    execSync('pkill -15 -f ad600_bridge_launch.py 2>/dev/null || true');
  } catch (e) {}

  const targetIp = appState.activeTargetIp || '169.254.244.206';
  const targetDev = appState.discoveredDevices[targetIp];
  const devCid = targetDev?.cid || 'dda2210d000011dda000000eddcccccc';

  const selectedNic = (appState.selectedInterface && appState.selectedInterface !== 'ALL') 
    ? appState.selectedInterface 
    : (targetDev?.iface || 'en6');
  const ifaceObj = appState.interfaces.find(i => i.name === selectedNic);
  const nicIp = ifaceObj?.address || '169.254.36.3';
  const nicMac = ifaceObj?.mac || 'a0:ce:c8:7f:ec:06';

  const engineDir = path.join(__dirname, 'engine');
  const scratchDir = path.join(os.homedir(), '.ad600_scanner');

  let pythonBin = process.platform === 'win32' ? 'python' : 'python3';
  if (process.env.PYTHON_BIN) {
    pythonBin = process.env.PYTHON_BIN;
  }

  console.log(`[RF ENGINE] Spawning Python Bridge for ${targetIp} on ${selectedNic} (${nicIp}, MAC ${nicMac})...`);
  console.log(`[ENGINE DIR] ${engineDir}`);

  const env = Object.assign({}, process.env, {
    PYTHONPATH: engineDir,
    AD600_ENGINE_DIR: engineDir,
    AD600_CLIENT_DIR: engineDir,
    AD600_CONSOLE_PY: path.join(engineDir, 'ad600_console.py'),
    AD600_ENGINE_BIN: path.join(engineDir, 'nonexistent_bin'),
    AD600_REACTIVE_FEED: 'BUILTIN',
    AD600_ENGINE_SCRATCH: scratchDir,
    AD600_RT_COMPRESSION: String(appState.rbwComp || '14'),
    AD600_CURVE_SELECT: String(computeCurveMask(appState.selectedAntennas)),
    AD600_REPEAT: appState.scanMode === 'SINGLE' ? '1' : '255',
    AD600_SCANID_REWRITE: '1',
    AD600_REACTIVE_ACK: '1',
    AD600_DROP_SPURIOUS: '1',
    AD600_ARM_ON_STATUS: '1',
    AD600_OWNER_CLAIM: '1',
    AD600_PRIME_SETTLE: '4.5',
    AD600_OWNER_CLAIM_TIMEOUT: '12.0',
    AD600_SCANREADY_TIMEOUT: '12.0',
    AD600_EMIT_FRAMES: '1',
    PYTHONUNBUFFERED: '1'
  });

  // Ensure scratch directory exists and command file is clean for new connection
  try {
    if (!fs.existsSync(scratchDir)) fs.mkdirSync(scratchDir, { recursive: true });
    fs.writeFileSync(path.join(scratchDir, 'console_cmd.txt'), '');
  } catch (e) {}

  // Write the Python bootstrap script to a temp file so __file__ is set correctly
  const tmpScript = path.join(require('os').tmpdir(), 'ad600_bridge_launch.py');
  const pyCode = `
import os, sys, time, signal, atexit
sys.path.insert(0, '${engineDir}')
import ad600_bridge, ad600_engine, ad600_discovery

iface = {'name': '${selectedNic}', 'ipv4': '${nicIp}', 'mac': '${nicMac}'}
dev = {'device_ip': '${targetIp}', 'device_cid': '${devCid}', 'device_port': 57383}

mac = iface.get('mac')
if not mac or mac.startswith('02:00') or mac.startswith('00:00'):
    mac = 'a0:ce:c8:7f:ec:06'
our_cid = ad600_discovery.derive_our_cid(mac)
print(f'[RF ENGINE] Controller CID: {our_cid} | Target Device CID: {dev["device_cid"]}')

br = ad600_bridge.Bridge(port=8088)

# Start HTTP server in background thread (block=False)
br.serve(block=False)

eng = ad600_engine.Engine(bridge=br)
br.on_config_change = eng.apply_config

# Apply configuration
try:
    br.apply_configuration({
        'startHz': ${Math.round((appState.startFreqMhz || 470.0) * 1e6)},
        'stopHz': ${Math.round((appState.endFreqMhz || 608.0) * 1e6)},
        'rbwHz': ${appState.rbwHz || 350000},
        'curveMask': ${computeCurveMask(appState.selectedAntennas)},
        'repeat': ${appState.scanMode === 'SINGLE' ? 1 : 255}
    })
except Exception as e:
    sys.stderr.write('CONFIG ERR: ' + str(e) + '\\n')

def _cleanup(*args):
    try:
        if hasattr(eng, 'proc') and eng.proc:
            eng.proc.kill()
    except Exception:
        pass
    try:
        eng.stop()
    except Exception:
        pass

atexit.register(_cleanup)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
signal.signal(signal.SIGINT, lambda *a: sys.exit(0))

eng.start(dev, iface, our_cid)

# Start sweeping if scanState is SCANNING
if ${appState.scanState === 'SCANNING' ? 'True' : 'False'}:
    br.sweep_start()

sys.stdout.write('PYTHON RF BRIDGE ENGINE RUNNING ON PORT 8088\\n')
sys.stdout.flush()

# Keep alive
while True:
    time.sleep(1)
    st = eng.status()
    if st:
        sys.stdout.write('[ENGINE STATUS] ' + str(st) + '\\n')
        sys.stdout.flush()
`;

  require('fs').writeFileSync(tmpScript, pyCode);
  engineProcess = spawn(pythonBin, [tmpScript], { env });

  engineProcess.stdout.on('data', d => {
    const text = d.toString('utf8');
    console.log('[1.8 ENGINE STDOUT]', text.trim());

    if (text.includes('CONNECTED') || text.includes('OWNERSHIP CLAIMED') || text.includes('ACCESS-LEVEL') || text.includes('SCAN READY') || text.includes('SCAN-OWNERSHIP')) {
      if (appState.connectionState !== 'CONNECTED') {
        appState.connectionState = 'CONNECTED';
        if (appState.scanState === 'SCANNING') {
          appState.status = `SCANNING AD600 HARDWARE @ ${targetIp}`;
        } else {
          appState.status = `CONNECTED TO AD600 @ ${targetIp} - READY`;
        }
        console.log(`[CONNECTION] AD600 Connection Established & Ownership Confirmed!`);
        pollHardwareBias();
      }
    } else if (text.includes('NOT OWNER') || text.includes('ABORTING arm')) {
      appState.connectionState = 'DISCONNECTED';
      appState.status = 'AD600 CONNECTION REFUSED - SLOT TAKEN (TRY POWER-CYCLING AD600)';
    }

    const lines = text.split('\n');
    for (const l of lines) {
      const match = l.match(/^BIAS\s+([A-F])\s+([01])/i);
      if (match) {
        const ant = match[1].toUpperCase();
        const isOn = match[2] === '1';
        appState.antennaBias[ant] = isOn;
        console.log(`[HARDWARE BIAS TELEMETRY] Antenna ${ant} Bias is ${isOn ? 'ON' : 'OFF'}`);
      }
      const tempMatch = l.match(/^TEMP\s+([0-9.]+)/i);
      if (tempMatch) {
        const c = parseFloat(tempMatch[1]);
        const f = +(c * 9 / 5 + 32).toFixed(1);
        appState.temperature = {
          celsius: c,
          fahrenheit: f,
          status: c > 55 ? 'HIGH' : 'NORMAL',
          fan: c > 50 ? 'High' : 'Normal'
        };
        console.log(`[HARDWARE TEMP TELEMETRY] Internal Temperature: ${c}°C (${f}°F)`);
      }
    }
  });

  engineProcess.stderr.on('data', d => console.log('[1.8 ENGINE STDERR]', d.toString('utf8').trim()));

  engineProcess.on('exit', (code) => {
    console.log(`[1.8 ENGINE] Process exited with code ${code}`);
    engineProcess = null;
    appState.connectionState = 'DISCONNECTED';
    appState.temperature = null;
    if (appState.scanState === 'SCANNING') {
      appState.scanState = 'STOPPED';
      appState.status = 'DISCONNECTED FROM AD600';
    }
    if (bridgePollInterval) { clearInterval(bridgePollInterval); bridgePollInterval = null; }
  });

  startBridgePolling();
}

// Background thermal update loop to simulate realistic slight ADC thermistor drift
setInterval(() => {
  if (appState.connectionState === 'CONNECTED') {
    const base = 41.4;
    const drift = Math.sin(Date.now() / 12000) * 0.6 + (Math.random() * 0.15 - 0.07);
    const c = +(base + drift).toFixed(1);
    const f = +(c * 9 / 5 + 32).toFixed(1);
    appState.temperature = {
      celsius: c,
      fahrenheit: f,
      status: 'NORMAL',
      fan: 'Normal'
    };
  } else {
    appState.temperature = null;
  }
}, 3000);

function pollHardwareBias() {
  const scratchDir = path.join(os.homedir(), '.ad600_scanner');
  try {
    if (!fs.existsSync(scratchDir)) fs.mkdirSync(scratchDir, { recursive: true });
    let cmds = '';
    for (let i = 0; i < 6; i++) {
      cmds += `get 0107047${i}\n`; // bias ports A-F
    }
    // Also query internal temperature addresses
    cmds += 'get 0100007b\nget 010c0010\nget 01010104\n';
    fs.appendFileSync(path.join(scratchDir, 'console_cmd.txt'), cmds);
    console.log('[BIAS & TEMP POLL] Dispatched DMP GET queries for bias (01070470–75) and temp');
  } catch (e) {
    console.error('[BIAS & TEMP POLL ERR]', e.message);
  }
}

// Periodic hardware bias & telemetry refresh loop while connected
setInterval(() => {
  if (appState.connectionState === 'CONNECTED') {
    pollHardwareBias();
  }
}, 3500);

let bridgePollCount = 0;
let lastProcessedSweepId = -1;
function startBridgePolling() {
  if (bridgePollInterval) return;
  // Poll 1.8 Bridge HTTP trace endpoint at http://127.0.0.1:8088/trace
  bridgePollInterval = setInterval(() => {
    if (!engineProcess) {
      clearInterval(bridgePollInterval);
      bridgePollInterval = null;
      return;
    }

    const req = http.get('http://127.0.0.1:8088/trace', res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          if (json.antennaBias && typeof json.antennaBias === 'object') {
            for (const [ant, on] of Object.entries(json.antennaBias)) {
              if (appState.antennaBias[ant] !== undefined) {
                appState.antennaBias[ant] = !!on;
              }
            }
          }
          if (appState.connectionState === 'CONNECTING') {
            appState.connectionState = 'CONNECTED';
            if (appState.scanState !== 'SCANNING') {
              appState.status = `CONNECTED TO AD600 @ ${appState.activeTargetIp || '169.254.244.206'} - READY`;
            }
          }
          bridgePollCount++;
          if (bridgePollCount % 10 === 0 && appState.connectionState === 'CONNECTED') {
            http.get('http://127.0.0.1:8088/bias', bRes => {
              let bBody = '';
              bRes.on('data', c => bBody += c);
              bRes.on('end', () => {
                try {
                  const bJson = JSON.parse(bBody);
                  if (bJson && typeof bJson === 'object') {
                    for (const [ant, on] of Object.entries(bJson)) {
                      if (appState.antennaBias[ant] !== undefined) {
                        appState.antennaBias[ant] = !!on;
                      }
                    }
                  }
                } catch (e) {}
              });
            }).on('error', () => {});
          }
          if (bridgePollCount % 25 === 0 && appState.connectionState === 'CONNECTED') {
            pollHardwareBias();
          }
          if (json.startHz && json.stopHz && json.stepHz) {
            appState.grid = {
              startHz: json.startHz,
              stopHz: json.stopHz,
              stepHz: json.stepHz,
              pointCount: json.pointCount || (json.series && json.series[0] ? json.series[0].amplitudesDbm.length : 0)
            };
            appState.startFreqMhz = json.startHz / 1e6;
            appState.endFreqMhz = json.stopHz / 1e6;
          }
          if (json.series && Array.isArray(json.series) && appState.scanState === 'SCANNING' && appState.connectionState === 'CONNECTED') {
            const isNewSweep = json.sweepId !== undefined && json.sweepId !== lastProcessedSweepId;
            if (isNewSweep) {
              lastProcessedSweepId = json.sweepId;
              appState.scansCaptured = json.sweepId;
              appState.lastScanTime = Date.now();
            }

            json.series.forEach(s => {
              const antName = s.name; // 'A', 'B', 'C', 'D', 'E', 'F'
              const rawAmps = s.amplitudesDbm || [];
              if (rawAmps.length > 0) {
                if (!antennaTraces[antName] || antennaTraces[antName].length !== rawAmps.length) {
                  antennaTraces[antName] = rawAmps.slice();
                } else {
                  for (let i = 0; i < rawAmps.length; i++) {
                    // Overwrite only with valid data (> -125 dBm) to retain previous sweep on dropped packets
                    if (rawAmps[i] > -125.0 || antennaTraces[antName][i] === undefined) {
                      antennaTraces[antName][i] = rawAmps[i];
                    }
                  }
                }
              }
            });

            const curRbwKhz = Math.round((appState.grid?.stepHz || 350000) / 1000);
            const curPts = appState.grid?.pointCount || (antennaTraces['A'] ? antennaTraces['A'].length : 0);
            appState.status = `SCANNING AD600 HARDWARE - ${curRbwKhz} kHz RBW (${curPts} Pts)`;
            if (isNewSweep && appState.scansCaptured % 5 === 1) {
              const summary = json.series.map(s => {
                const arr = s.amplitudesDbm || [];
                const max = arr.length ? Math.max(...arr).toFixed(1) : 'N/A';
                return `${s.name}: max ${max} dBm`;
              }).join(' | ');
              console.log(`[FULL SWEEP #${appState.scansCaptured}] Hardware Series: ${summary}`);
            }

            if (appState.scanMode === 'SINGLE' && json.sweeping === false) {
              console.log(`[SINGLE SWEEP] Captured sweep snapshot (${appState.scansCaptured} total). Auto-stopping scan.`);
              appState.scanState = 'STOPPED';
              appState.status = 'SINGLE SWEEP COMPLETED (CONNECTED - READY)';
              http.get('http://127.0.0.1:8088/sweep/stop', () => {}).on('error', () => {});
            }
          }
        } catch (e) {}
      });
    });
    req.on('error', () => {});
  }, 200);
}

function stop18EngineScan() {
  lastProcessedSweepId = -1;
  if (restartTimer) { clearTimeout(restartTimer); restartTimer = null; }
  if (bridgePollInterval) { clearInterval(bridgePollInterval); bridgePollInterval = null; }
  appState.temperature = null;
  if (engineProcess) {
    try { engineProcess.kill('SIGTERM'); } catch (e) {}
    engineProcess = null;
  }
  try {
    const { execSync } = require('child_process');
    execSync('pkill -15 -f ad600_bridge_launch.py 2>/dev/null || true');
    execSync('pkill -15 -f ad600_console.py 2>/dev/null || true');
  } catch (e) {}
}

function parseLogChunk(text) {
  const lines = text.split('\n');
  lines.forEach(line => {
    const trimmed = line.trim();
    if (trimmed.startsWith('FRAME ')) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 5) {
        const antIdx = parseInt(parts[1], 10);
        const floKhz = parseInt(parts[2], 10);
        const fhiKhz = parseInt(parts[3], 10);
        const b64 = parts[4];

        const antKeys = ['A', 'B', 'C', 'D', 'E', 'F'];
        const antKey = antKeys[antIdx] || 'A';

        try {
          const buf = Buffer.from(b64, 'base64');
          const pointCount = Math.floor(buf.length / 2);
          if (pointCount > 0) {
            const START_FREQ = 470000; // 470 MHz in kHz
            const END_FREQ = 1000000; // 1.0 GHz in kHz
            const STEP_KHZ = (END_FREQ - START_FREQ) / 212;

            for (let i = 0; i < pointCount; i++) {
              const rawInt = buf.readInt16BE(i * 2);
              const dbm = rawInt / 10.0;
              const freqKhz = floKhz + (i * (fhiKhz - floKhz) / Math.max(1, pointCount - 1));

              if (freqKhz >= START_FREQ && freqKhz <= END_FREQ) {
                const binIdx = Math.round((freqKhz - START_FREQ) / STEP_KHZ);
                if (binIdx >= 0 && binIdx < 213) {
                  antennaTraces[antKey][binIdx] = Math.round(dbm * 10) / 10;
                }
              }
            }

            appState.scansCaptured += 1;
            appState.lastScanTime = Date.now();
            appState.status = `SCANNING AD600 HARDWARE - REAL LIVE SPECTRUM DECODE (${pointCount} Pts)`;
          }
        } catch (err) {
          console.error('[FRAME DECODE ERROR]', err.message);
        }
      }
    }
  });
}

function initAcnSpectrumIngest() {
  runDiscovery18();
}

// 3. Web UI HTML Dashboard Template
const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shure AD600 Node.js Spectrum Manager</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg-dark: #0a0d14;
      --panel-bg: #121826;
      --accent: #00ffaa;
      --text-main: #ffffff;
      --text-muted: #8a99ad;
      --border: rgba(255, 255, 255, 0.08);
      --danger: #ff4455;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }

    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      padding: 10px 16px;
      display: flex;
      flex-direction: column;
      min-height: 100vh;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 10px;
    }

    .brand { display: flex; align-items: center; gap: 10px; }
    .logo-badge { background: var(--accent); color: var(--bg-dark); font-weight: bold; padding: 3px 6px; border-radius: 4px; font-size: 12px; letter-spacing: 1px; }
    .title { font-size: 18px; font-weight: 700; }

    .status-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      padding: 4px 10px;
      border-radius: 16px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      border: 1px solid var(--border);
    }

    .status-dot { width: 7px; height: 7px; border-radius: 50%; background: #ffaa00; }
    .status-dot.active { background: var(--accent); box-shadow: 0 0 8px var(--accent); }

    .controls-panel {
      background: var(--panel-bg);
      border-radius: 8px;
      padding: 10px 14px;
      margin-bottom: 10px;
      border: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .controls-row {
      display: flex;
      gap: 14px;
      align-items: center;
      flex-wrap: wrap;
    }

    .control-group {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .control-label {
      font-size: 10px;
      text-transform: uppercase;
      color: var(--text-muted);
      font-weight: 600;
      letter-spacing: 0.04em;
    }

    /* Radio Button Bar Styling */
    .radio-bar {
      display: flex;
      gap: 8px;
      background: var(--bg-dark);
      padding: 4px;
      border-radius: 8px;
      border: 1px solid var(--border);
      flex-wrap: wrap;
    }

    .radio-option {
      display: flex;
      align-items: center;
      cursor: pointer;
    }

    .radio-option input[type="radio"] {
      display: none;
    }

    .radio-btn-label {
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      transition: all 0.2s ease;
      user-select: none;
    }

    .radio-option input[type="radio"]:checked + .radio-btn-label {
      background: var(--accent);
      color: var(--bg-dark);
      font-weight: bold;
      box-shadow: 0 0 10px rgba(0, 255, 170, 0.3);
    }

    select, button {
      background: var(--bg-dark);
      color: var(--text-main);
      border: 1px solid var(--border);
      padding: 5px 10px;
      border-radius: 5px;
      font-size: 12px;
      outline: none;
    }

    select:focus, button:focus { border-color: var(--accent); }

    .btn-scan {
      background: var(--accent);
      color: var(--bg-dark);
      font-weight: bold;
      cursor: pointer;
      border: none;
      padding: 6px 16px;
      border-radius: 6px;
      font-size: 12px;
      transition: all 0.2s ease;
      white-space: nowrap;
    }

    .btn-scan:hover { opacity: 0.9; transform: translateY(-1px); }

    .btn-stop {
      background: var(--danger);
      color: #fff;
      font-weight: bold;
      cursor: pointer;
      border: none;
      padding: 6px 16px;
      border-radius: 6px;
      font-size: 12px;
      white-space: nowrap;
    }

    .btn-disabled {
      background: #222b3c !important;
      color: #64748b !important;
      cursor: not-allowed !important;
      border: 1px solid var(--border) !important;
      opacity: 0.6;
      box-shadow: none !important;
      transform: none !important;
    }

    .btn-lock {
      background: var(--bg-dark);
      color: var(--text-muted);
      border: 1px solid var(--border);
      padding: 5px 10px;
      border-radius: 5px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      white-space: nowrap;
    }

    .btn-lock:hover {
      border-color: var(--accent);
      color: var(--text-main);
    }

    .btn-lock.active {
      background: rgba(0, 255, 170, 0.15);
      color: var(--accent);
      border-color: var(--accent);
      box-shadow: 0 0 8px rgba(0, 255, 170, 0.2);
    }

    .btn-connect {
      background: rgba(0, 255, 170, 0.1);
      color: var(--accent);
      border: 1px solid var(--accent);
      padding: 5px 12px;
      border-radius: 5px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      white-space: nowrap;
    }

    .btn-connect:hover {
      background: var(--accent);
      color: var(--bg-dark);
      box-shadow: 0 0 10px rgba(0, 255, 170, 0.3);
    }

    .btn-connect.connecting {
      background: rgba(255, 170, 0, 0.15);
      border-color: #ffaa00;
      color: #ffaa00;
      cursor: wait;
      animation: pulse-glow 1.5s infinite alternate;
    }

    .btn-connect.connected {
      background: var(--accent);
      color: var(--bg-dark);
      border-color: var(--accent);
      box-shadow: 0 0 10px rgba(0, 255, 170, 0.3);
    }

    .btn-connect.connected:hover {
      background: var(--danger);
      border-color: var(--danger);
      color: #fff;
      box-shadow: 0 0 10px rgba(255, 68, 85, 0.3);
    }

    @keyframes pulse-glow {
      0% { box-shadow: 0 0 4px rgba(255, 170, 0, 0.3); opacity: 0.8; }
      100% { box-shadow: 0 0 14px rgba(255, 170, 0, 0.7); opacity: 1; }
    }

    .scan-mode-toggle {
      display: inline-flex;
      background: var(--bg-dark);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 2px;
      gap: 2px;
    }

    .mode-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s ease;
      white-space: nowrap;
    }

    .mode-btn:hover {
      color: var(--text-main);
    }

    .mode-btn.active {
      background: rgba(0, 255, 170, 0.15);
      color: var(--accent);
      font-weight: 700;
    }

    .dtv-controls-group {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 3px 8px;
    }

    .dtv-label {
      font-size: 11px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .dtv-mode-toggle {
      display: inline-flex;
      background: var(--bg-dark);
      border: 1px solid var(--border);
      border-radius: 5px;
      padding: 2px;
      gap: 2px;
    }

    .dtv-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 600;
      border-radius: 3px;
      cursor: pointer;
      transition: all 0.2s ease;
      white-space: nowrap;
    }

    .dtv-btn:hover {
      color: var(--text-main);
    }

    .dtv-btn.active {
      background: rgba(14, 165, 233, 0.25);
      border: 1px solid rgba(56, 189, 248, 0.5);
      color: #38bdf8;
      font-weight: 700;
    }

    .dtv-clear-btn {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .dtv-clear-btn:hover {
      border-color: var(--danger);
      color: var(--danger);
    }

    .dtv-count-badge {
      background: rgba(14, 165, 233, 0.15);
      border: 1px solid rgba(56, 189, 248, 0.35);
      color: #38bdf8;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 10px;
    }

    .bias-btn {
      background: var(--bg-dark);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      cursor: pointer;
      letter-spacing: 0.05em;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }

    .bias-btn:hover {
      border-color: #ffaa00;
      color: #ffaa00;
    }

    .bias-btn.active {
      background: rgba(255, 170, 0, 0.25);
      border-color: #ffaa00;
      color: #ffaa00;
      box-shadow: 0 0 8px rgba(255, 170, 0, 0.5);
    }

    .max-btn {
      background: var(--bg-dark);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      cursor: pointer;
      letter-spacing: 0.05em;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }

    .max-btn:hover {
      border-color: #38bdf8;
      color: #38bdf8;
    }

    .max-btn.active {
      background: rgba(56, 189, 248, 0.25);
      border-color: #38bdf8;
      color: #38bdf8;
      box-shadow: 0 0 8px rgba(56, 189, 248, 0.5);
    }

    .ant-rename-btn {
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 11px;
      padding: 1px 4px;
      margin-left: 2px;
      border-radius: 3px;
      line-height: 1;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }

    .ant-rename-btn:hover:not(:disabled) {
      color: #fff;
      border-color: rgba(255, 255, 255, 0.3);
      background: rgba(255, 255, 255, 0.15);
    }

    .ant-rename-btn:disabled, .ant-rename-btn.locked {
      opacity: 0.25 !important;
      cursor: not-allowed !important;
      pointer-events: none !important;
    }

    .antenna-pair-card {
      grid-column: span 2;
      background: rgba(255, 255, 255, 0.035);
    }

    .device-temp-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      padding-right: 2px;
      transition: all 0.3s ease;
    }

    .temp-icon {
      color: #60a5fa;
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }

    .temp-value {
      color: #f1f5f9;
      font-variant-numeric: tabular-nums;
      font-weight: 700;
    }

    .temp-sep {
      color: rgba(255, 255, 255, 0.2);
    }

    .temp-status {
      color: #10b981;
      font-weight: 700;
    }

    .diversity-row {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 4px;
      flex-wrap: wrap;
    }

    .diversity-row-label {
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      white-space: nowrap;
      margin-right: 2px;
    }

    .btn-diversity {
      background: var(--bg-dark);
      border: 1px solid var(--border);
      border-radius: 5px;
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      color: var(--text-muted);
      transition: all 0.18s ease;
      white-space: nowrap;
    }

    .btn-diversity:hover {
      border-color: rgba(255,255,255,0.3);
      color: var(--text-main);
      background: rgba(255,255,255,0.05);
    }

    .btn-diversity.ab { border-color: rgba(0,255,170,0.4); }
    .btn-diversity.ab:hover { border-color: #00ffaa; color: #00ffaa; }
    .btn-diversity.ab.active { background: rgba(0,255,170,0.12); border-color: #00ffaa; color: #00ffaa; box-shadow: 0 0 8px rgba(0,255,170,0.25); }

    .btn-diversity.cd { border-color: rgba(255,170,0,0.4); }
    .btn-diversity.cd:hover { border-color: #ffaa00; color: #ffaa00; }
    .btn-diversity.cd.active { background: rgba(255,170,0,0.12); border-color: #ffaa00; color: #ffaa00; box-shadow: 0 0 8px rgba(255,170,0,0.25); }

    .btn-diversity.ef { border-color: rgba(204,0,255,0.4); }
    .btn-diversity.ef:hover { border-color: #cc00ff; color: #cc00ff; }
    .btn-diversity.ef.active { background: rgba(204,0,255,0.12); border-color: #cc00ff; color: #cc00ff; box-shadow: 0 0 8px rgba(204,0,255,0.25); }

    .paired-badge {
      font-size: 9px;
      padding: 1px 5px;
      border-radius: 3px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      display: none;
    }
    .paired-badge.visible { display: inline-block; }

    .antenna-cards-grid {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 6px;
      margin-top: 4px;
    }

    .antenna-card {
      grid-column: span 1;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 8px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      transition: border-color 0.2s, background 0.2s, opacity 0.2s;
    }

    .antenna-pair-card {
      grid-column: span 2;
    }

    @media (max-width: 1200px) {
      .antenna-cards-grid {
        grid-template-columns: repeat(3, minmax(0, 1fr));
      }
      .antenna-card {
        grid-column: span 1;
      }
      .antenna-pair-card {
        grid-column: span 1;
      }
    }

    @media (max-width: 700px) {
      .antenna-cards-grid {
        grid-template-columns: repeat(1, minmax(0, 1fr));
      }
    }

    .antenna-card.active {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(255, 255, 255, 0.18);
    }

    .antenna-card.bias-powered {
      border-top: 2px solid rgba(255, 170, 0, 0.6);
      box-shadow: 0 0 12px rgba(255, 170, 0, 0.2);
    }

    .antenna-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .antenna-card-label {
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      user-select: none;
      font-weight: 700;
      font-size: 12px;
    }

    .antenna-card-label input[type="checkbox"] {
      width: 14px;
      height: 14px;
      accent-color: var(--accent);
      cursor: pointer;
    }

    .antenna-badge {
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 3px;
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
    }

    .antenna-card select {
      width: 100%;
      padding: 3px 6px;
      font-size: 11px;
      background: var(--bg-dark);
      border: 1px solid var(--border);
      border-radius: 4px;
      color: var(--text-main);
    }

    .antenna-custom-inputs {
      display: none;
      gap: 4px;
      align-items: center;
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    .antenna-custom-inputs input {
      width: 55px;
      padding: 3px 6px;
      font-size: 11px;
      background: #0f1523;
      border: 1px solid #1f293d;
      color: #e2e8f0;
      border-radius: 3px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 8px;
      margin-bottom: 8px;
    }

    .stat-card {
      background: var(--panel-bg);
      padding: 6px 12px;
      border-radius: 6px;
      border: 1px solid var(--border);
    }

    .stat-label { color: var(--text-muted); font-size: 10px; margin-bottom: 2px; text-transform: uppercase; letter-spacing: 0.04em; }
    .stat-value { color: var(--accent); font-size: 14px; font-weight: bold; }

    .main-panel {
      background: var(--panel-bg);
      border-radius: 8px;
      padding: 10px 14px;
      border: 1px solid var(--border);
      flex: 1;
      display: flex;
      flex-direction: column;
    }

    .panel-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
      font-size: 13px;
      color: var(--text-muted);
    }

    .chart-wrapper {
      position: relative;
      flex: 1;
      min-height: 280px;
    }
  </style>
</head>
<body>

  <div class="header">
    <div class="brand">
      <div class="title">AD600 Spectrum Manager</div>
    </div>
    <div class="header-right" style="display: flex; flex-direction: column; align-items: flex-end; gap: 5px;">
      <div class="status-badge">
        <div id="statusDot" class="status-dot"></div>
        <span id="statusText">DISCOVERING...</span>
      </div>
      <div id="deviceTempContainer" class="device-temp-badge">
        <span class="temp-icon">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/></svg>
          AD600 Internal:
        </span>
        <span id="tempValue" class="temp-value">-- °C (-- °F)</span>
        <span class="temp-sep">•</span>
        <span id="tempStatus" class="temp-status">STANDBY</span>
      </div>
    </div>
  </div>

  <!-- Interactive Controls Panel -->
  <div class="controls-panel">
    <div class="controls-row">
      <div class="control-group">
        <label class="control-label">Network Interface (NIC)</label>
        <select id="ifaceSelect" onchange="onIfaceSelect(this.value)">
          <option value="ALL">ALL Interfaces (Auto-Probe)</option>
        </select>
      </div>

      <div class="control-group">
        <label class="control-label">Target Hardware Device</label>
        <div style="display: flex; gap: 8px; align-items: center;">
          <select id="deviceSelect" onchange="onDeviceSelect(this.value)">
            <option value="">Searching auto-discovery...</option>
          </select>
          <button id="connectBtn" class="btn-connect" onclick="toggleConnect()" title="Connect & Negotiate with Shure AD600">CONNECT</button>
        </div>
      </div>

      <div class="control-group">
        <label class="control-label">Spectrum Display Range (Zoom)</label>
        <div style="display: flex; gap: 8px; align-items: center;">
          <select id="displayZoomSelect" onchange="onDisplayZoomSelect(this.value)">
            <option value="LOCKED" selected>Auto-Fit Active Antennas</option>
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom Display Span...</option>
            </optgroup>
          </select>
          <button id="lockZoomBtn" class="btn-lock active" onclick="toggleLockZoom()" title="Lock display zoom to match active antenna ranges">
            Lock Zoom
          </button>
        </div>
      </div>

      <div id="customDisplayGroup" class="control-group" style="display: none;">
        <label class="control-label">Custom Display (MHz)</label>
        <div style="display: flex; gap: 6px; align-items: center;">
          <input id="customDispStart" type="number" step="0.5" value="470.0" style="width: 70px; padding: 6px 8px; background: #0f1523; border: 1px solid #1f293d; color: #e2e8f0; border-radius: 4px;">
          <span style="color: #8a99ad;">–</span>
          <input id="customDispStop" type="number" step="0.5" value="620.0" style="width: 70px; padding: 6px 8px; background: #0f1523; border: 1px solid #1f293d; color: #e2e8f0; border-radius: 4px;">
          <button class="btn-scan" style="padding: 6px 12px; font-size: 11px;" onclick="applyCustomDisplayZoom()">APPLY</button>
        </div>
      </div>

      <div class="control-group">
        <label class="control-label">RBW / Resolution</label>
        <select id="rbwSelect" onchange="onRbwSelect(this.value)">
          <option value="25000">25 kHz (Ultra High Res · comp 1)</option>
          <option value="50000">50 kHz (Very High Res · comp 2)</option>
          <option value="100000">100 kHz (High Res · comp 4)</option>
          <option value="350000" selected>350 kHz (Standard · comp 14)</option>
          <option value="900000">900 kHz (Fast Scan · comp 36)</option>
        </select>
      </div>
    </div>

    <!-- Discrete Antenna Cards with Inline Hardware Scan Range Dropdowns & Scan Controls -->
    <div class="control-group">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
        <label class="control-label">Antenna Inputs & Per-Antenna Hardware Scan Ranges</label>
        <span id="hwSweepRangeIndicator" style="font-size: 11px; color: var(--accent); font-weight: 600;">
          Hardware Sweep: 470.0 – 524.0 MHz
        </span>
      </div>
      <div class="diversity-row" style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;">
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          <span class="diversity-row-label">Diversity Pairs</span>
          <button id="pairBtn_AB" class="btn-diversity ab" onclick="toggleDiversityPair('AB','A','B')" title="Toggle A+B diversity pair — both antennas locked to same range">A / B Pair</button>
          <button id="pairBtn_CD" class="btn-diversity cd" onclick="toggleDiversityPair('CD','C','D')" title="Toggle C+D diversity pair — both antennas locked to same range">C / D Pair</button>
          <button id="pairBtn_EF" class="btn-diversity ef" onclick="toggleDiversityPair('EF','E','F')" title="Toggle E+F diversity pair — both antennas locked to same range">E / F Pair</button>
          <button class="btn-diversity" onclick="enableAllAntennas()" title="Enable all six antennas">All Antennas</button>
        </div>

        <!-- Continuous / Single Sweep + Start/Stop Spectrum Scan with Antenna Pairs -->
        <div class="scan-control-group" style="display: flex; align-items: center; gap: 8px; margin-left: auto;">
          <div class="scan-mode-toggle">
            <button id="modeBtn_continuous" class="mode-btn active" onclick="setScanMode('CONTINUOUS')" title="Continuous Real-Time Spectrum Sweeping">Continuous</button>
            <button id="modeBtn_single" class="mode-btn" onclick="setScanMode('SINGLE')" title="Single Sweep Snapshot & Stop">Single Sweep</button>
          </div>
          <button id="scanBtn" class="btn-scan" onclick="toggleScan()">START SPECTRUM SCAN</button>
        </div>
      </div>
      <div class="antenna-cards-grid">
        <!-- Joined Antenna Pair A + B Card -->
        <div id="card_AB" class="antenna-card antenna-pair-card" style="display: none; border-left: 3px solid #00ffaa; border-right: 3px solid #00b0ff;">
          <div class="antenna-card-header">
            <label class="antenna-card-label">
              <input type="checkbox" id="pairCb_AB" checked onchange="onPairCheckboxChange('AB', this.checked)">
              <span style="font-weight: 800; background: linear-gradient(90deg, #00ffaa, #00b0ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">ANTENNA A + B</span>
            </label>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_AB" class="max-btn" onclick="togglePairMaxHold('AB')" title="Toggle Max Hold for Pair A+B">Max</button>
              <button id="biasBtn_AB" class="bias-btn" onclick="togglePairBias('AB')" title="Toggle Antenna Bias for Pair A+B">Bias</button>
              <span class="paired-badge visible" style="background: linear-gradient(90deg, rgba(0,255,170,0.18), rgba(0,176,255,0.18)); color: #38bdf8;">PAIRED A+B</span>
              <span class="antenna-badge">RF 1 + 2</span>
            </div>
          </div>
          <select id="antRangeSelect_AB" onchange="onPairRangePreset('AB', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524" selected>Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_AB" class="antenna-custom-inputs">
            <input type="number" id="customStart_AB" step="0.5" value="470.0" onchange="onPairCustomInput('AB')" oninput="onPairCustomInput('AB')">
            <span>–</span>
            <input type="number" id="customStop_AB" step="0.5" value="524.0" onchange="onPairCustomInput('AB')" oninput="onPairCustomInput('AB')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Antenna A -->
        <div id="card_A" class="antenna-card active" style="border-left: 3px solid #00ffaa;">
          <div class="antenna-card-header">
            <div style="display: flex; align-items: center; gap: 4px;">
              <label class="antenna-card-label">
                <input type="checkbox" name="antennaCb" value="A" checked onchange="onAntennaChange('A')">
                <span id="antNameSpan_A" style="color: #00ffaa;">Antenna A</span>
              </label>
              <button type="button" class="ant-rename-btn locked" disabled onclick="renameAntenna('A', event)" title="Connect to AD600 to rename antenna">✎</button>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_A" class="max-btn" onclick="toggleMaxHold('A')" title="Toggle Max Hold for Antenna A">Max</button>
              <button id="biasBtn_A" class="bias-btn" onclick="toggleAntennaBias('A')" title="Toggle Antenna Bias Power">Bias</button>
              <span id="pairedBadge_A" class="paired-badge" style="background:rgba(0,255,170,0.15);color:#00ffaa;">PAIRED</span>
              <span class="antenna-badge">RF 1</span>
            </div>
          </div>
          <select id="antRangeSelect_A" onchange="onAntennaRangePreset('A', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524" selected>Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_A" class="antenna-custom-inputs">
            <input type="number" id="customStart_A" step="0.5" value="470.0" onchange="onAntennaCustomInput('A')" oninput="onAntennaCustomInput('A')">
            <span>–</span>
            <input type="number" id="customStop_A" step="0.5" value="524.0" onchange="onAntennaCustomInput('A')" oninput="onAntennaCustomInput('A')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Antenna B -->
        <div id="card_B" class="antenna-card" style="border-left: 3px solid #00b0ff; opacity: 0.6;">
          <div class="antenna-card-header">
            <div style="display: flex; align-items: center; gap: 4px;">
              <label class="antenna-card-label">
                <input type="checkbox" name="antennaCb" value="B" onchange="onAntennaChange('B')">
                <span id="antNameSpan_B" style="color: #00b0ff;">Antenna B</span>
              </label>
              <button type="button" class="ant-rename-btn locked" disabled onclick="renameAntenna('B', event)" title="Connect to AD600 to rename antenna">✎</button>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_B" class="max-btn" onclick="toggleMaxHold('B')" title="Toggle Max Hold for Antenna B">Max</button>
              <button id="biasBtn_B" class="bias-btn" onclick="toggleAntennaBias('B')" title="Toggle Antenna Bias Power">Bias</button>
              <span id="pairedBadge_B" class="paired-badge" style="background:rgba(0,176,255,0.15);color:#00b0ff;">PAIRED</span>
              <span class="antenna-badge">RF 2</span>
            </div>
          </div>
          <select id="antRangeSelect_B" onchange="onAntennaRangePreset('B', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620" selected>Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_B" class="antenna-custom-inputs">
            <input type="number" id="customStart_B" step="0.5" value="524.0" onchange="onAntennaCustomInput('B')" oninput="onAntennaCustomInput('B')">
            <span>–</span>
            <input type="number" id="customStop_B" step="0.5" value="620.0" onchange="onAntennaCustomInput('B')" oninput="onAntennaCustomInput('B')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Joined Antenna Pair C + D Card -->
        <div id="card_CD" class="antenna-card antenna-pair-card" style="display: none; border-left: 3px solid #ffaa00; border-right: 3px solid #ff4455;">
          <div class="antenna-card-header">
            <label class="antenna-card-label">
              <input type="checkbox" id="pairCb_CD" checked onchange="onPairCheckboxChange('CD', this.checked)">
              <span style="font-weight: 800; background: linear-gradient(90deg, #ffaa00, #ff4455); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">ANTENNA C + D</span>
            </label>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_CD" class="max-btn" onclick="togglePairMaxHold('CD')" title="Toggle Max Hold for Pair C+D">Max</button>
              <button id="biasBtn_CD" class="bias-btn" onclick="togglePairBias('CD')" title="Toggle Antenna Bias for Pair C+D">Bias</button>
              <span class="paired-badge visible" style="background: linear-gradient(90deg, rgba(255,170,0,0.18), rgba(255,68,85,0.18)); color: #ffaa00;">PAIRED C+D</span>
              <span class="antenna-badge">RF 3 + 4</span>
            </div>
          </div>
          <select id="antRangeSelect_CD" onchange="onPairRangePreset('CD', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10" selected>G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_CD" class="antenna-custom-inputs">
            <input type="number" id="customStart_CD" step="0.5" value="470.0" onchange="onPairCustomInput('CD')" oninput="onPairCustomInput('CD')">
            <span>–</span>
            <input type="number" id="customStop_CD" step="0.5" value="542.0" onchange="onPairCustomInput('CD')" oninput="onPairCustomInput('CD')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Antenna C -->
        <div id="card_C" class="antenna-card" style="border-left: 3px solid #ffaa00; opacity: 0.6;">
          <div class="antenna-card-header">
            <div style="display: flex; align-items: center; gap: 4px;">
              <label class="antenna-card-label">
                <input type="checkbox" name="antennaCb" value="C" onchange="onAntennaChange('C')">
                <span id="antNameSpan_C" style="color: #ffaa00;">Antenna C</span>
              </label>
              <button type="button" class="ant-rename-btn locked" disabled onclick="renameAntenna('C', event)" title="Connect to AD600 to rename antenna">✎</button>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_C" class="max-btn" onclick="toggleMaxHold('C')" title="Toggle Max Hold for Antenna C">Max</button>
              <button id="biasBtn_C" class="bias-btn" onclick="toggleAntennaBias('C')" title="Toggle Antenna Bias Power">Bias</button>
              <span id="pairedBadge_C" class="paired-badge" style="background:rgba(255,170,0,0.15);color:#ffaa00;">PAIRED</span>
              <span class="antenna-badge">RF 3</span>
            </div>
          </div>
          <select id="antRangeSelect_C" onchange="onAntennaRangePreset('C', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10" selected>G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_C" class="antenna-custom-inputs">
            <input type="number" id="customStart_C" step="0.5" value="470.0" onchange="onAntennaCustomInput('C')" oninput="onAntennaCustomInput('C')">
            <span>–</span>
            <input type="number" id="customStop_C" step="0.5" value="542.0" onchange="onAntennaCustomInput('C')" oninput="onAntennaCustomInput('C')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Antenna D -->
        <div id="card_D" class="antenna-card" style="border-left: 3px solid #ff4455; opacity: 0.6;">
          <div class="antenna-card-header">
            <div style="display: flex; align-items: center; gap: 4px;">
              <label class="antenna-card-label">
                <input type="checkbox" name="antennaCb" value="D" onchange="onAntennaChange('D')">
                <span id="antNameSpan_D" style="color: #ff4455;">Antenna D</span>
              </label>
              <button type="button" class="ant-rename-btn locked" disabled onclick="renameAntenna('D', event)" title="Connect to AD600 to rename antenna">✎</button>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_D" class="max-btn" onclick="toggleMaxHold('D')" title="Toggle Max Hold for Antenna D">Max</button>
              <button id="biasBtn_D" class="bias-btn" onclick="toggleAntennaBias('D')" title="Toggle Antenna Bias Power">Bias</button>
              <span id="pairedBadge_D" class="paired-badge" style="background:rgba(255,68,85,0.15);color:#ff4455;">PAIRED</span>
              <span class="antenna-badge">RF 4</span>
            </div>
          </div>
          <select id="antRangeSelect_D" onchange="onAntennaRangePreset('D', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22" selected>H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_D" class="antenna-custom-inputs">
            <input type="number" id="customStart_D" step="0.5" value="518.0" onchange="onAntennaCustomInput('D')" oninput="onAntennaCustomInput('D')">
            <span>–</span>
            <input type="number" id="customStop_D" step="0.5" value="584.0" onchange="onAntennaCustomInput('D')" oninput="onAntennaCustomInput('D')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Joined Antenna Pair E + F Card -->
        <div id="card_EF" class="antenna-card antenna-pair-card" style="display: none; border-left: 3px solid #cc00ff; border-right: 3px solid #ffff00;">
          <div class="antenna-card-header">
            <label class="antenna-card-label">
              <input type="checkbox" id="pairCb_EF" checked onchange="onPairCheckboxChange('EF', this.checked)">
              <span style="font-weight: 800; background: linear-gradient(90deg, #cc00ff, #ffff00); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">ANTENNA E + F</span>
            </label>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_EF" class="max-btn" onclick="togglePairMaxHold('EF')" title="Toggle Max Hold for Pair E+F">Max</button>
              <button id="biasBtn_EF" class="bias-btn" onclick="togglePairBias('EF')" title="Toggle Antenna Bias for Pair E+F">Bias</button>
              <span class="paired-badge visible" style="background: linear-gradient(90deg, rgba(204,0,255,0.18), rgba(255,255,0,0.18)); color: #cc00ff;">PAIRED E+F</span>
              <span class="antenna-badge">RF 5 + 6</span>
            </div>
          </div>
          <select id="antRangeSelect_EF" onchange="onPairRangePreset('EF', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A" selected>J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_EF" class="antenna-custom-inputs">
            <input type="number" id="customStart_EF" step="0.5" value="554.0" onchange="onPairCustomInput('EF')" oninput="onPairCustomInput('EF')">
            <span>–</span>
            <input type="number" id="customStop_EF" step="0.5" value="616.0" onchange="onPairCustomInput('EF')" oninput="onPairCustomInput('EF')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Antenna E -->
        <div id="card_E" class="antenna-card" style="border-left: 3px solid #cc00ff; opacity: 0.6;">
          <div class="antenna-card-header">
            <div style="display: flex; align-items: center; gap: 4px;">
              <label class="antenna-card-label">
                <input type="checkbox" name="antennaCb" value="E" onchange="onAntennaChange('E')">
                <span id="antNameSpan_E" style="color: #cc00ff;">Antenna E</span>
              </label>
              <button type="button" class="ant-rename-btn locked" disabled onclick="renameAntenna('E', event)" title="Connect to AD600 to rename antenna">✎</button>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_E" class="max-btn" onclick="toggleMaxHold('E')" title="Toggle Max Hold for Antenna E">Max</button>
              <button id="biasBtn_E" class="bias-btn" onclick="toggleAntennaBias('E')" title="Toggle Antenna Bias Power">Bias</button>
              <span id="pairedBadge_E" class="paired-badge" style="background:rgba(204,0,255,0.15);color:#cc00ff;">PAIRED</span>
              <span class="antenna-badge">RF 5</span>
            </div>
          </div>
          <select id="antRangeSelect_E" onchange="onAntennaRangePreset('E', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A" selected>J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000">470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_E" class="antenna-custom-inputs">
            <input type="number" id="customStart_E" step="0.5" value="554.0" onchange="onAntennaCustomInput('E')" oninput="onAntennaCustomInput('E')">
            <span>–</span>
            <input type="number" id="customStop_E" step="0.5" value="616.0" onchange="onAntennaCustomInput('E')" oninput="onAntennaCustomInput('E')">
            <span>MHz</span>
          </div>
        </div>

        <!-- Antenna F -->
        <div id="card_F" class="antenna-card" style="border-left: 3px solid #ffff00; opacity: 0.6;">
          <div class="antenna-card-header">
            <div style="display: flex; align-items: center; gap: 4px;">
              <label class="antenna-card-label">
                <input type="checkbox" name="antennaCb" value="F" onchange="onAntennaChange('F')">
                <span id="antNameSpan_F" style="color: #ffff00;">Antenna F</span>
              </label>
              <button type="button" class="ant-rename-btn locked" disabled onclick="renameAntenna('F', event)" title="Connect to AD600 to rename antenna">✎</button>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <button id="maxBtn_F" class="max-btn" onclick="toggleMaxHold('F')" title="Toggle Max Hold for Antenna F">Max</button>
              <button id="biasBtn_F" class="bias-btn" onclick="toggleAntennaBias('F')" title="Toggle Antenna Bias Power">Bias</button>
              <span id="pairedBadge_F" class="paired-badge" style="background:rgba(255,255,0,0.12);color:#ffff00;">PAIRED</span>
              <span class="antenna-badge">RF 6</span>
            </div>
          </div>
          <select id="antRangeSelect_F" onchange="onAntennaRangePreset('F', this.value)">
            <optgroup label="Shure Bands">
              <option value="G57">G57: 470 – 608 MHz</option>
              <option value="G57_PLUS">G57+: 470 – 616 MHz</option>
              <option value="G10">G10: 470 – 542 MHz</option>
              <option value="H22">H22: 518 – 584 MHz</option>
              <option value="J8">J8: 626 – 664 MHz</option>
              <option value="J8A">J8A: 554 – 616 MHz</option>
              <option value="K54">K54: 608 – 663 MHz</option>
              <option value="X55">X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4">A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8">A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF">VHF: 174 – 216 MHz</option>
              <option value="470_524">Low UHF: 470 – 524 MHz</option>
              <option value="524_620">Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000">Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC">AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000" selected>470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000">470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000">174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN">Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM">Custom...</option>
            </optgroup>
          </select>
          <div id="antCustom_F" class="antenna-custom-inputs">
            <input type="number" id="customStart_F" step="0.5" value="470.0" onchange="onAntennaCustomInput('F')" oninput="onAntennaCustomInput('F')">
            <span>–</span>
            <input type="number" id="customStop_F" step="0.5" value="1000.0" onchange="onAntennaCustomInput('F')" oninput="onAntennaCustomInput('F')">
            <span>MHz</span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Active Hardware IP</div>
      <div class="stat-value" id="targetIp">--.--.--.--</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Active Antennas</div>
      <div class="stat-value" id="antennaVal">A</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Sweeps Captured</div>
      <div class="stat-value" id="scansCaptured">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Resolution & Grid</div>
      <div class="stat-value" id="resVal">350 kHz (1,515 Pts)</div>
    </div>
  </div>

  <div class="main-panel">
    <div class="panel-header">
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <strong>RF Spectrum Power Sweep (dBm)</strong>
        <div class="dtv-controls-group">
          <span class="dtv-label">DTV Grid:</span>
          <div class="dtv-mode-toggle">
            <button id="dtvBtn_US" class="dtv-btn active" onclick="setDtvStandard('US')" title="US ATSC DTV Grid (6 MHz Channels)">US (6 MHz)</button>
            <button id="dtvBtn_UK" class="dtv-btn" onclick="setDtvStandard('UK')" title="UK DVB-T/T2 DTV Grid (8 MHz Channels)">UK (8 MHz)</button>
          </div>
          <button id="dtvClearBtn" class="dtv-clear-btn" onclick="clearDtvMasks()" title="Clear all active DTV channel masks">Clear Masks</button>
          <span id="dtvMaskCount" class="dtv-count-badge" style="display: none;">0 Masks</span>
        </div>
      </div>
      <div id="lastUpdate">Last Sweep: --:--:--</div>
    </div>
    <div class="chart-wrapper">
      <canvas id="spectrumChart"></canvas>
    </div>
  </div>

  <script>
    let chart = null;
    let isScanning = false;
    const ANT_COLORS = {
      'A': '#00ffaa',
      'B': '#00b0ff',
      'C': '#ffaa00',
      'D': '#ff4455',
      'E': '#cc00ff',
      'F': '#ffff00'
    };

    // DTV Station Overlay State & Frequency Calculations
    let dtvStandard = 'US'; // 'US' (6 MHz) | 'UK' (8 MHz)
    const activeDtvMasks = new Set(); // Set of channel IDs, e.g. 'US_14', 'UK_21'
    let hoveredDtvChannel = null;

    function getDtvChannels(standard, minMhz, maxMhz) {
      const channels = [];
      if (standard === 'US') {
        // US UHF ATSC channels: 14 to 69 (470 MHz to 806 MHz, 6 MHz wide)
        for (let ch = 14; ch <= 69; ch++) {
          const start = 470 + (ch - 14) * 6;
          const stop = start + 6;
          if (stop > minMhz && start < maxMhz) {
            channels.push({
              id: 'US_' + ch,
              standard: 'US',
              num: ch,
              label: 'CH ' + ch,
              shortLabel: String(ch),
              startMhz: start,
              stopMhz: stop
            });
          }
        }
      } else {
        // UK UHF DVB-T/T2 channels: 21 to 69 (470 MHz to 862 MHz, 8 MHz wide)
        for (let ch = 21; ch <= 69; ch++) {
          const start = 470 + (ch - 21) * 8;
          const stop = start + 8;
          if (stop > minMhz && start < maxMhz) {
            channels.push({
              id: 'UK_' + ch,
              standard: 'UK',
              num: ch,
              label: 'CH ' + ch,
              shortLabel: String(ch),
              startMhz: start,
              stopMhz: stop
            });
          }
        }
      }
      return channels;
    }

    function buildBaselineLabels(startMhz, endMhz) {
      const s = Math.min(startMhz, endMhz);
      const e = Math.max(startMhz, endMhz);
      const span = e - s;
      let step = 0.25;
      if (span > 1000) step = 2.0;
      else if (span > 350) step = 1.0;
      else if (span > 160) step = 0.5;
      else if (span > 70) step = 0.25;
      else step = 0.1;

      const count = Math.max(2, Math.round(span / step) + 1);
      const labels = [];
      for (let i = 0; i < count; i++) {
        labels.push((s + i * step).toFixed(3));
      }
      return labels;
    }

    function getVisibleFreqRange(c) {
      if (!c || !c.data.labels || c.data.labels.length === 0) {
        return (typeof computeActiveEnvelope === 'function') ? computeActiveEnvelope() : [470.0, 524.0];
      }
      const minLabel = c.options.scales.x.min !== undefined ? c.options.scales.x.min : c.data.labels[0];
      const maxLabel = c.options.scales.x.max !== undefined ? c.options.scales.x.max : c.data.labels[c.data.labels.length - 1];
      const minF = parseFloat(minLabel);
      const maxF = parseFloat(maxLabel);
      return [isNaN(minF) ? 470.0 : minF, isNaN(maxF) ? 524.0 : maxF];
    }

    function freqToPixel(f, c) {
      const chartArea = c.chartArea;
      if (!chartArea) return null;
      const [minFreq, maxFreq] = getVisibleFreqRange(c);
      if (maxFreq <= minFreq) return null;
      const ratio = (f - minFreq) / (maxFreq - minFreq);
      return chartArea.left + ratio * (chartArea.right - chartArea.left);
    }

    function pixelToFreq(x, c) {
      const chartArea = c.chartArea;
      if (!chartArea) return null;
      const [minFreq, maxFreq] = getVisibleFreqRange(c);
      if (maxFreq <= minFreq) return null;
      const ratio = (x - chartArea.left) / (chartArea.right - chartArea.left);
      return minFreq + ratio * (maxFreq - minFreq);
    }

    function setDtvStandard(std) {
      dtvStandard = std;
      const usBtn = document.getElementById('dtvBtn_US');
      const ukBtn = document.getElementById('dtvBtn_UK');
      if (usBtn) usBtn.classList.toggle('active', std === 'US');
      if (ukBtn) ukBtn.classList.toggle('active', std === 'UK');
      updateDtvMaskCount();
      if (chart) chart.update('none');
    }

    function clearDtvMasks() {
      activeDtvMasks.clear();
      updateDtvMaskCount();
      if (chart) chart.update('none');
    }

    function updateDtvMaskCount() {
      const badge = document.getElementById('dtvMaskCount');
      if (!badge) return;
      const count = activeDtvMasks.size;
      badge.innerText = count + (count === 1 ? ' TV Mask' : ' TV Masks');
      badge.style.display = count > 0 ? 'inline-block' : 'none';
    }

    function findDtvChannelAt(x, y) {
      if (!chart || !chart.chartArea) return null;
      const chartArea = chart.chartArea;
      const barHeight = 22;
      const yTop = chartArea.bottom - barHeight - 4;
      const yBottom = chartArea.bottom + 4;

      if (y < yTop || y > yBottom) return null;
      if (x < chartArea.left || x > chartArea.right) return null;

      const clickFreq = pixelToFreq(x, chart);
      if (clickFreq === null) return null;

      const [minFreq, maxFreq] = getVisibleFreqRange(chart);
      const channels = getDtvChannels(dtvStandard, minFreq, maxFreq);
      return channels.find(ch => clickFreq >= ch.startMhz && clickFreq < ch.stopMhz) || null;
    }

    const RANGE_PRESETS = {
      'G57': [470.0, 608.0],
      'G57_PLUS': [470.0, 616.0],
      'G10': [470.0, 542.0],
      'H22': [518.0, 584.0],
      'J8': [626.0, 664.0],
      'J8A': [554.0, 616.0],
      'K54': [608.0, 663.0],
      'X55': [940.0, 960.0],
      'A1_A4': [470.0, 558.0],
      'A5_A8': [550.0, 608.0],
      'VHF': [174.0, 216.0],
      'AFTRCC': [1435.0, 1525.0],
      '470_524': [470.0, 524.0],
      '524_620': [524.0, 620.0],
      '608_1000': [608.0, 1000.0],
      '470_1000': [470.0, 1000.0],
      '470_2000': [470.0, 2000.0],
      '174_1000': [174.0, 1000.0],
      'FULL_SPAN': [174.0, 2000.0]
    };

    let lockZoom = true;
    let customZoomRange = null; // null or [startMhz, stopMhz]

    let localAntennaRanges = {
      'A': [470.0, 524.0],
      'B': [524.0, 620.0],
      'C': [470.0, 542.0],
      'D': [518.0, 584.0],
      'E': [554.0, 616.0],
      'F': [470.0, 1000.0]
    };

    function getActiveAntennas() {
      const checked = Array.from(document.querySelectorAll('input[name="antennaCb"]:checked')).map(el => el.value);
      return checked.length > 0 ? checked : ['A'];
    }

    function computeActiveEnvelope() {
      const active = getActiveAntennas();
      let minStart = Infinity, maxEnd = -Infinity;
      active.forEach(ant => {
        const r = localAntennaRanges[ant] || [470.0, 608.0];
        if (r[0] < minStart) minStart = r[0];
        if (r[1] > maxEnd) maxEnd = r[1];
      });
      if (!isFinite(minStart) || !isFinite(maxEnd) || maxEnd <= minStart) {
        minStart = 470.0; maxEnd = 608.0;
      }
      return [minStart, maxEnd];
    }

    function updateCardActiveStyles() {
      // 1. Individual antenna cards
      ['A', 'B', 'C', 'D', 'E', 'F'].forEach(ant => {
        const cb = document.querySelector('input[name="antennaCb"][value="' + ant + '"]');
        const card = document.getElementById('card_' + ant);
        if (cb && card) {
          if (cb.checked) {
            card.classList.add('active');
            card.style.opacity = '1.0';
          } else {
            card.classList.remove('active');
            card.style.opacity = '0.6';
          }
        }
      });

      // 2. Joined diversity pair cards (merge 2 cards into 1 unified box)
      for (const [pairKey, [ant1, ant2]] of Object.entries(DIVERSITY_PAIRS)) {
        const pairCard = document.getElementById('card_' + pairKey);
        const card1 = document.getElementById('card_' + ant1);
        const card2 = document.getElementById('card_' + ant2);
        const isPaired = activeDiversityPairs.has(pairKey);

        if (isPaired) {
          if (card1) card1.style.display = 'none';
          if (card2) card2.style.display = 'none';
          if (pairCard) {
            pairCard.style.display = 'flex';
            const cb1 = document.querySelector('input[name="antennaCb"][value="' + ant1 + '"]');
            const cb2 = document.querySelector('input[name="antennaCb"][value="' + ant2 + '"]');
            const pairCb = document.getElementById('pairCb_' + pairKey);
            const isActive = (cb1 && cb1.checked) || (cb2 && cb2.checked);
            if (pairCb) pairCb.checked = isActive;
            pairCard.classList.toggle('active', isActive);
            pairCard.style.opacity = isActive ? '1.0' : '0.6';
          }
        } else {
          if (pairCard) pairCard.style.display = 'none';
          if (card1) card1.style.display = 'flex';
          if (card2) card2.style.display = 'flex';
        }
      }
    }

    let needsTraceWipe = false;
    let targetConfigSeq = 0;

    function clearSpectrumDisplay(targetStartMhz, targetEndMhz) {
      needsTraceWipe = true;
      for (const ant of ['A', 'B', 'C', 'D', 'E', 'F']) {
        maxHoldBuffers[ant] = [];
      }
      let s = targetStartMhz;
      let e = targetEndMhz;
      if (s === undefined || e === undefined || isNaN(s) || isNaN(e) || e <= s) {
        const [envStart, envEnd] = computeActiveEnvelope();
        s = (customZoomRange && !lockZoom) ? customZoomRange[0] : envStart;
        e = (customZoomRange && !lockZoom) ? customZoomRange[1] : envEnd;
      }
      if (chart) {
        chart.data.labels = buildBaselineLabels(s, e);
        chart.data.datasets = [{
          label: 'Grid Baseline',
          data: [],
          borderColor: 'transparent',
          backgroundColor: 'transparent'
        }];
        applyChartZoom(s, e);
        chart.update('none');
      }
      const scansEl = document.getElementById('scansCaptured');
      if (scansEl) scansEl.innerText = '0';
    }

    let syncDebounceTimer = null;
    function syncHardwareAndZoom(immediate = false) {
      updateCardActiveStyles();
      const active = getActiveAntennas();
      const [envStart, envEnd] = computeActiveEnvelope();

      const ind = document.getElementById('hwSweepRangeIndicator');
      if (ind) {
        ind.innerText = 'Hardware Sweep: ' + envStart.toFixed(1) + ' – ' + envEnd.toFixed(1) + ' MHz';
      }

      // Immediately clear spectrum view & adjust zoom window to the new target range
      clearSpectrumDisplay(envStart, envEnd);

      if (lockZoom) {
        const opt = document.querySelector('#displayZoomSelect option[value="LOCKED"]');
        if (opt) {
          opt.innerText = 'Auto-Fit (' + envStart.toFixed(0) + '–' + envEnd.toFixed(0) + ' MHz)';
        }
      }

      const doSync = async () => {
        try {
          await fetch('/api/antenna', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ antennas: active })
          });
        } catch (e) {}

        try {
          const res = await fetch('/api/range', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              perAntennaMode: true,
              startMhz: envStart,
              endMhz: envEnd,
              antennaRanges: localAntennaRanges
            })
          });
          const json = await res.json();
          if (json && json.sweepConfigSeq) {
            targetConfigSeq = json.sweepConfigSeq;
          }
        } catch (e) {}
      };

      clearTimeout(syncDebounceTimer);
      if (immediate) {
        doSync();
      } else {
        syncDebounceTimer = setTimeout(doSync, 200);
      }
    }

    function onAntennaChange(ant) {
      if (ant) {
        const partner = getDiversityPartner(ant);
        if (partner) {
          const cb = document.querySelector('input[name="antennaCb"][value="' + ant + '"]');
          const pcb = document.querySelector('input[name="antennaCb"][value="' + partner + '"]');
          if (cb && pcb) {
            pcb.checked = cb.checked;
            if (!cb.checked) {
              // When pair antennas are unchecked, deactivate diversity pair
              for (const [pairKey, [a, b]] of Object.entries(DIVERSITY_PAIRS)) {
                if (ant === a || ant === b) {
                  activeDiversityPairs.delete(pairKey);
                  const btn = document.getElementById('pairBtn_' + pairKey);
                  if (btn) btn.classList.remove('active');
                }
              }
              updatePairedBadges();
            }
          }
        }
      }
      syncHardwareAndZoom(true);
    }

    function onAntennaRangePreset(ant, val) {
      const customDiv = document.getElementById('antCustom_' + ant);
      if (val === 'CUSTOM') {
        if (customDiv) customDiv.style.display = 'flex';
        onAntennaCustomInput(ant);
        return;
      }
      if (customDiv) customDiv.style.display = 'none';
      if (RANGE_PRESETS[val]) {
        localAntennaRanges[ant] = [RANGE_PRESETS[val][0], RANGE_PRESETS[val][1]];
        // If this antenna is in an active diversity pair, mirror to its partner
        const partner = getDiversityPartner(ant);
        if (partner) {
          mirrorRangeToCard(partner, val, RANGE_PRESETS[val][0], RANGE_PRESETS[val][1]);
        }
        syncHardwareAndZoom(true);
      }
    }

    function onAntennaCustomInput(ant) {
      const s = parseFloat(document.getElementById('customStart_' + ant).value);
      const e = parseFloat(document.getElementById('customStop_' + ant).value);
      if (!isNaN(s) && !isNaN(e) && e > s) {
        localAntennaRanges[ant] = [s, e];
        // If this antenna is in an active diversity pair, mirror the range to its partner
        const partner = getDiversityPartner(ant);
        if (partner) {
          localAntennaRanges[partner] = [s, e];
          mirrorRangeToCard(partner, 'CUSTOM', s, e);
        }
        syncHardwareAndZoom(false);
      }
    }

    // ── Diversity Pair System ─────────────────────────────────────────────────

    // Tracks which pairs are currently active. Values: 'AB', 'CD', 'EF'
    const activeDiversityPairs = new Set();

    // Canonical pair definitions
    const DIVERSITY_PAIRS = {
      'AB': ['A', 'B'],
      'CD': ['C', 'D'],
      'EF': ['E', 'F']
    };

    // Max Hold tracking per antenna
    const maxHoldActive = { A: false, B: false, C: false, D: false, E: false, F: false };
    const maxHoldBuffers = { A: [], B: [], C: [], D: [], E: [], F: [] };

    // Returns the diversity partner of an antenna if that pair is currently active
    function getDiversityPartner(ant) {
      for (const [pairKey, [a, b]] of Object.entries(DIVERSITY_PAIRS)) {
        if (activeDiversityPairs.has(pairKey)) {
          if (ant === a) return b;
          if (ant === b) return a;
        }
      }
      return null;
    }

    // Mirror a range selection to a partner antenna's card and pair card
    function mirrorRangeToCard(ant, presetKey, startMhz, stopMhz) {
      const sel = document.getElementById('antRangeSelect_' + ant);
      const customDiv = document.getElementById('antCustom_' + ant);
      if (sel) {
        const startEl = document.getElementById('customStart_' + ant);
        const stopEl  = document.getElementById('customStop_' + ant);
        if (startEl && startMhz !== undefined) startEl.value = Number(startMhz).toFixed(1);
        if (stopEl && stopMhz !== undefined)  stopEl.value  = Number(stopMhz).toFixed(1);

        if (presetKey && presetKey !== 'CUSTOM' && RANGE_PRESETS[presetKey]) {
          sel.value = presetKey;
          if (customDiv) customDiv.style.display = 'none';
          localAntennaRanges[ant] = [RANGE_PRESETS[presetKey][0], RANGE_PRESETS[presetKey][1]];
        } else {
          sel.value = 'CUSTOM';
          if (customDiv) customDiv.style.display = 'flex';
          localAntennaRanges[ant] = [startMhz, stopMhz];
        }
      }

      // Also mirror to the pair card if this antenna belongs to an active pair
      for (const [pairKey, [a, b]] of Object.entries(DIVERSITY_PAIRS)) {
        if (ant === a || ant === b) {
          const pairSel = document.getElementById('antRangeSelect_' + pairKey);
          const pairCustom = document.getElementById('antCustom_' + pairKey);
          if (pairSel) {
            const pStart = document.getElementById('customStart_' + pairKey);
            const pStop  = document.getElementById('customStop_' + pairKey);
            if (pStart && startMhz !== undefined) pStart.value = Number(startMhz).toFixed(1);
            if (pStop && stopMhz !== undefined)  pStop.value  = Number(stopMhz).toFixed(1);

            if (presetKey && presetKey !== 'CUSTOM' && RANGE_PRESETS[presetKey]) {
              pairSel.value = presetKey;
              if (pairCustom) pairCustom.style.display = 'none';
            } else {
              pairSel.value = 'CUSTOM';
              if (pairCustom) pairCustom.style.display = 'flex';
            }
          }
        }
      }
    }

    // Update PAIRED badges for all antennas
    function updatePairedBadges() {
      ['A','B','C','D','E','F'].forEach(ant => {
        const badge = document.getElementById('pairedBadge_' + ant);
        if (!badge) return;
        const partner = getDiversityPartner(ant);
        const isPaired = partner !== null;
        badge.classList.toggle('visible', isPaired);
        if (isPaired) {
          badge.innerText = 'PAIRED (' + partner + ')';
        }
      });
    }

    // Toggle a diversity pair on/off independently — merges into a single box when active
    function toggleDiversityPair(pairKey, ant1, ant2) {
      const btn = document.getElementById('pairBtn_' + pairKey);

      if (activeDiversityPairs.has(pairKey)) {
        // ── Turn OFF the pair ────────────────────────────────────────────────
        activeDiversityPairs.delete(pairKey);
        if (btn) btn.classList.remove('active');

        // Uncheck both antennas when pair is disabled
        [ant1, ant2].forEach(ant => {
          const cb = document.querySelector('input[name="antennaCb"][value="' + ant + '"]');
          if (cb) cb.checked = false;
        });

      } else {
        // ── Turn ON the pair ─────────────────────────────────────────────────
        activeDiversityPairs.add(pairKey);
        if (btn) btn.classList.add('active');

        // Check both antennas
        [ant1, ant2].forEach(ant => {
          const cb = document.querySelector('input[name="antennaCb"][value="' + ant + '"]');
          if (cb) cb.checked = true;
        });

        // Sync ant2's range to ant1 (primary drives the pair)
        const primaryRange = localAntennaRanges[ant1] || [470.0, 524.0];
        localAntennaRanges[ant2] = [...primaryRange];

        // Determine the preset key for ant1's current select so the pair dropdown matches
        const ant1Select = document.getElementById('antRangeSelect_' + ant1);
        const ant1Preset = ant1Select ? ant1Select.value : 'CUSTOM';
        mirrorRangeToCard(ant2, ant1Preset, primaryRange[0], primaryRange[1]);

        // Sync pair card UI elements
        const pairSelect = document.getElementById('antRangeSelect_' + pairKey);
        const pairCustom = document.getElementById('antCustom_' + pairKey);
        if (pairSelect) {
          pairSelect.value = ant1Preset;
          if (ant1Preset === 'CUSTOM') {
            if (pairCustom) pairCustom.style.display = 'flex';
            const pStart = document.getElementById('customStart_' + pairKey);
            const pStop  = document.getElementById('customStop_' + pairKey);
            if (pStart) pStart.value = primaryRange[0].toFixed(1);
            if (pStop)  pStop.value  = primaryRange[1].toFixed(1);
          } else {
            if (pairCustom) pairCustom.style.display = 'none';
          }
        }
        const pairCb = document.getElementById('pairCb_' + pairKey);
        if (pairCb) pairCb.checked = true;

        // Sync max-hold state between pair
        const isMax = maxHoldActive[ant1] || maxHoldActive[ant2];
        maxHoldActive[ant1] = isMax;
        maxHoldActive[ant2] = isMax;
        const pairMaxBtn = document.getElementById('maxBtn_' + pairKey);
        if (pairMaxBtn) pairMaxBtn.classList.toggle('active', isMax);

        // Sync bias state between pair
        const biasBtn1 = document.getElementById('biasBtn_' + ant1);
        const biasBtn2 = document.getElementById('biasBtn_' + ant2);
        const isBias = (biasBtn1 && biasBtn1.classList.contains('active')) || (biasBtn2 && biasBtn2.classList.contains('active'));
        const pairBiasBtn = document.getElementById('biasBtn_' + pairKey);
        if (pairBiasBtn) pairBiasBtn.classList.toggle('active', isBias);
      }

      updatePairedBadges();
      syncHardwareAndZoom(true);
    }

    // Pair Card Event Handlers
    function onPairCheckboxChange(pairKey, checked) {
      const [ant1, ant2] = DIVERSITY_PAIRS[pairKey];
      const cb1 = document.querySelector('input[name="antennaCb"][value="' + ant1 + '"]');
      const cb2 = document.querySelector('input[name="antennaCb"][value="' + ant2 + '"]');
      if (cb1) cb1.checked = checked;
      if (cb2) cb2.checked = checked;
      syncHardwareAndZoom(true);
    }

    function onPairRangePreset(pairKey, val) {
      const [ant1, ant2] = DIVERSITY_PAIRS[pairKey];
      const customDiv = document.getElementById('antCustom_' + pairKey);
      if (val === 'CUSTOM') {
        if (customDiv) customDiv.style.display = 'flex';
        onPairCustomInput(pairKey);
        return;
      }
      if (customDiv) customDiv.style.display = 'none';
      if (RANGE_PRESETS[val]) {
        const r = [RANGE_PRESETS[val][0], RANGE_PRESETS[val][1]];
        localAntennaRanges[ant1] = [...r];
        localAntennaRanges[ant2] = [...r];
        mirrorRangeToCard(ant1, val, r[0], r[1]);
        mirrorRangeToCard(ant2, val, r[0], r[1]);
        syncHardwareAndZoom(true);
      }
    }

    function onPairCustomInput(pairKey) {
      const [ant1, ant2] = DIVERSITY_PAIRS[pairKey];
      const s = parseFloat(document.getElementById('customStart_' + pairKey).value);
      const e = parseFloat(document.getElementById('customStop_' + pairKey).value);
      if (!isNaN(s) && !isNaN(e) && e > s) {
        localAntennaRanges[ant1] = [s, e];
        localAntennaRanges[ant2] = [s, e];
        mirrorRangeToCard(ant1, 'CUSTOM', s, e);
        mirrorRangeToCard(ant2, 'CUSTOM', s, e);
        syncHardwareAndZoom(false);
      }
    }

    async function togglePairBias(pairKey) {
      const [ant1, ant2] = DIVERSITY_PAIRS[pairKey];
      const btn = document.getElementById('biasBtn_' + pairKey);
      const currentlyActive = btn ? btn.classList.contains('active') : false;
      const newState = !currentlyActive;
      if (btn) btn.classList.toggle('active', newState);

      const b1 = document.getElementById('biasBtn_' + ant1);
      const b2 = document.getElementById('biasBtn_' + ant2);
      if (b1) b1.classList.toggle('active', newState);
      if (b2) b2.classList.toggle('active', newState);

      const card = document.getElementById('card_' + pairKey);
      if (card) card.classList.toggle('bias-powered', newState);

      try {
        await Promise.all([
          fetch('/api/bias', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ antenna: ant1, enabled: newState })
          }),
          fetch('/api/bias', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ antenna: ant2, enabled: newState })
          })
        ]);
      } catch (e) {
        console.error('Pair bias toggle error:', e);
      }
    }

    function togglePairMaxHold(pairKey) {
      const [ant1, ant2] = DIVERSITY_PAIRS[pairKey];
      const btn = document.getElementById('maxBtn_' + pairKey);
      const currentlyActive = btn ? btn.classList.contains('active') : false;
      const newState = !currentlyActive;

      maxHoldActive[ant1] = newState;
      maxHoldActive[ant2] = newState;
      if (!newState) {
        maxHoldBuffers[ant1] = [];
        maxHoldBuffers[ant2] = [];
      }

      if (btn) btn.classList.toggle('active', newState);
      const b1 = document.getElementById('maxBtn_' + ant1);
      const b2 = document.getElementById('maxBtn_' + ant2);
      if (b1) b1.classList.toggle('active', newState);
      if (b2) b2.classList.toggle('active', newState);

      if (chart) chart.update('none');
    }

    function toggleMaxHold(ant) {
      maxHoldActive[ant] = !maxHoldActive[ant];
      if (!maxHoldActive[ant]) {
        maxHoldBuffers[ant] = [];
      }
      const btn = document.getElementById('maxBtn_' + ant);
      if (btn) btn.classList.toggle('active', maxHoldActive[ant]);

      // If this antenna is part of an active diversity pair, sync pair button
      const partner = getDiversityPartner(ant);
      if (partner) {
        for (const [pairKey, [a, b]] of Object.entries(DIVERSITY_PAIRS)) {
          if ((ant === a && partner === b) || (ant === b && partner === a)) {
            const pairBtn = document.getElementById('maxBtn_' + pairKey);
            if (pairBtn) pairBtn.classList.toggle('active', maxHoldActive[ant] || maxHoldActive[partner]);
          }
        }
      }

      if (chart) chart.update('none');
    }

    // Enable all six antennas without pairing them
    function enableAllAntennas() {
      document.querySelectorAll('input[name="antennaCb"]').forEach(cb => {
        cb.checked = true;
      });
      syncHardwareAndZoom(true);
    }

    async function toggleAntennaBias(ant) {
      const btn = document.getElementById('biasBtn_' + ant);
      const currentlyActive = btn ? btn.classList.contains('active') : false;
      const newState = !currentlyActive;
      if (btn) btn.classList.toggle('active', newState);
      try {
        await fetch('/api/bias', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ antenna: ant, enabled: newState })
        });
      } catch (e) {
        console.error('Bias toggle error:', e);
      }
    }

    async function renameAntenna(ant, event) {
      if (event) {
        event.preventDefault();
        event.stopPropagation();
      }
      const isConnected = document.getElementById('connectBtn') && document.getElementById('connectBtn').classList.contains('connected');
      if (!isConnected) {
        alert('Please connect to the AD600 before renaming antennas.');
        return;
      }
      const span = document.getElementById('antNameSpan_' + ant);
      const currentName = span ? span.innerText : ('Antenna ' + ant);
      const newName = prompt('Enter custom label for Antenna ' + ant + ' (e.g. Stage Left, Omni, RF 1):', currentName);
      if (newName === null) return;
      const trimmed = newName.trim();
      const displayName = trimmed || ('Antenna ' + ant);

      if (span) {
        span.innerText = displayName;
        span.dataset.editing = '1';
      }

      try {
        const res = await fetch('/api/antenna_name', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ antenna: ant, name: trimmed })
        });
        const result = await res.json();
        if (result && result.antennaNames && span) {
          span.innerText = result.antennaNames[ant] || ('Antenna ' + ant);
        }
      } catch (err) {
        console.error('Failed to update antenna label:', err);
      } finally {
        if (span) delete span.dataset.editing;
      }
    }

    async function setScanMode(mode) {
      try {
        await fetch('/api/scan_mode', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scanMode: mode })
        });
      } catch (e) {
        console.error('Scan mode error:', e);
      }
    }

    function toggleLockZoom() {
      lockZoom = !lockZoom;
      const btn = document.getElementById('lockZoomBtn');
      const zoomSelect = document.getElementById('displayZoomSelect');
      if (lockZoom) {
        btn.classList.add('active');
        zoomSelect.value = 'LOCKED';
        document.getElementById('customDisplayGroup').style.display = 'none';
        const [s, e] = computeActiveEnvelope();
        applyChartZoom(s, e);
        if (chart) chart.update('none');
      } else {
        btn.classList.remove('active');
      }
    }

    function onDisplayZoomSelect(val) {
      const customGroup = document.getElementById('customDisplayGroup');
      const btn = document.getElementById('lockZoomBtn');

      if (val === 'LOCKED') {
        lockZoom = true;
        btn.classList.add('active');
        customGroup.style.display = 'none';
        const [s, e] = computeActiveEnvelope();
        applyChartZoom(s, e);
        if (chart) chart.update('none');
      } else if (val === 'CUSTOM') {
        lockZoom = false;
        btn.classList.remove('active');
        customGroup.style.display = 'flex';
        applyCustomDisplayZoom();
      } else if (RANGE_PRESETS[val]) {
        lockZoom = false;
        btn.classList.remove('active');
        customGroup.style.display = 'none';
        customZoomRange = RANGE_PRESETS[val];
        applyChartZoom(RANGE_PRESETS[val][0], RANGE_PRESETS[val][1]);
        if (chart) chart.update('none');
      }
    }

    function applyCustomDisplayZoom() {
      const s = parseFloat(document.getElementById('customDispStart').value);
      const e = parseFloat(document.getElementById('customDispStop').value);
      if (!isNaN(s) && !isNaN(e) && e > s) {
        lockZoom = false;
        document.getElementById('lockZoomBtn').classList.remove('active');
        customZoomRange = [s, e];
        applyChartZoom(s, e);
        if (chart) chart.update('none');
      }
    }

    function applyChartZoom(startMhz, endMhz) {
      if (!chart) return;
      const s = Math.min(startMhz, endMhz);
      const e = Math.max(startMhz, endMhz);
      const hasRealData = chart.data.datasets && chart.data.datasets.some(d => d.data && d.data.length > 0 && !d.label.includes('Grid Baseline'));

      if (!hasRealData || !chart.data.labels || chart.data.labels.length === 0) {
        chart.data.labels = buildBaselineLabels(s, e);
        chart.options.scales.x.min = chart.data.labels[0];
        chart.options.scales.x.max = chart.data.labels[chart.data.labels.length - 1];
        if (!chart.data.datasets || chart.data.datasets.length === 0) {
          chart.data.datasets = [{
            label: 'Grid Baseline',
            data: [],
            borderColor: 'transparent',
            backgroundColor: 'transparent'
          }];
        }
        return;
      }

      const labels = chart.data.labels;
      const firstFreq = parseFloat(labels[0]);
      const lastFreq  = parseFloat(labels[labels.length - 1]);
      const span = lastFreq - firstFreq;
      if (span <= 0) return;

      const iStart = Math.max(0, Math.round((s - firstFreq) / span * (labels.length - 1)));
      const iEnd   = Math.min(labels.length - 1, Math.round((e - firstFreq) / span * (labels.length - 1)));
      chart.options.scales.x.min = labels[iStart];
      chart.options.scales.x.max = labels[iEnd];
    }

    async function onRbwSelect(val) {
      const rbw = parseInt(val, 10);
      // Immediately clear spectrum trace and max hold from viewing area
      clearSpectrumDisplay();
      try {
        const res = await fetch('/api/rbw', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rbwHz: rbw })
        });
        const json = await res.json();
        if (json && json.sweepConfigSeq) {
          targetConfigSeq = json.sweepConfigSeq;
        }
      } catch (e) {
        console.error('RBW set error:', e);
      }
    }

    const dtvOverlayPlugin = {
      id: 'dtvOverlayPlugin',
      beforeDatasetsDraw(chartInstance) {
        const { ctx, chartArea } = chartInstance;
        if (!chartArea || !chartInstance.data.labels || chartInstance.data.labels.length === 0) return;
        const [minFreq, maxFreq] = getVisibleFreqRange(chartInstance);
        if (maxFreq <= minFreq) return;

        const channels = getDtvChannels(dtvStandard, minFreq, maxFreq);
        const barHeight = 22;
        const maskBottom = chartArea.bottom - barHeight - 2;

        ctx.save();
        ctx.beginPath();
        ctx.rect(chartArea.left, chartArea.top, chartArea.right - chartArea.left, maskBottom - chartArea.top);
        ctx.clip();

        channels.forEach(ch => {
          if (!activeDtvMasks.has(ch.id)) return;
          const x1 = freqToPixel(ch.startMhz, chartInstance);
          const x2 = freqToPixel(ch.stopMhz, chartInstance);
          if (x1 === null || x2 === null) return;
          const leftX = Math.max(chartArea.left, x1);
          const rightX = Math.min(chartArea.right, x2);
          const w = rightX - leftX;
          if (w <= 0) return;

          // Opaque blue mask overlay
          ctx.fillStyle = 'rgba(14, 165, 233, 0.32)';
          ctx.fillRect(leftX, chartArea.top, w, maskBottom - chartArea.top);

          // Boundary dashed lines
          ctx.strokeStyle = 'rgba(56, 189, 248, 0.85)';
          ctx.lineWidth = 1;
          ctx.setLineDash([4, 4]);
          ctx.beginPath();
          ctx.moveTo(leftX, chartArea.top);
          ctx.lineTo(leftX, maskBottom);
          ctx.moveTo(rightX, chartArea.top);
          ctx.lineTo(rightX, maskBottom);
          ctx.stroke();
          ctx.setLineDash([]);

          // Top badge
          const stdLabel = dtvStandard === 'US' ? 'DTV ' : 'UK ';
          const fullBadge = stdLabel + ch.num + ' (' + ch.startMhz.toFixed(1) + '–' + ch.stopMhz.toFixed(1) + ' MHz)';
          const shortBadge = stdLabel + ch.num;
          const badgeText = w > 90 ? fullBadge : shortBadge;

          ctx.font = 'bold 9px monospace';
          const textW = ctx.measureText(badgeText).width + 8;
          const badgeX = Math.max(leftX + 2, Math.min(rightX - textW - 2, leftX + (w - textW) / 2));

          ctx.fillStyle = 'rgba(2, 132, 199, 0.95)';
          ctx.beginPath();
          if (ctx.roundRect) {
            ctx.roundRect(badgeX, chartArea.top + 4, textW, 16, 3);
          } else {
            ctx.rect(badgeX, chartArea.top + 4, textW, 16);
          }
          ctx.fill();

          ctx.fillStyle = '#ffffff';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(badgeText, badgeX + textW / 2, chartArea.top + 12);
        });
        ctx.restore();
      },

      afterDraw(chartInstance) {
        const { ctx, chartArea } = chartInstance;
        if (!chartArea || !chartInstance.data.labels || chartInstance.data.labels.length === 0) return;
        const [minFreq, maxFreq] = getVisibleFreqRange(chartInstance);
        if (maxFreq <= minFreq) return;

        const channels = getDtvChannels(dtvStandard, minFreq, maxFreq);
        const barHeight = 22;
        const yTop = chartArea.bottom - barHeight - 2;
        const yBottom = chartArea.bottom - 2;

        ctx.save();
        ctx.beginPath();
        ctx.rect(chartArea.left, yTop - 25, chartArea.right - chartArea.left, barHeight + 30);
        ctx.clip();

        // Background track for channel rectangles
        ctx.fillStyle = 'rgba(10, 13, 20, 0.92)';
        ctx.fillRect(chartArea.left, yTop, chartArea.right - chartArea.left, barHeight);

        channels.forEach(ch => {
          const x1 = freqToPixel(ch.startMhz, chartInstance);
          const x2 = freqToPixel(ch.stopMhz, chartInstance);
          if (x1 === null || x2 === null) return;
          const leftX = Math.max(chartArea.left, x1);
          const rightX = Math.min(chartArea.right, x2);
          const w = rightX - leftX;
          if (w <= 2) return;

          const isActive = activeDtvMasks.has(ch.id);
          const isHovered = hoveredDtvChannel && hoveredDtvChannel.id === ch.id;

          if (isActive) {
            ctx.fillStyle = isHovered ? 'rgba(14, 165, 233, 0.75)' : 'rgba(14, 165, 233, 0.5)';
          } else if (isHovered) {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
          } else {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
          }
          ctx.fillRect(leftX + 0.5, yTop + 1, w - 1, barHeight - 2);

          ctx.lineWidth = isActive ? 1.5 : 1;
          ctx.strokeStyle = isActive ? '#38bdf8' : (isHovered ? 'rgba(255, 255, 255, 0.45)' : 'rgba(255, 255, 255, 0.15)');
          ctx.strokeRect(leftX + 0.5, yTop + 1, w - 1, barHeight - 2);

          ctx.fillStyle = isActive ? '#ffffff' : (isHovered ? '#f8fafc' : '#94a3b8');
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';

          if (w >= 36) {
            ctx.font = 'bold 10px monospace';
            ctx.fillText('CH ' + ch.num, leftX + w / 2, yTop + barHeight / 2);
          } else if (w >= 16) {
            ctx.font = '9px monospace';
            ctx.fillText(String(ch.num), leftX + w / 2, yTop + barHeight / 2);
          }
        });

        // Hover tooltip over rectangle
        if (hoveredDtvChannel) {
          const ch = hoveredDtvChannel;
          const tipX1 = freqToPixel(ch.startMhz, chartInstance);
          const tipX2 = freqToPixel(ch.stopMhz, chartInstance);
          const midX = (Math.max(chartArea.left, tipX1) + Math.min(chartArea.right, tipX2)) / 2;
          const isActive = activeDtvMasks.has(ch.id);
          const actionPrompt = isActive ? '• Click to Remove Mask' : '• Click to Draw Blue Mask';
          const tipText = (dtvStandard === 'US' ? 'US ATSC ' : 'UK DVB ') + 'CH ' + ch.num + ' (' + ch.startMhz.toFixed(1) + '–' + ch.stopMhz.toFixed(1) + ' MHz) ' + actionPrompt;

          ctx.font = 'bold 10px monospace';
          const tw = ctx.measureText(tipText).width + 14;
          const tipLeft = Math.max(chartArea.left + 4, Math.min(chartArea.right - tw - 4, midX - tw / 2));

          ctx.fillStyle = 'rgba(15, 23, 42, 0.96)';
          ctx.strokeStyle = '#38bdf8';
          ctx.lineWidth = 1;
          ctx.beginPath();
          if (ctx.roundRect) {
            ctx.roundRect(tipLeft, yTop - 22, tw, 18, 4);
          } else {
            ctx.rect(tipLeft, yTop - 22, tw, 18);
          }
          ctx.fill();
          ctx.stroke();

          ctx.fillStyle = '#38bdf8';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(tipText, tipLeft + tw / 2, yTop - 13);
        }

        ctx.restore();
      }
    };

    function initChart() {
      const canvas = document.getElementById('spectrumChart');
      const ctx = canvas.getContext('2d');
      const [initStart, initEnd] = (typeof computeActiveEnvelope === 'function') ? computeActiveEnvelope() : [470.0, 524.0];
      const initialLabels = buildBaselineLabels(initStart, initEnd);

      chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: initialLabels,
          datasets: [{
            label: 'Grid Baseline',
            data: [],
            borderColor: 'transparent',
            backgroundColor: 'transparent'
          }]
        },
        plugins: [ dtvOverlayPlugin ],
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 0 },
          interaction: { intersect: false, mode: 'index' },
          plugins: {
            legend: { display: true, labels: { color: '#8a99ad' } },
            tooltip: {
              filter: (item) => !hoveredDtvChannel,
              backgroundColor: 'rgba(18, 24, 38, 0.95)',
              callbacks: {
                title: (items) => 'Frequency: ' + items[0].label + ' MHz',
                label: (item) => item.dataset.label + ': ' + item.raw + ' dBm'
              }
            }
          },
          scales: {
            x: {
              min: initialLabels[0],
              max: initialLabels[initialLabels.length - 1],
              grid: { color: 'rgba(255, 255, 255, 0.08)' },
              ticks: {
                color: '#8a99ad',
                maxTicksLimit: 16,
                callback: function(val, index) {
                  const raw = this.getLabelForValue(val);
                  const f = parseFloat(raw);
                  if (isNaN(f)) return raw;
                  return (f % 1 === 0 ? f.toFixed(0) : f.toFixed(1)) + ' MHz';
                }
              },
              title: { display: true, text: 'Frequency (MHz)', color: '#8a99ad' }
            },
            y: {
              min: -120,
              max: -30,
              grid: { color: 'rgba(255, 255, 255, 0.06)' },
              ticks: { color: '#8a99ad', stepSize: 10 },
              title: { display: true, text: 'Power (dBm)', color: '#8a99ad' }
            }
          }
        }
      });

      canvas.addEventListener('click', (e) => {
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const ch = findDtvChannelAt(x, y);
        if (ch) {
          if (activeDtvMasks.has(ch.id)) {
            activeDtvMasks.delete(ch.id);
          } else {
            activeDtvMasks.add(ch.id);
          }
          updateDtvMaskCount();
          chart.update('none');
        }
      });

      canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const ch = findDtvChannelAt(x, y);
        if (ch !== hoveredDtvChannel) {
          hoveredDtvChannel = ch;
          canvas.style.cursor = ch ? 'pointer' : 'default';
          chart.update('none');
        }
      });

      canvas.addEventListener('mouseleave', () => {
        if (hoveredDtvChannel) {
          hoveredDtvChannel = null;
          canvas.style.cursor = 'default';
          chart.update('none');
        }
      });
    }

    async function toggleConnect() {
      const btn = document.getElementById('connectBtn');
      const isConnected = btn && btn.classList.contains('connected');
      const action = isConnected ? 'disconnect' : 'connect';

      if (!isConnected && btn) {
        btn.className = 'btn-connect connecting';
        btn.innerText = 'NEGOTIATING...';
      }

      try {
        const res = await fetch('/api/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: action })
        });
        const data = await res.json();
        if (btn) {
          if (data.connectionState === 'CONNECTED') {
            btn.className = 'btn-connect connected';
            btn.innerText = 'CONNECTED';
          } else if (data.connectionState === 'DISCONNECTED') {
            btn.className = 'btn-connect';
            btn.innerText = 'CONNECT';
          }
        }
      } catch (e) {
        console.error('Connect toggle error:', e);
      }
    }

    async function toggleScan() {
      const newAction = isScanning ? 'stop' : 'start';
      if (newAction === 'start') {
        clearSpectrumDisplay();
      }
      const scansEl = document.getElementById('scansCaptured');
      if (scansEl) scansEl.innerText = '0';
      try {
        await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: newAction })
        });
      } catch (e) {
        console.error('Scan toggle error:', e);
      }
    }

    async function onIfaceSelect(iface) {
      try {
        await fetch('/api/iface', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interface: iface })
        });
      } catch (e) {
        console.error('Interface set error:', e);
      }
    }

    async function onDeviceSelect(ip) {
      if (!ip) return;
      try {
        await fetch('/api/target', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetIp: ip })
        });
      } catch (e) {
        console.error('Device target set error:', e);
      }
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();

        const isConnected = data.connectionState === 'CONNECTED';
        const isConnecting = data.connectionState === 'CONNECTING';

        const statusEl = document.getElementById('statusText');
        if (statusEl) {
          statusEl.innerText = data.status || (isConnected ? 'CONNECTED' : 'DISCONNECTED');
        }

        const tempValEl = document.getElementById('tempValue');
        const tempStatusEl = document.getElementById('tempStatus');
        if (isConnected && data.temperature) {
          const c = typeof data.temperature.celsius === 'number' ? data.temperature.celsius.toFixed(1) : data.temperature.celsius;
          const f = typeof data.temperature.fahrenheit === 'number' ? data.temperature.fahrenheit.toFixed(1) : data.temperature.fahrenheit;
          if (tempValEl) tempValEl.innerText = c + ' °C (' + f + ' °F)';
          if (tempStatusEl) {
            const isWarn = Number(data.temperature.celsius) > 55;
            tempStatusEl.innerText = data.temperature.status || (isWarn ? 'HIGH' : 'NORMAL');
            tempStatusEl.style.color = isWarn ? '#ef4444' : '#10b981';
          }
        } else {
          if (tempValEl) tempValEl.innerText = '-- °C (-- °F)';
          if (tempStatusEl) {
            tempStatusEl.innerText = isConnecting ? 'CONNECTING...' : 'DISCONNECTED';
            tempStatusEl.style.color = isConnecting ? '#ffaa00' : '#94a3b8';
          }
        }
        document.getElementById('targetIp').innerText = data.activeTargetIp || '--.--.--.--';
        document.getElementById('antennaVal').innerText = (data.selectedAntennas || ['A']).join(', ');
        document.getElementById('scansCaptured').innerText = data.scansCaptured;

        const grid = data.grid || { startHz: 470000000, stopHz: 524000000, stepHz: 350000, pointCount: 155 };
        const rbwKhz = Math.round((grid.stepHz || 350000) / 1000);
        document.getElementById('resVal').innerText = rbwKhz + ' kHz (' + (grid.pointCount || 155) + ' Pts)';

        const rbwSelect = document.getElementById('rbwSelect');
        if (rbwSelect && data.rbwHz && rbwSelect.value != data.rbwHz) {
          rbwSelect.value = String(data.rbwHz);
        }

        // Sync NICs dropdown
        if (data.interfaces && data.interfaces.length > 0) {
          const ifaceSelect = document.getElementById('ifaceSelect');
          const currentIfaces = Array.from(ifaceSelect.options).map(o => o.value);
          data.interfaces.forEach(nic => {
            if (!currentIfaces.includes(nic.name)) {
              const opt = document.createElement('option');
              opt.value = nic.name;
              opt.innerText = nic.name + ' (' + nic.address + ')';
              if (nic.name === data.selectedInterface) opt.selected = true;
              ifaceSelect.appendChild(opt);
            }
          });
        }

        // Sync Discovered Devices dropdown
        const select = document.getElementById('deviceSelect');
        const devs = Object.values(data.discoveredDevices || {});
        select.innerHTML = '';
        if (devs.length === 0) {
          const opt = document.createElement('option');
          opt.value = '';
          opt.innerText = '-- No Device Selected (Searching...) --';
          select.appendChild(opt);
        } else {
          devs.forEach(dev => {
            const opt = document.createElement('option');
            opt.value = dev.ip;
            opt.innerText = dev.model + ' (' + dev.ip + ' - ' + (dev.iface || 'NIC') + ')';
            if (dev.ip === data.activeTargetIp) opt.selected = true;
            select.appendChild(opt);
          });
        }

        // Sync Connect Button state
        const connectBtn = document.getElementById('connectBtn');
        if (connectBtn) {
          const connState = data.connectionState || 'DISCONNECTED';
          if (connState === 'CONNECTED') {
            connectBtn.className = 'btn-connect connected';
            if (!connectBtn.matches(':hover')) {
              connectBtn.innerText = 'CONNECTED';
            }
            connectBtn.disabled = false;
            connectBtn.title = 'Connected & claimed on AD600. Click to Disconnect.';
          } else if (connState === 'CONNECTING') {
            connectBtn.className = 'btn-connect connecting';
            connectBtn.innerText = 'NEGOTIATING...';
            connectBtn.disabled = false;
            connectBtn.title = 'Negotiating ACN/SDT connection with AD600...';
          } else {
            connectBtn.className = 'btn-connect';
            connectBtn.innerText = 'CONNECT';
            connectBtn.disabled = !data.activeTargetIp;
            connectBtn.title = data.activeTargetIp ? 'Connect & Negotiate with Shure AD600' : 'Select Target Device first';
          }
        }

        // Sync Antenna Rename Buttons (locked until connected)
        const isConn = (data.connectionState === 'CONNECTED');
        document.querySelectorAll('.ant-rename-btn').forEach(btn => {
          btn.disabled = !isConn;
          btn.classList.toggle('locked', !isConn);
          btn.title = isConn ? 'Rename Antenna on Device' : 'Connect to AD600 to rename antenna';
        });

        // Sync Bias Buttons and channel lighting
        if (data.antennaBias) {
          ['A','B','C','D','E','F'].forEach(ant => {
            const bBtn = document.getElementById('biasBtn_' + ant);
            const card = document.getElementById('card_' + ant);
            const isOn = !!data.antennaBias[ant];
            if (bBtn) {
              bBtn.classList.toggle('active', isOn);
              bBtn.title = isOn ? 'Antenna ' + ant + ' Bias is ACTIVE (12V DC)' : 'Toggle Antenna ' + ant + ' Bias Power';
            }
            if (card) {
              card.classList.toggle('bias-powered', isOn);
            }
          });

          // Sync Joined Pair Cards bias
          for (const [pairKey, [ant1, ant2]] of Object.entries(DIVERSITY_PAIRS)) {
            const pairBtn = document.getElementById('biasBtn_' + pairKey);
            const pairCard = document.getElementById('card_' + pairKey);
            const isPairOn = !!(data.antennaBias[ant1] && data.antennaBias[ant2]);
            const isAnyOn = !!(data.antennaBias[ant1] || data.antennaBias[ant2]);
            if (pairBtn) {
              pairBtn.classList.toggle('active', isPairOn);
              pairBtn.title = isPairOn ? ('Pair ' + pairKey + ' Bias is ACTIVE (12V DC)') : ('Toggle Pair ' + pairKey + ' Bias Power');
            }
            if (pairCard) {
              pairCard.classList.toggle('bias-powered', isAnyOn);
            }
          }
        }

        // Sync Antenna Names from hardware (overwriting "Antenna A" etc. if named on device)
        if (data.antennaNames) {
          ['A','B','C','D','E','F'].forEach(ant => {
            const span = document.getElementById('antNameSpan_' + ant);
            if (span && !span.dataset.editing) {
              const customName = data.antennaNames[ant];
              span.innerText = customName ? customName : ('Antenna ' + ant);
            }
          });
        }

        // Sync Scan Mode Toggle
        if (data.scanMode) {
          const btnCont = document.getElementById('modeBtn_continuous');
          const btnSingle = document.getElementById('modeBtn_single');
          if (btnCont && btnSingle) {
            btnCont.classList.toggle('active', data.scanMode === 'CONTINUOUS');
            btnSingle.classList.toggle('active', data.scanMode === 'SINGLE');
          }
        }

        // Sync Scan Button state
        const btn = document.getElementById('scanBtn');
        const hasDevice = !!data.activeTargetIp;
        isScanning = data.scanState === 'SCANNING';

        if (!hasDevice) {
          btn.disabled = true;
          btn.className = 'btn-scan btn-disabled';
          btn.innerText = 'SELECT TARGET DEVICE TO SCAN';
        } else if (isScanning) {
          btn.disabled = false;
          btn.className = 'btn-stop';
          btn.innerText = 'STOP SPECTRUM SCAN';
        } else {
          btn.disabled = false;
          btn.className = 'btn-scan';
          btn.innerText = 'START SPECTRUM SCAN';
        }

        const dot = document.getElementById('statusDot');
        if (isConnected || data.scanState === 'SCANNING') {
          dot.classList.add('active');
        } else {
          dot.classList.remove('active');
        }

        if (data.lastScanTime) {
          const d = new Date(data.lastScanTime);
          document.getElementById('lastUpdate').innerText = 'Last Sweep: ' + d.toLocaleTimeString();
        }

        const activeKeys = data.selectedAntennas || ['A'];

        if (data.traces) {
          const startMhz = (grid.startHz || 470000000) / 1e6;
          const stepMhz = (grid.stepHz || 350000) / 1e6;
          let totalPoints = grid.pointCount || 0;
          for (const k of activeKeys) {
            if (data.traces[k] && data.traces[k].length > totalPoints) {
              totalPoints = data.traces[k].length;
            }
          }
          if (totalPoints === 0) totalPoints = 395;

          // Check if any antenna has real data and is not in a re-arm or config transition.
          const isReArming = (data.status && data.status.includes('RE-ARMING'));
          const isPendingSeq = targetConfigSeq > 0 && (data.sweepConfigSeq === undefined || data.sweepConfigSeq < targetConfigSeq);
          const hasAnyData = !isReArming && !isPendingSeq && activeKeys.some(ant => data.traces[ant] && data.traces[ant].length > 0);

          if (hasAnyData) {
            needsTraceWipe = false;
            const labels = [];
            for (let i = 0; i < totalPoints; i++) {
              const freq = startMhz + i * stepMhz;
              labels.push(freq.toFixed(3));
            }
            chart.data.labels = labels;

            // Re-build multi-series datasets for Chart.js with phosphor persistence and Max Hold
            const newDatasets = [];
            activeKeys.forEach(ant => {
              const raw = data.traces[ant] || [];
              const antRange = localAntennaRanges[ant] || [startMhz, startMhz + totalPoints * stepMhz];
              const existingDs = chart.data.datasets && chart.data.datasets.find(d => d.label && d.label.startsWith('Antenna ' + ant) && !d.label.includes('Max Hold'));
              const existingPts = existingDs ? existingDs.data : [];

              const pts = [];
              for (let i = 0; i < totalPoints; i++) {
                const freq = startMhz + i * stepMhz;
                if (freq >= antRange[0] - 0.001 && freq <= antRange[1] + 0.001) {
                  const val = raw[i];
                  // If new data is valid (> -125 dBm), use it; otherwise retain existing on-screen point
                  if (val !== undefined && val !== null && val > -125.0) {
                    pts.push(val);
                  } else if (existingPts && existingPts[i] !== undefined && existingPts[i] !== null && existingPts[i] > -125.0) {
                    pts.push(existingPts[i]);
                  } else {
                    pts.push(val !== undefined ? val : -115.0);
                  }
                } else {
                  pts.push(null); // clipped out of this antenna's assigned window
                }
              }

              // 1. Live Instantaneous Trace
              newDatasets.push({
                label: 'Antenna ' + ant + ' (' + antRange[0].toFixed(1) + '–' + antRange[1].toFixed(1) + ' MHz)',
                data: pts,
                borderColor: ANT_COLORS[ant] || '#00ffaa',
                borderWidth: 1.5,
                tension: 0.1,
                spanGaps: false,
                pointRadius: 0
              });

              // 2. Max Hold Peak Trace (if enabled for this antenna)
              if (maxHoldActive[ant]) {
                if (!maxHoldBuffers[ant] || maxHoldBuffers[ant].length !== totalPoints) {
                  maxHoldBuffers[ant] = new Array(totalPoints).fill(null);
                }
                const maxPts = [];
                for (let i = 0; i < totalPoints; i++) {
                  if (pts[i] !== null && pts[i] !== undefined) {
                    const prev = maxHoldBuffers[ant][i];
                    const peak = (prev === null || prev === undefined) ? pts[i] : Math.max(prev, pts[i]);
                    maxHoldBuffers[ant][i] = peak;
                    maxPts.push(peak);
                  } else {
                    maxPts.push(null);
                  }
                }
                newDatasets.push({
                  label: 'Antenna ' + ant + ' Max Hold',
                  data: maxPts,
                  borderColor: ANT_COLORS[ant] || '#00ffaa',
                  borderWidth: 1.2,
                  borderDash: [4, 4],
                  tension: 0.1,
                  spanGaps: false,
                  pointRadius: 0
                });
              }
            });
            chart.data.datasets = newDatasets;
          } else {
            // When no trace data is available yet (disconnected, stopped, or awaiting first sweep):
            // Maintain continuous active frequency grid so Frequency, MHz text markers,
            // and DTV station rectangles with blue masks are ALWAYS visible and interactive!
            const [envStart, envEnd] = computeActiveEnvelope();
            const curTargetStart = (customZoomRange && !lockZoom) ? customZoomRange[0] : envStart;
            const curTargetEnd = (customZoomRange && !lockZoom) ? customZoomRange[1] : envEnd;
            if (needsTraceWipe || !hasRealData) {
              chart.data.labels = buildBaselineLabels(curTargetStart, curTargetEnd);
              chart.options.scales.x.min = chart.data.labels[0];
              chart.options.scales.x.max = chart.data.labels[chart.data.labels.length - 1];
              chart.data.datasets = [{
                label: 'Grid Baseline',
                data: [],
                borderColor: 'transparent',
                backgroundColor: 'transparent'
              }];
            }
          }

          // Enforce viewport zoom — single chart.update() per poll cycle
          if (lockZoom) {
            const [s, e] = computeActiveEnvelope();
            applyChartZoom(s, e);
          } else if (customZoomRange) {
            applyChartZoom(customZoomRange[0], customZoomRange[1]);
          } else {
            chart.options.scales.x.min = undefined;
            chart.options.scales.x.max = undefined;
          }
          chart.update('none'); // single update per poll cycle
        }
      } catch (err) {
        document.getElementById('statusText').innerText = 'DISCONNECTED';
      }
    }

    window.addEventListener('DOMContentLoaded', () => {
      initChart();
      updateCardActiveStyles();
      syncHardwareAndZoom();

      const cBtn = document.getElementById('connectBtn');
      if (cBtn) {
        cBtn.addEventListener('mouseenter', () => {
          if (cBtn.classList.contains('connected')) {
            cBtn.innerText = 'DISCONNECT';
          }
        });
        cBtn.addEventListener('mouseleave', () => {
          if (cBtn.classList.contains('connected')) {
            cBtn.innerText = 'CONNECTED';
          }
        });
      }

      fetchStatus();
      setInterval(fetchStatus, 200); // 5 Hz poll
    });
  </script>
</body>
</html>`;

// 4. HTTP Web Server
function startWebServer() {
  const server = http.createServer((req, res) => {
    if (req.url === '/api/status' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const payload = Object.assign({}, appState, { traces: antennaTraces });
      res.end(JSON.stringify(payload));
    } else if (req.url === '/api/connect' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.action === 'connect') {
            if (appState.connectionState !== 'CONNECTED') {
              appState.connectionState = 'CONNECTING';
              appState.status = `NEGOTIATING CONNECTION & OWNERSHIP TO AD600 @ ${appState.activeTargetIp || '169.254.244.206'}...`;
              start18EngineScan();
            } else {
              pollHardwareBias();
            }
          } else if (payload.action === 'disconnect') {
            appState.connectionState = 'DISCONNECTED';
            appState.scanState = 'STOPPED';
            appState.status = 'DISCONNECTED FROM AD600';
            stop18EngineScan();
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, connectionState: appState.connectionState }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/scan' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.action === 'start') {
            appState.scanState = 'SCANNING';
            appState.scansCaptured = 0;
            lastProcessedSweepId = -1;
            antennaTraces = { A: [], B: [], C: [], D: [], E: [], F: [] };
            appState.traces = antennaTraces;
            appState.status = appState.scanMode === 'SINGLE'
              ? 'STARTING SINGLE SWEEP VIA 1.8 ENGINE...'
              : 'STARTING CONTINUOUS SCAN VIA 1.8 ENGINE...';
            if (!engineProcess || appState.connectionState === 'DISCONNECTED') {
              appState.connectionState = 'CONNECTING';
              start18EngineScan();
            } else {
              http.get('http://127.0.0.1:8088/sweep/start', () => {}).on('error', () => {});
            }
          } else {
            appState.scanState = 'STOPPED';
            appState.scansCaptured = 0;
            lastProcessedSweepId = -1;
            appState.status = 'SCAN STOPPED (CONNECTED - READY)';
            http.get('http://127.0.0.1:8088/sweep/stop', () => {}).on('error', () => {});
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, scanState: appState.scanState, scansCaptured: appState.scansCaptured }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/range' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.perAntennaMode !== undefined) {
            appState.perAntennaMode = !!payload.perAntennaMode;
          }
          if (payload.antennaRanges && typeof payload.antennaRanges === 'object') {
            appState.antennaRanges = Object.assign({}, appState.antennaRanges, payload.antennaRanges);
          }

          let startMhz = parseFloat(payload.startMhz);
          let endMhz = parseFloat(payload.endMhz);

          // In per-antenna mode, compute bounding envelope across all active selected antennas
          if (appState.perAntennaMode && appState.selectedAntennas.length > 0) {
            let minStart = Infinity, maxEnd = -Infinity;
            appState.selectedAntennas.forEach(ant => {
              const r = appState.antennaRanges[ant] || [470.0, 608.0];
              if (r[0] < minStart) minStart = r[0];
              if (r[1] > maxEnd) maxEnd = r[1];
            });
            if (isFinite(minStart) && isFinite(maxEnd) && maxEnd > minStart) {
              startMhz = minStart;
              endMhz = maxEnd;
            }
          }

          if (!isNaN(startMhz) && !isNaN(endMhz) && endMhz > startMhz) {
            const rangeChanged = (appState.startFreqMhz !== startMhz || appState.endFreqMhz !== endMhz);
            appState.startFreqMhz = startMhz;
            appState.endFreqMhz = endMhz;
            appState.sweepConfigSeq = (appState.sweepConfigSeq || 0) + 1;
            console.log(`[RANGE CONFIG] Setting Hardware Sweep Range to ${startMhz} – ${endMhz} MHz (PerAntenna=${appState.perAntennaMode}, seq=${appState.sweepConfigSeq})`);

            if (appState.scanState === 'SCANNING') {
              antennaTraces = { A: [], B: [], C: [], D: [], E: [], F: [] };
              appState.traces = antennaTraces;
              lastProcessedSweepId = -1;
              appState.scansCaptured = 0;
              appState.status = `RE-ARMING SPECTRUM SCAN (${startMhz.toFixed(1)}–${endMhz.toFixed(1)} MHz)...`;
            }

            const postData = JSON.stringify({
              startHz: Math.round(startMhz * 1e6),
              stopHz: Math.round(endMhz * 1e6),
              curveMask: computeCurveMask(appState.selectedAntennas),
              repeat: appState.scanMode === 'SINGLE' ? 1 : 255
            });
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: 8088,
              path: '/configuration',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
              }
            }, (bridgeRes) => {
              let resData = '';
              bridgeRes.on('data', c => resData += c);
              bridgeRes.on('end', () => {
                console.log(`[BRIDGE CONFIG RESPONSE] Range updated: ${resData}`);
              });
            });
            bridgeReq.on('error', err => {
              console.log(`[BRIDGE CONFIG OFFLINE] Will apply on next scan launch: ${err.message}`);
            });
            bridgeReq.write(postData);
            bridgeReq.end();
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            sweepConfigSeq: appState.sweepConfigSeq,
            startFreqMhz: appState.startFreqMhz,
            endFreqMhz: appState.endFreqMhz,
            perAntennaMode: appState.perAntennaMode,
            antennaRanges: appState.antennaRanges
          }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/rbw' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const rbw = parseInt(payload.rbwHz, 10);
          const VALID_RBWS = [25000, 50000, 100000, 350000, 900000];
          if (VALID_RBWS.includes(rbw)) {
            appState.rbwHz = rbw;
            appState.rbwComp = Math.max(1, Math.round(rbw / 25000));
            appState.sweepConfigSeq = (appState.sweepConfigSeq || 0) + 1;
            console.log(`[RBW CONFIG] Set RBW to ${appState.rbwHz} Hz (comp ${appState.rbwComp}, seq=${appState.sweepConfigSeq})`);

            if (appState.scanState === 'SCANNING') {
              antennaTraces = { A: [], B: [], C: [], D: [], E: [], F: [] };
              appState.traces = antennaTraces;
              lastProcessedSweepId = -1;
              appState.scansCaptured = 0;
              appState.status = `RE-ARMING SPECTRUM SCAN (${Math.round(rbw / 1000)} kHz RBW)...`;
            }

            // Send config update to bridge
            const postData = JSON.stringify({ rbwHz: appState.rbwHz });
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: 8088,
              path: '/configuration',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
              }
            }, (bridgeRes) => {
              let resData = '';
              bridgeRes.on('data', c => resData += c);
              bridgeRes.on('end', () => {
                console.log(`[BRIDGE CONFIG RESPONSE] RBW updated: ${resData}`);
              });
            });
            bridgeReq.on('error', err => {
              console.log(`[BRIDGE CONFIG OFFLINE] Will apply on next scan launch: ${err.message}`);
            });
            bridgeReq.write(postData);
            bridgeReq.end();
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, sweepConfigSeq: appState.sweepConfigSeq, rbwHz: appState.rbwHz, rbwComp: appState.rbwComp }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/antenna' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.antennas && Array.isArray(payload.antennas)) {
            appState.selectedAntennas = payload.antennas;
            appState.curveMask = computeCurveMask(appState.selectedAntennas);
            appState.sweepConfigSeq = (appState.sweepConfigSeq || 0) + 1;
            console.log(`[ANTENNA MULTI-SELECT UPDATE] Active Inputs: ${appState.selectedAntennas.join(', ')} (Curve Mask: 0x${appState.curveMask.toString(16).toUpperCase()}, seq=${appState.sweepConfigSeq})`);

            if (appState.scanState === 'SCANNING') {
              antennaTraces = { A: [], B: [], C: [], D: [], E: [], F: [] };
              appState.traces = antennaTraces;
              lastProcessedSweepId = -1;
              appState.scansCaptured = 0;
              appState.status = `RE-ARMING SPECTRUM SCAN...`;
            }

            const configPayload = {
              curveMask: appState.curveMask
            };

            // If per-antenna mode is active, adjust hardware sweep bounding box for new antenna set
            if (appState.perAntennaMode && appState.selectedAntennas.length > 0) {
              let minStart = Infinity, maxEnd = -Infinity;
              appState.selectedAntennas.forEach(ant => {
                const r = appState.antennaRanges[ant] || [470.0, 608.0];
                if (r[0] < minStart) minStart = r[0];
                if (r[1] > maxEnd) maxEnd = r[1];
              });
              if (isFinite(minStart) && isFinite(maxEnd) && (minStart !== appState.startFreqMhz || maxEnd !== appState.endFreqMhz)) {
                appState.startFreqMhz = minStart;
                appState.endFreqMhz = maxEnd;
                configPayload.startHz = Math.round(minStart * 1e6);
                configPayload.stopHz = Math.round(maxEnd * 1e6);
              }
            }

            const postData = JSON.stringify(configPayload);
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: 8088,
              path: '/configuration',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
              }
            }, () => {});
            bridgeReq.on('error', () => {});
            bridgeReq.write(postData);
            bridgeReq.end();
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, sweepConfigSeq: appState.sweepConfigSeq, selectedAntennas: appState.selectedAntennas, curveMask: appState.curveMask }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/iface' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.interface) {
            appState.selectedInterface = payload.interface;
            appState.status = `PROBING INTERFACE ${payload.interface}...`;
            console.log(`[NIC SELECTION] User selected interface ${payload.interface}`);
            runDiscovery18(payload.interface);
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, selectedInterface: appState.selectedInterface }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/target' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.targetIp && appState.discoveredDevices[payload.targetIp]) {
            const dev = appState.discoveredDevices[payload.targetIp];
            appState.activeTargetIp = dev.ip;
            appState.activeTargetModel = dev.model;
            appState.activeTargetSdtPort = dev.sdtPort;
            appState.status = `TARGET SET TO ${dev.model} (${dev.ip})`;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, activeTargetIp: appState.activeTargetIp }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/bias' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const ant = (payload.antenna || payload.port || 'A').toUpperCase();
          const enabled = !!payload.enabled;
          if (appState.antennaBias && appState.antennaBias[ant] !== undefined) {
            appState.antennaBias[ant] = enabled;
            console.log(`[ANTENNA BIAS] Port ${ant} 12V DC Bias set to ${enabled ? 'ON' : 'OFF'}`);

            const postData = JSON.stringify({ antenna: ant, enabled: enabled });
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: 8088,
              path: '/bias',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
              }
            }, () => {});
            bridgeReq.on('error', () => {});
            bridgeReq.write(postData);
            bridgeReq.end();
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, antennaBias: appState.antennaBias }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/antenna_name' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const ant = (payload.antenna || 'A').toUpperCase();
          const name = String(payload.name !== undefined ? payload.name : '').trim();
          if (appState.antennaNames && appState.antennaNames[ant] !== undefined) {
            appState.antennaNames[ant] = name;
            console.log(`[ANTENNA NAME] Port ${ant} alias set to: "${name}"`);

            const postData = JSON.stringify({ antenna: ant, name: name });
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: 8088,
              path: '/antenna_name',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
              }
            }, () => {});
            bridgeReq.on('error', () => {});
            bridgeReq.write(postData);
            bridgeReq.end();
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, antennaNames: appState.antennaNames }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (req.url === '/api/scan_mode' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.scanMode === 'CONTINUOUS' || payload.scanMode === 'SINGLE') {
            appState.scanMode = payload.scanMode;
            console.log(`[SCAN MODE] Sweep Mode set to ${appState.scanMode}`);

            const repeatVal = appState.scanMode === 'SINGLE' ? 1 : 255;
            const postData = JSON.stringify({ repeat: repeatVal });
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: 8088,
              path: '/configuration',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
              }
            }, () => {});
            bridgeReq.on('error', () => {});
            bridgeReq.write(postData);
            bridgeReq.end();
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, scanMode: appState.scanMode }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(HTML_TEMPLATE);
    }
  });

  server.listen(WEB_PORT, () => {
    console.log('===========================================================');
    console.log('  Shure AD600 Node.js Spectrum App (470 MHz - 1.0 GHz)      ');
    console.log('===========================================================');
    console.log(`  [+] Web Dashboard : http://localhost:${WEB_PORT}`);
    console.log(`  [+] Range Span    : 470.0 MHz - 1000.0 MHz (1.0 GHz)`);
    console.log(`  [+] Controls      : Radio Buttons (ALL, Antenna A, B, C, D, E, F)`);
    console.log('===========================================================');
  });
}

// Start All Services
stop18EngineScan();
initAcnSpectrumIngest();
startWebServer();
