const http = require('http');
const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');

const WEB_PORT = 8000;
const SLP_PORT = 8427;
const SLP_MULTICAST_ADDR = '239.255.254.253';
const RTL_TCP_HOST = process.env.RTL_TCP_HOST || '127.0.0.1';
const RTL_TCP_PORT = Number.parseInt(process.env.RTL_TCP_PORT || '1234', 10);

// App State
let appState = {
  interfaces: [], // list of { name, address }
  selectedInterface: 'ALL', // 'ALL' = auto: pick the NIC whose subnet contains the device
  discoveredDevices: {
    [RTL_TCP_HOST]: { ip: RTL_TCP_HOST, model: 'RTL-SDR (rtl_tcp)', iface: 'network', lastSeen: Date.now() }
  },
  activeTargetIp: RTL_TCP_HOST,
  activeTargetModel: 'RTL-SDR (rtl_tcp)',
  activeTargetSdtPort: RTL_TCP_PORT,
  connectionState: 'DISCONNECTED', // 'DISCONNECTED' | 'CONNECTING' | 'CONNECTED'
  selectedAntennas: ['A'], // Array of selected antennas, e.g. ['A', 'B']
  inputLabel: 'RTL-SDR',
  rtlClients: [{
    id: 'rtl-client-1',
    name: 'RTL-SDR',
    host: RTL_TCP_HOST,
    port: RTL_TCP_PORT,
    startMhz: 470.0,
    stopMhz: 524.0,
    enabled: false,
    state: 'DISCONNECTED'
  }],
  scanState: 'STOPPED', // 'STOPPED' | 'SCANNING'
  status: 'DISCONNECTED - RTL-SDR NODE READY',
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
  antennaBiasPending: {}, // ant -> { enabled, t } awaiting device confirmation
  scanSlotOwned: false,
  antennaNames: {
    'A': 'Shared Scan Range',
    'B': '',
    'C': '',
    'D': '',
    'E': '',
    'F': ''
  },
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
        validIps.push({ name, address: net.address, netmask: net.netmask, mac: net.mac });
      }
    }
  }
  appState.interfaces = validIps;
  return validIps;
}

function ipv4ToInt(ip) {
  const p = String(ip || '').split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

// The local NIC whose real subnet (address + netmask) contains `ip`, or null. Works equally for a
// link-local direct connection (169.254/16) and a routed/DHCP LAN — never a guessed prefix or a
// hardcoded interface name (findings §6.6).
function ifaceForHost(ip) {
  const target = ipv4ToInt(ip);
  if (target === null) return null;
  for (const nic of appState.interfaces) {
    const addr = ipv4ToInt(nic.address);
    const mask = ipv4ToInt(nic.netmask);
    if (addr === null || mask === null) continue;
    if (((addr & mask) >>> 0) === ((target & mask) >>> 0)) return nic;
  }
  return null;
}

// 2. 1.8 Engine Process Manager & Multi-Antenna Trace Aggregator
const { spawn, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const ENGINE_DIR = path.join(__dirname, 'engine');
// App-private scratch dir (console_cmd.txt / console_out.log). Deliberately NOT ~/.ad600_scanner,
// which the SoundBase AD600 plugin also uses.
const SCRATCH_DIR = process.env.AD600_ENGINE_SCRATCH || path.join(os.homedir(), '.ad600_node_app');
const CMD_FILE = path.join(SCRATCH_DIR, 'console_cmd.txt');
const RTL_CLIENT_CONFIG_FILE = path.join(os.homedir(), '.rtl_tcp_spectrum_scanner', 'clients.json');
const PYTHON_BIN = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
const BRIDGE_PORT = 8088;
// The rtl_tcp IQ stream is not calibrated to absolute input power.
const TRACE_FLOOR_DBFS = -125.0;
const TRACE_CEILING_DBFS = 10.0;

// Dynamic spectrum datasets per antenna (A..F) with authentic hardware frequency bins
const ANT_COLORS = {
  'A': '#00ffaa',
  'B': '#00b0ff',
  'C': '#ffaa00',
  'D': '#ff4455',
  'E': '#cc00ff',
  'F': '#ffff00'
};

const RTL_CLIENT_LIMIT = 6;
const RTL_SLOT_RANGES = {
  A: [470.0, 524.0],
  B: [524.0, 620.0],
  C: [470.0, 542.0],
  D: [518.0, 584.0],
  E: [554.0, 616.0],
  F: [470.0, 1000.0]
};
const RTL_SLOTS = Object.keys(ANT_COLORS);

let sourceTraces = { 'rtl-client-1': [] };

function gridForRange(startMhz, stopMhz, stepHz) {
  const startHz = Math.round(startMhz * 1e6);
  const stopHz = Math.round(stopMhz * 1e6);
  return {
    startHz,
    stopHz,
    stepHz,
    pointCount: Math.max(1, Math.floor((stopHz - startHz) / stepHz) + 1)
  };
}

function clientRange(client, index = appState.rtlClients.indexOf(client)) {
  const fallback = RTL_SLOT_RANGES[RTL_SLOTS[Math.max(0, index)] || 'A'];
  const startMhz = Number(client && client.startMhz);
  const stopMhz = Number(client && client.stopMhz);
  if (Number.isFinite(startMhz) && Number.isFinite(stopMhz) && startMhz >= 24 && stopMhz <= 1766 && stopMhz > startMhz) {
    return [startMhz, stopMhz];
  }
  return fallback;
}

function rtlClientsForStatus() {
  return appState.rtlClients.map((client, index) => {
    const slot = RTL_SLOTS[index] || 'F';
    const [startMhz, stopMhz] = clientRange(client, index);
    return Object.assign({}, client, {
      slot,
      color: ANT_COLORS[slot],
      progress: rtlClientRuntimes.get(client.id)?.progress || null,
      startMhz,
      stopMhz,
      grid: gridForRange(startMhz, stopMhz, appState.rbwHz)
    });
  });
}

const rtlClientRuntimes = new Map();
let nextBridgePort = BRIDGE_PORT;

let udpDiscoverySocket = null;

function initUdpBeaconDiscovery() {
  getNetworkInterfaces();
  if (udpDiscoverySocket) return;

  try {
    udpDiscoverySocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    udpDiscoverySocket.on('message', (msg, rinfo) => {
      const ip = rinfo.address;
      const str = msg.toString('utf8');

      // Only AD600 adverts; other Shure gear (and WWB/SoundBase controllers) also talk on 8427.
      if (!/AD600/i.test(str)) return;

      // Match CID if present in the advert. Unknown stays null — the engine bootstrap resolves it
      // by discovery before JOIN rather than guessing another unit's identity.
      const cidMatch = str.match(/\(cid=([A-Fa-f0-9-]+)\)/);
      const cid = cidMatch ? cidMatch[1].replace(/-/g, '').toLowerCase() : null;
      const nic = ifaceForHost(ip);
      recordDiscoveredDevice(ip, cid, nic ? nic.name : null, 'beacon');
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

function recordDiscoveredDevice(ip, cid, ifaceName, source, sdtPort) {
  const prev = appState.discoveredDevices[ip];
  if (!prev) {
    console.log(`[DISCOVERY] Found AD600 @ ${ip} on ${ifaceName || '?'} via ${source} (CID: ${cid || 'unknown'})`);
  }
  appState.discoveredDevices[ip] = {
    ip: ip,
    model: 'Shure AD600 Spectrum Manager',
    cid: cid || (prev && prev.cid) || null,
    iface: ifaceName || (prev && prev.iface) || null,
    sdtPort: sdtPort || (prev && prev.sdtPort) || 57383,
    lastSeen: Date.now()
  };
  if (!appState.activeTargetIp) {
    appState.activeTargetIp = ip;
    if (appState.connectionState === 'DISCONNECTED') {
      appState.status = `DISCOVERED AD600 @ ${ip} (${ifaceName || '?'}) - READY`;
    }
  }
}

// Active SLP discovery via the bundled engine/ad600_discovery.py (stdlib only), one probe per NIC.
const DISCOVERY_PY = `
import sys, json
sys.path.insert(0, sys.argv[1])
import ad600_discovery as d
rec = d.discover(sys.argv[2], timeout=4)
print(json.dumps(rec or None))
`;

function runDiscovery(targetIface = null) {
  initUdpBeaconDiscovery();
  getNetworkInterfaces();
  const ifacesToProbe = (targetIface && targetIface !== 'ALL')
    ? [targetIface]
    : appState.interfaces.map(i => i.name);

  ifacesToProbe.forEach(iface => {
    // execFile (not exec) so `iface` is passed as a literal argv entry, never interpreted by a shell.
    execFile(PYTHON_BIN, ['-c', DISCOVERY_PY, ENGINE_DIR, iface], { timeout: 15000 }, (err, stdout) => {
      if (err) return;
      let rec = null;
      try { rec = JSON.parse((stdout || '').trim().split('\n').pop()); } catch (e) { return; }
      if (!rec || !rec.device_ip) return;
      recordDiscoveredDevice(rec.device_ip, rec.device_cid, rec.iface || iface, 'SLP', rec.device_port);
    });
  });
}

function enabledRtlClients() {
  return appState.rtlClients.filter(client => client.enabled);
}

function loadRtlClientProfiles() {
  try {
    const saved = JSON.parse(fs.readFileSync(RTL_CLIENT_CONFIG_FILE, 'utf8'));
    if (!Array.isArray(saved)) return;
    const savedDefault = saved.find(entry => entry && entry.id === 'rtl-client-1');
    if (savedDefault) {
      const [startMhz, stopMhz] = clientRange(savedDefault, 0);
      appState.rtlClients[0].startMhz = startMhz;
      appState.rtlClients[0].stopMhz = stopMhz;
    }
    const profiles = [];
    for (const entry of saved) {
      if (!entry || typeof entry !== 'object') continue;
      const name = String(entry.name || '').trim().slice(0, 64);
      const host = String(entry.host || '').trim();
      const port = Number.parseInt(entry.port, 10);
      if (!entry.id || entry.id === 'rtl-client-1' || !name || !host || /\s/.test(host) ||
          host.length > 253 || !Number.isInteger(port) || port < 1 || port > 65535) continue;
      const defaultClient = appState.rtlClients[0];
      if ((defaultClient.host.toLowerCase() === host.toLowerCase() && defaultClient.port === port) ||
          profiles.some(client => client.id === String(entry.id) ||
            (client.host.toLowerCase() === host.toLowerCase() && client.port === port))) continue;
      const [startMhz, stopMhz] = clientRange(entry, profiles.length + 1);
      profiles.push({ id: String(entry.id), name, host, port, startMhz, stopMhz, enabled: false, state: 'DISCONNECTED' });
      if (profiles.length >= RTL_CLIENT_LIMIT - 1) break;
    }
    appState.rtlClients = [appState.rtlClients[0], ...profiles];
    sourceTraces = Object.fromEntries(appState.rtlClients.map(client => [client.id, []]));
  } catch (err) {
    if (err.code !== 'ENOENT') console.error('[RTL CLIENTS] Could not load saved client profiles:', err.message);
  }
}

function saveRtlClientProfiles() {
  const profiles = appState.rtlClients.map(client => client.id === 'rtl-client-1'
    ? { id: client.id, startMhz: client.startMhz, stopMhz: client.stopMhz }
    : ({ id: client.id, name: client.name, host: client.host, port: client.port, startMhz: client.startMhz, stopMhz: client.stopMhz }));
  try {
    fs.mkdirSync(path.dirname(RTL_CLIENT_CONFIG_FILE), { recursive: true });
    fs.writeFileSync(RTL_CLIENT_CONFIG_FILE, JSON.stringify(profiles, null, 2) + '\n', { mode: 0o600 });
    return true;
  } catch (err) {
    console.error('[RTL CLIENTS] Could not save client profiles:', err.message);
    return false;
  }
}

function syncRtlConnectionState() {
  const enabled = enabledRtlClients();
  const rangeClients = enabled.length ? enabled : appState.rtlClients.slice(0, 1);
  if (rangeClients.length) {
    const ranges = rangeClients.map(client => clientRange(client));
    appState.startFreqMhz = Math.min(...ranges.map(range => range[0]));
    appState.endFreqMhz = Math.max(...ranges.map(range => range[1]));
    appState.grid = gridForRange(appState.startFreqMhz, appState.endFreqMhz, appState.rbwHz);
  }
  const connected = enabled.filter(client => client.state === 'CONNECTED').length;
  appState.connectionState = enabled.length === 0
    ? 'DISCONNECTED'
    : (connected === enabled.length ? 'CONNECTED' : 'CONNECTING');
  appState.activeTargetIp = enabled.length ? enabled[0].host : null;
  appState.inputLabel = enabled.map(client => client.name).join(', ') || 'RTL-SDR';

  if (appState.scanState === 'SCANNING') {
    appState.status = `SCANNING ${enabled.length} RTL_TCP RECEIVER${enabled.length === 1 ? '' : 'S'}`;
  } else if (enabled.length === 0) {
    appState.status = 'NO RTL_TCP CLIENTS ENABLED';
  } else if (connected === enabled.length) {
    appState.status = `${connected} RTL_TCP RECEIVER${connected === 1 ? '' : 'S'} CONNECTED - READY`;
  } else {
    appState.status = `CONNECTING TO ${enabled.length} RTL_TCP RECEIVER${enabled.length === 1 ? '' : 'S'} (${connected} CONNECTED)...`;
  }
}

function allocateBridgePort() {
  const allocated = new Set(Array.from(rtlClientRuntimes.values(), runtime => runtime.bridgePort));
  while (allocated.has(nextBridgePort)) nextBridgePort++;
  const port = nextBridgePort++;
  if (nextBridgePort > 65000) nextBridgePort = BRIDGE_PORT;
  return port;
}

function startRtlTcpClient(client) {
  if (!client || !client.enabled || rtlClientRuntimes.has(client.id)) return;
  const [startMhz, stopMhz] = clientRange(client);
  const clientGrid = gridForRange(startMhz, stopMhz, appState.rbwHz);
  const bridgePort = allocateBridgePort();
  const backendPath = path.join(ENGINE_DIR, 'rtl_tcp_backend.py');
  const env = Object.assign({}, process.env, {
    PYTHONUNBUFFERED: '1',
    RTL_TCP_HOST: client.host,
    RTL_TCP_PORT: String(client.port),
    RTL_BRIDGE_PORT: String(bridgePort),
    RTL_SAMPLE_RATE: String(process.env.RTL_SAMPLE_RATE || 1800000),
    RTL_TUNER_GAIN_DB: String(process.env.RTL_TUNER_GAIN_DB || 25),
    RTL_TUNER_AGC: process.env.RTL_TUNER_AGC === '1' ? '1' : '0',
    RTL_DIGITAL_AGC: process.env.RTL_DIGITAL_AGC === '1' ? '1' : '0',
    RTL_START_HZ: String(clientGrid.startHz),
    RTL_STOP_HZ: String(clientGrid.stopHz),
    RTL_RBW_HZ: String(appState.rbwHz || 350000),
    RTL_REPEAT: appState.scanMode === 'SINGLE' ? '1' : '255',
    RTL_START_SWEEP: appState.scanState === 'SCANNING' ? '1' : '0'
  });
  const runtime = {
    clientId: client.id,
    bridgePort,
    grid: clientGrid,
    proc: null,
    pollInterval: null,
    pollInFlight: false,
    commandEpoch: 0,
    pendingSweepStart: false,
    progress: null,
    lastProcessedSweepId: -1,
    lastSweepComplete: false
  };
  const proc = spawn(PYTHON_BIN, [backendPath], { env });
  runtime.proc = proc;
  rtlClientRuntimes.set(client.id, runtime);
  client.state = 'CONNECTING';
  console.log(`[RTL TCP] Starting client ${client.name} at ${client.host}:${client.port}`);
  let stdoutBuffer = '';
  proc.stdout.on('data', data => {
    if (rtlClientRuntimes.get(client.id) !== runtime) return;
    stdoutBuffer += data.toString('utf8');
    const lines = stdoutBuffer.split('\n');
    stdoutBuffer = lines.pop();
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      console.log(`[RTL ${client.name}]`, line);
      if (line.startsWith('[RTL TCP] CONNECTED')) {
        client.state = 'CONNECTED';
        syncRtlConnectionState();
      } else if (line.startsWith('[RTL TCP] DISCONNECTED') || line.startsWith('[RTL TCP] CONNECTING')) {
        client.state = 'RECONNECTING';
        syncRtlConnectionState();
      }
    }
  });
  proc.stderr.on('data', data => {
    if (rtlClientRuntimes.get(client.id) === runtime) console.error(`[RTL ${client.name} ERROR]`, data.toString('utf8').trim());
  });
  proc.on('error', err => {
    if (rtlClientRuntimes.get(client.id) !== runtime) return;
    client.state = 'ERROR';
    client.error = err.message;
    syncRtlConnectionState();
  });
  proc.on('exit', code => {
    console.log(`[RTL ${client.name}] Backend exited with code ${code}`);
    if (rtlClientRuntimes.get(client.id) !== runtime) return;
    rtlClientRuntimes.delete(client.id);
    clearInterval(runtime.pollInterval);
    client.state = 'DISCONNECTED';
    if (appState.scanState === 'SCANNING' && enabledRtlClients().length === 0) appState.scanState = 'STOPPED';
    syncRtlConnectionState();
  });
  startBridgePolling(runtime);
  syncRtlConnectionState();
}

function stopRtlTcpClient(clientId) {
  const runtime = rtlClientRuntimes.get(clientId);
  rtlClientRuntimes.delete(clientId);
  if (runtime) {
    clearInterval(runtime.pollInterval);
    try { runtime.proc.kill('SIGTERM'); } catch (e) {}
  }
  sourceTraces[clientId] = [];
  const client = appState.rtlClients.find(item => item.id === clientId);
  if (client) client.state = 'DISCONNECTED';
  syncRtlConnectionState();
}

function requestBridge(runtime, path, payload, callback, retryCount = 0, epoch = runtime.commandEpoch) {
  if (rtlClientRuntimes.get(runtime.clientId) !== runtime || runtime.commandEpoch !== epoch) return;
  const postData = payload === undefined ? null : JSON.stringify(payload);
  const options = {
    hostname: '127.0.0.1',
    port: runtime.bridgePort,
    path,
    method: postData === null ? 'GET' : 'POST',
    headers: postData === null ? {} : {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  const req = http.request(options, res => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      if (callback && rtlClientRuntimes.get(runtime.clientId) === runtime && runtime.commandEpoch === epoch) callback(res, body);
    });
  });
  req.on('error', () => {
    if (retryCount < 10 && rtlClientRuntimes.get(runtime.clientId) === runtime) {
      setTimeout(() => requestBridge(runtime, path, payload, callback, retryCount + 1, epoch), 100);
    } else if (callback && runtime.commandEpoch === epoch) {
      callback(null, 'Bridge did not respond');
    }
  });
  req.setTimeout(5000, () => req.destroy());
  if (postData !== null) req.write(postData);
  req.end();
}

function broadcastBridgeRequest(path, payload, callback) {
  for (const runtime of rtlClientRuntimes.values()) requestBridge(runtime, path, payload, callback);
}

// Configure and restart in order. Ignore polls from before this command, including a previous
// single sweep's completion, until the bridge has acknowledged the new run.
function restartRtlSweep(runtime, configuration = {}) {
  runtime.commandEpoch++;
  runtime.pendingSweepStart = true;
  runtime.lastSweepComplete = false;
  runtime.progress = null;
  sourceTraces[runtime.clientId] = [];
  const failed = () => {
    runtime.pendingSweepStart = false;
    const client = appState.rtlClients.find(item => item.id === runtime.clientId);
    if (client) { client.state = 'ERROR'; client.error = 'Could not start sweep'; }
    syncRtlConnectionState();
  };
  requestBridge(runtime, '/configuration', Object.assign({}, configuration, {
    repeat: appState.scanMode === 'SINGLE' ? 1 : 255
  }), response => {
    if (!response || response.statusCode !== 200) return failed();
    if (appState.scanState !== 'SCANNING') { runtime.pendingSweepStart = false; return; }
    requestBridge(runtime, '/sweep/start', undefined, started => {
      if (!started || started.statusCode !== 200) return failed();
      runtime.lastProcessedSweepId = -1;
      runtime.pendingSweepStart = false;
    });
  });
}

// One-shot bias read (e.g. an explicit re-Connect while already connected). No periodic polling:
// the console GETs + SUBSCRIBEs bias on connect, so changes arrive as device EVENTs.
function requestBiasRefresh() {
  try {
    let cmds = '';
    for (let i = 0; i < 6; i++) cmds += `get 0107047${i}\n`;
    fs.appendFileSync(CMD_FILE, cmds);
  } catch (e) {
    console.error('[BIAS REFRESH ERR]', e.message);
  }
}

// A bias change is only shown as done once the device reports it; unconfirmed requests expire.
const BIAS_CONFIRM_TIMEOUT_MS = 6000;
setInterval(() => {
  const now = Date.now();
  for (const [ant, pend] of Object.entries(appState.antennaBiasPending)) {
    if (now - pend.t > BIAS_CONFIRM_TIMEOUT_MS) {
      delete appState.antennaBiasPending[ant];
      appState.status = `BIAS CHANGE ON ANTENNA ${ant} NOT CONFIRMED BY THE AD600`;
      console.log(`[BIAS] Antenna ${ant} change to ${pend.enabled ? 'ON' : 'OFF'} was not confirmed`);
    }
  }
}, 1000);

function startBridgePolling(runtime) {
  runtime.pollInterval = setInterval(() => {
    if (rtlClientRuntimes.get(runtime.clientId) !== runtime || runtime.pollInFlight) return;
    runtime.pollInFlight = true;
    const pollEpoch = runtime.commandEpoch;
    const req = http.get(`http://127.0.0.1:${runtime.bridgePort}/trace`, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        runtime.pollInFlight = false;
        if (res.statusCode !== 200 || rtlClientRuntimes.get(runtime.clientId) !== runtime ||
            pollEpoch !== runtime.commandEpoch || runtime.pendingSweepStart) return;
        try {
          const json = JSON.parse(body);
          runtime.progress = json.sweeping ? json.progress : null;
          const expectedGrid = runtime.grid;
          const gridMatchesConfig = json.startHz === expectedGrid.startHz &&
            json.stopHz === expectedGrid.stopHz && json.stepHz === expectedGrid.stepHz;
          if (json.startHz && json.stopHz && json.stepHz && gridMatchesConfig) {
            runtime.grid = {
              startHz: json.startHz,
              stopHz: json.stopHz,
              stepHz: json.stepHz,
              pointCount: json.pointCount || (json.series && json.series[0] ? json.series[0].amplitudesDbfs.length : 0)
            };
          }
          if (!Array.isArray(json.series) || !json.series[0]?.amplitudesDbfs?.length ||
              appState.scanState !== 'SCANNING' || !gridMatchesConfig) return;
          if (json.sweepId === undefined || json.sweepId === runtime.lastProcessedSweepId) return;
          runtime.lastProcessedSweepId = json.sweepId;
          runtime.lastSweepComplete = json.sweeping === false;
          const series = json.series[0];
          const rawAmps = (series && series.amplitudesDbfs) || [];
          const previous = sourceTraces[runtime.clientId] || [];
          if (rawAmps.length) {
            sourceTraces[runtime.clientId] = rawAmps.map((value, index) => {
              if (value > TRACE_FLOOR_DBFS && value <= TRACE_CEILING_DBFS) return value;
              return previous[index] !== undefined ? previous[index] : TRACE_FLOOR_DBFS - 5;
            });
          }
          appState.scansCaptured = Math.max(appState.scansCaptured, json.sweepCount || 0);
          appState.lastScanTime = Date.now();
          syncRtlConnectionState();

          if (appState.scanMode === 'SINGLE' && enabledRtlClients().length > 0 &&
              enabledRtlClients().every(client => {
                const activeRuntime = rtlClientRuntimes.get(client.id);
                return activeRuntime && activeRuntime.lastSweepComplete;
              })) {
            appState.scanState = 'STOPPED';
            for (const runtime of rtlClientRuntimes.values()) {
              runtime.commandEpoch++;
              runtime.pendingSweepStart = false;
              runtime.progress = null;
            }
            broadcastBridgeRequest('/sweep/stop');
            syncRtlConnectionState();
          }
        } catch (e) {}
      });
    });
    req.setTimeout(5000, () => req.destroy());
    req.on('error', () => { runtime.pollInFlight = false; });
  }, 200);
}

function stopAllRtlTcpClients() {
  for (const client of appState.rtlClients) {
    client.enabled = false;
    stopRtlTcpClient(client.id);
  }
  appState.antennaBiasPending = {};
}

function clearSourceTraces() {
  sourceTraces = {};
  for (const client of enabledRtlClients()) sourceTraces[client.id] = [];
  appState.scansCaptured = 0;
  appState.lastScanTime = null;
  for (const runtime of rtlClientRuntimes.values()) {
    runtime.lastProcessedSweepId = -1;
    runtime.lastSweepComplete = false;
  }
}

function initAcnSpectrumIngest() {
  getNetworkInterfaces();
}

// Shared frequency-band <optgroup> markup for the display-zoom selector and every per-antenna /
// per-pair range selector, so the preset list only has to be edited in one place.
function bandOptionsHtml(selectedValue, customLabel) {
  customLabel = customLabel || 'Custom...';
  const sel = v => (v === selectedValue ? ' selected' : '');
  return `
            <optgroup label="Wireless Mic Bands — Shure">
              <option value="G57"${sel('G57')}>G57: 470 – 608 MHz</option>
              <option value="G57_PLUS"${sel('G57_PLUS')}>G57+: 470 – 616 MHz</option>
              <option value="G10"${sel('G10')}>G10: 470 – 542 MHz</option>
              <option value="H22"${sel('H22')}>H22: 518 – 584 MHz</option>
              <option value="J8"${sel('J8')}>J8: 626 – 664 MHz</option>
              <option value="J8A"${sel('J8A')}>J8A: 554 – 616 MHz</option>
              <option value="K54"${sel('K54')}>K54: 608 – 663 MHz</option>
              <option value="X55"${sel('X55')}>X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Wireless Mic Bands — Sennheiser">
              <option value="A1_A4"${sel('A1_A4')}>EM 6000 A1–A4: 470 – 558 MHz</option>
              <option value="A5_A8"${sel('A5_A8')}>EM 6000 A5–A8: 550 – 638 MHz</option>
              <option value="S_6000_B1_B4"${sel('S_6000_B1_B4')}>EM 6000 B1–B4: 630 – 718 MHz</option>
              <option value="S_6000_B5_B8"${sel('S_6000_B5_B8')}>EM 6000 B5–B8: 710 – 798 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Evolution G1 — Legacy">
              <option value="S_G1_A"${sel('S_G1_A')}>G1 A: 518 – 550 MHz</option>
              <option value="S_G1_B"${sel('S_G1_B')}>G1 B: 630 – 662 MHz</option>
              <option value="S_G1_C"${sel('S_G1_C')}>G1 C: 740 – 772 MHz</option>
              <option value="S_G1_D"${sel('S_G1_D')}>G1 D: 790 – 822 MHz</option>
              <option value="S_G1_E"${sel('S_G1_E')}>G1 E: 838 – 870 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Evolution G2 — Legacy">
              <option value="S_G2_A"${sel('S_G2_A')}>G2 A: 518 – 554 MHz</option>
              <option value="S_G2_B"${sel('S_G2_B')}>G2 B: 626 – 662 MHz</option>
              <option value="S_G2_C"${sel('S_G2_C')}>G2 C: 740 – 776 MHz</option>
              <option value="S_G2_D"${sel('S_G2_D')}>G2 D: 786 – 822 MHz</option>
              <option value="S_G2_E"${sel('S_G2_E')}>G2 E: 830 – 866 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Evolution G3">
              <option value="S_G3_A"${sel('S_G3_A')}>G3 A: 516 – 558 MHz</option>
              <option value="S_G3_A2"${sel('S_G3_A2')}>G3 100 LE A2: 518 – 554 MHz</option>
              <option value="S_G3_G"${sel('S_G3_G')}>G3 G: 566 – 608 MHz</option>
              <option value="S_G3_B"${sel('S_G3_B')}>G3 B: 626 – 668 MHz</option>
              <option value="S_G3_B2"${sel('S_G3_B2')}>G3 100 LE B2: 626 – 662 MHz</option>
              <option value="S_G3_C"${sel('S_G3_C')}>G3 C: 734 – 776 MHz</option>
              <option value="S_G3_D"${sel('S_G3_D')}>G3 D: 780 – 822 MHz</option>
              <option value="S_G3_E"${sel('S_G3_E')}>G3 E: 823 – 865 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Evolution G4">
              <option value="S_G4_A1"${sel('S_G4_A1')}>G4 A1: 470 – 516 MHz</option>
              <option value="S_G4_A"${sel('S_G4_A')}>G4 A: 516 – 558 MHz</option>
              <option value="S_G4_AS"${sel('S_G4_AS')}>G4 AS: 520 – 558 MHz</option>
              <option value="S_G4_G"${sel('S_G4_G')}>G4 G: 566 – 608 MHz</option>
              <option value="S_G4_GB"${sel('S_G4_GB')}>G4 GB: 606 – 648 MHz</option>
              <option value="S_G4_B"${sel('S_G4_B')}>G4 B: 626 – 668 MHz</option>
              <option value="S_G4_C"${sel('S_G4_C')}>G4 C: 734 – 776 MHz</option>
              <option value="S_G4_CTH"${sel('S_G4_CTH')}>G4 C-TH: 748.2 – 757.8 MHz</option>
              <option value="S_G4_D"${sel('S_G4_D')}>G4 D: 780 – 822 MHz</option>
              <option value="S_G4_TH"${sel('S_G4_TH')}>G4 TH: 794 – 806 MHz</option>
              <option value="S_G4_JB"${sel('S_G4_JB')}>G4 JB: 806 – 810 MHz</option>
              <option value="S_G4_E"${sel('S_G4_E')}>G4 E: 823 – 865 MHz</option>
              <option value="S_G4_KP"${sel('S_G4_KP')}>G4 K+: 925 – 937.5 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Evolution G4 300/500">
              <option value="S_G4_AWPLUS"${sel('S_G4_AWPLUS')}>G4 AW+: 470 – 558 MHz</option>
              <option value="S_G4_AW30"${sel('S_G4_AW30')}>G4 AW30: 470 – 558 MHz</option>
              <option value="S_G4_GW1"${sel('S_G4_GW1')}>G4 GW1: 558 – 608 MHz</option>
              <option value="S_G4_GW"${sel('S_G4_GW')}>G4 GW: 558 – 626 MHz</option>
              <option value="S_G4_GBW"${sel('S_G4_GBW')}>G4 GBW: 606 – 678 MHz</option>
              <option value="S_G4_BW"${sel('S_G4_BW')}>G4 BW: 626 – 698 MHz</option>
              <option value="S_G4_CW"${sel('S_G4_CW')}>G4 CW: 718 – 790 MHz</option>
              <option value="S_G4_CWTH"${sel('S_G4_CWTH')}>G4 CW-TH: 748.2 – 757.8 MHz</option>
              <option value="S_G4_DW"${sel('S_G4_DW')}>G4 DW: 790 – 865 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser 2000 Series">
              <option value="S_2000_AW"${sel('S_2000_AW')}>2000 AW: 516 – 558 MHz</option>
              <option value="S_2000_GW"${sel('S_2000_GW')}>2000 GW: 558 – 626 MHz</option>
              <option value="S_2000_BW"${sel('S_2000_BW')}>2000 BW: 626 – 698 MHz</option>
              <option value="S_2000_CW"${sel('S_2000_CW')}>2000 CW: 718 – 790 MHz</option>
              <option value="S_2000_DW"${sel('S_2000_DW')}>2000 DW: 790 – 865 MHz</option>
              <option value="S_2000_AWPLUS"${sel('S_2000_AWPLUS')}>2000 AW+: 470 – 558 MHz</option>
              <option value="S_2000_GW1"${sel('S_2000_GW1')}>2000 GW1: 558 – 608 MHz</option>
              <option value="S_2000_GBW"${sel('S_2000_GBW')}>2000 GBW: 606 – 678 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser 3000/5000 Series — Legacy">
              <option value="S_3000_A"${sel('S_3000_A')}>3000/5000 A: 470 – 560 MHz</option>
              <option value="S_3000_B"${sel('S_3000_B')}>3000/5000 B: 518 – 608 MHz</option>
              <option value="S_3000_C"${sel('S_3000_C')}>3000/5000 C: 548 – 638 MHz</option>
              <option value="S_3000_D"${sel('S_3000_D')}>3000/5000 D: 614 – 704 MHz</option>
              <option value="S_3000_E"${sel('S_3000_E')}>3000/5000 E: 678 – 768 MHz</option>
              <option value="S_3000_F"${sel('S_3000_F')}>3000/5000 F: 708 – 798 MHz</option>
              <option value="S_3000_G"${sel('S_3000_G')}>3000/5000 G: 776 – 866 MHz</option>
              <option value="S_3000_H"${sel('S_3000_H')}>3000/5000 H: 814 – 904 MHz</option>
              <option value="S_3000_II_L"${sel('S_3000_II_L')}>3000/5000-II L: 470 – 638 MHz</option>
              <option value="S_3000_II_N"${sel('S_3000_II_N')}>3000/5000-II N: 614 – 798 MHz</option>
              <option value="S_3000_II_P"${sel('S_3000_II_P')}>3000/5000-II P: 776 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser EW-D Digital">
              <option value="S_EWD_Q1_6"${sel('S_EWD_Q1_6')}>EW-D Q1-6: 470.2 – 526 MHz</option>
              <option value="S_EWD_R1_6"${sel('S_EWD_R1_6')}>EW-D R1-6: 520 – 576 MHz</option>
              <option value="S_EWD_R4_9"${sel('S_EWD_R4_9')}>EW-D R4-9: 552 – 607.8 MHz</option>
              <option value="S_EWD_S1_7"${sel('S_EWD_S1_7')}>EW-D S1-7: 606.2 – 662 MHz</option>
              <option value="S_EWD_S4_7"${sel('S_EWD_S4_7')}>EW-D S4-7: 630 – 662 MHz</option>
              <option value="S_EWD_S7_10"${sel('S_EWD_S7_10')}>EW-D S7-10: 662 – 693.8 MHz</option>
              <option value="S_EWD_U1_5"${sel('S_EWD_U1_5')}>EW-D U1/5: 823.2–831.8 / 863.2–864.8 MHz</option>
              <option value="S_EWD_V3_4"${sel('S_EWD_V3_4')}>EW-D V3-4: 925.2 – 937.3 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF"${sel('VHF')}>VHF: 174 – 216 MHz</option>
              <option value="470_524"${sel('470_524')}>Low UHF: 470 – 524 MHz</option>
              <option value="524_620"${sel('524_620')}>Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000"${sel('608_1000')}>Upper UHF: 608 – 1000 MHz</option>
              <option value="AFTRCC"${sel('AFTRCC')}>AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000"${sel('470_1000')}>470 – 1000 MHz (1 GHz)</option>
              <option value="470_1766"${sel('470_1766')}>470 – 1766 MHz (R820T upper span)</option>
              <option value="174_1000"${sel('174_1000')}>174 – 1000 MHz</option>
              <option value="FULL_SPAN"${sel('FULL_SPAN')}>Full Span: 24 – 1766 MHz (R820T)</option>
            </optgroup>
            <optgroup label="Custom Range">
              <option value="CUSTOM"${sel('CUSTOM')}>${customLabel}</option>
            </optgroup>`;
}

// 3. Web UI HTML Dashboard Template
const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RTL-SDR Web Spectrum Scanner</title>
  <script src="/vendor/chart.umd.min.js"></script>
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

    .rtl-client-manager {
      padding: 9px 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: rgba(7, 11, 19, 0.45);
    }

    .rtl-client-manager-header, .rtl-client-add-row {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .rtl-client-manager-header { justify-content: space-between; margin-bottom: 7px; }
    .rtl-client-hint, .rtl-client-endpoint { color: var(--text-muted); font-size: 11px; }
    .rtl-client-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(245px, 1fr)); gap: 6px; }
    .rtl-client-card { min-width: 0; display: flex; flex-direction: column; gap: 7px; padding: 8px 9px; background: var(--bg-dark); border: 1px solid var(--border); border-left: 3px solid var(--receiver-color, var(--accent)); border-radius: 5px; }
    .rtl-client-card-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; min-width: 0; }
    .rtl-client-main { display: flex; min-width: 0; align-items: center; gap: 8px; }
    .rtl-client-main input { accent-color: var(--accent); }
    .rtl-client-name { font-size: 12px; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .rtl-client-meta { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
    .rtl-client-state { color: var(--text-muted); font-size: 10px; text-transform: uppercase; }
    .rtl-client-state.connected { color: var(--accent); }
    .rtl-client-state.error { color: var(--danger); }
    .rtl-client-remove { padding: 3px 7px; color: var(--text-muted); cursor: pointer; }
    .rtl-client-remove:disabled { opacity: 0.45; cursor: default; }
    .rtl-client-slot { flex: 0 0 auto; width: 20px; height: 20px; display: grid; place-items: center; border: 1px solid currentColor; border-radius: 4px; font-size: 11px; font-weight: 800; }
    .rtl-client-range-select { width: 100%; padding: 5px 7px; color: var(--text-main); background: var(--bg-dark); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; }
    .rtl-client-custom-range { display: flex; align-items: center; gap: 5px; color: var(--text-muted); font-size: 10px; }
    .rtl-client-custom-range[hidden] { display: none; }
    .rtl-client-custom-range input { min-width: 0; width: 76px; padding: 4px 5px; color: var(--text-main); background: var(--bg-dark); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; }
    .rtl-client-custom-range button { padding: 4px 7px; font-size: 10px; }
    .antenna-cards-grid { display: none !important; }
    .rtl-client-add-row { margin-top: 7px; flex-wrap: wrap; }
    .rtl-client-add-row input { min-width: 100px; padding: 5px 7px; color: var(--text-main); background: var(--bg-dark); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; }
    .rtl-client-add-row #rtlClientName { width: 150px; }
    .rtl-client-add-row #rtlClientHost { flex: 1; }
    .rtl-client-add-row #rtlClientPort { width: 80px; }
    #rtlClientMessage { min-height: 13px; margin-top: 4px; color: var(--danger); font-size: 11px; }

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

    .bias-btn.pending {
      outline: 1px dashed #ffaa00;
      animation: bias-pending 0.8s ease-in-out infinite alternate;
    }
    @keyframes bias-pending { from { opacity: 1; } to { opacity: 0.45; } }

    .view-only-badge {
      display: none;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.04em;
      color: #ffaa00;
      border: 1px solid rgba(255, 170, 0, 0.4);
      border-radius: 12px;
      padding: 3px 8px;
    }
    body.view-only .view-only-badge { display: inline-block; }
    body.view-only .controls-panel { pointer-events: none; opacity: 0.55; }

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

    .graph-band-labels {
      color: #cbd5e1;
      font-size: 11px;
      font-weight: 600;
      line-height: 1.4;
    }

    .chart-wrapper {
      position: relative;
      flex: 1;
      min-height: 280px;
    }

    #card_B, #card_C, #card_D, #card_E, #card_F,
    #card_AB, #card_CD, #card_EF { display: none !important; }
    #card_A .antenna-card-label input, #card_A .ant-rename-btn,
    #card_A .max-btn, #card_A .bias-btn, #card_A .antenna-badge { display: none !important; }
  </style>
</head>
<body>

  <div class="header">
    <div class="brand">
      <div class="title">RTL-SDR Spectrum Scanner</div>
    </div>
    <div class="header-right" style="display: flex; flex-direction: column; align-items: flex-end; gap: 5px;">
      <div class="status-badge">
        <div id="statusDot" class="status-dot"></div>
        <span id="statusText">NO RTL_TCP CLIENTS ENABLED</span>
      </div>
      <span class="view-only-badge" title="Controls are limited to the host computer (RTL_REMOTE_CONTROL=0)">VIEW ONLY</span>
    </div>
  </div>

  <!-- Interactive Controls Panel -->
  <div class="controls-panel">
    <div class="controls-row">
      <div class="control-group" style="display: none;">
        <label class="control-label">Network Interface (NIC)</label>
        <select id="ifaceSelect" onchange="onIfaceSelect(this.value)">
          <option value="ALL">ALL Interfaces (Auto-Probe)</option>
        </select>
      </div>

      <div class="control-group">
        <label class="control-label">Spectrum Display Range (Zoom)</label>
        <div style="display: flex; gap: 8px; align-items: center;">
          <select id="displayZoomSelect" onchange="onDisplayZoomSelect(this.value)">
            <option value="LOCKED" selected>Auto-Fit Receiver Range</option>
            ${bandOptionsHtml('', 'Custom Display Span...')}
          </select>
          <button id="lockZoomBtn" class="btn-lock active" onclick="toggleLockZoom()" title="Lock display zoom to the receiver scan range">
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
        <label class="control-label">Spectrum Bin Width</label>
        <select id="rbwSelect" onchange="onRbwSelect(this.value)">
          <option value="50000">50 kHz</option>
          <option value="100000">100 kHz</option>
          <option value="350000" selected>350 kHz</option>
          <option value="900000">900 kHz</option>
        </select>
      </div>
    </div>

    <!-- Scan controls -->
    <div class="control-group">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
        <label class="control-label">Receiver Scan Ranges</label>
        <span id="hwSweepRangeIndicator" style="font-size: 11px; color: var(--accent); font-weight: 600;">
          Configure each receiver above
        </span>
      </div>
      <div class="diversity-row" style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;">
        <!-- Continuous / Single Sweep + Start/Stop Spectrum Scan -->
        <div class="scan-control-group" style="display: flex; align-items: center; gap: 8px; margin-left: auto;">
          <div class="scan-mode-toggle">
            <button id="modeBtn_continuous" class="mode-btn active" onclick="setScanMode('CONTINUOUS')" title="Continuous Real-Time Spectrum Sweeping">Continuous</button>
            <button id="modeBtn_single" class="mode-btn" onclick="setScanMode('SINGLE')" title="Single Sweep Snapshot & Stop">Single Sweep</button>
          </div>
          <button id="scanBtn" class="btn-scan" onclick="toggleScan()">START SPECTRUM SCAN</button>
        </div>
      </div>
      <section class="rtl-client-manager" aria-label="Antennas">
        <div class="rtl-client-manager-header">
          <label class="control-label">Antennas</label>
          <span class="rtl-client-hint">Manage up to six rtl_tcp receivers. Each antenna has its own color and frequency range; enabled antennas scan together.</span>
        </div>
        <div id="rtlClientList" class="rtl-client-list"></div>
        <form id="rtlClientForm" class="rtl-client-add-row" onsubmit="addRtlClient(event)">
          <input id="rtlClientName" type="text" maxlength="64" placeholder="Antenna name" value="RTL-SDR 2" required>
          <input id="rtlClientHost" type="text" maxlength="253" placeholder="rtl-sdr.local or 192.168.1.20" required>
          <input id="rtlClientPort" type="number" min="1" max="65535" value="1234" aria-label="rtl_tcp port" required>
          <button class="btn-scan" type="submit" style="padding: 5px 11px; font-size: 11px;">ADD ANTENNA</button>
        </form>
        <div id="rtlClientMessage" role="status" aria-live="polite"></div>
      </section>
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
            ${bandOptionsHtml('CUSTOM')}
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
                <span id="antNameSpan_A" style="color: #00ffaa;">Shared Scan Range</span>
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
            ${bandOptionsHtml('CUSTOM')}
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
            ${bandOptionsHtml('CUSTOM')}
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
            ${bandOptionsHtml('G10')}
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
            ${bandOptionsHtml('G10')}
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
            ${bandOptionsHtml('H22')}
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
            ${bandOptionsHtml('J8A')}
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
            ${bandOptionsHtml('J8A')}
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
            ${bandOptionsHtml('CUSTOM')}
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
      <div class="stat-label">Active rtl_tcp Host</div>
      <div class="stat-value" id="targetIp">--.--.--.--</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Enabled Receivers</div>
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
        <strong>RF Spectrum Power Sweep (dBFS)</strong>
        <span id="graphBandLabels" class="graph-band-labels" aria-live="polite"></span>
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
    const ANT_COLORS = ${JSON.stringify(ANT_COLORS)}; // generated from the server's single source of truth

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
      if (!c) {
        return (typeof computeActiveEnvelope === 'function') ? computeActiveEnvelope() : [470.0, 524.0];
      }
      const labels = c.data.labels || [];
      const scale = c.scales && c.scales.x;
      const minLabel = c.options.scales.x.min !== undefined ? c.options.scales.x.min : (scale ? scale.min : labels[0]);
      const maxLabel = c.options.scales.x.max !== undefined ? c.options.scales.x.max : (scale ? scale.max : labels[labels.length - 1]);
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
      'S_G1_A': [518.0, 550.0],
      'S_G1_B': [630.0, 662.0],
      'S_G1_C': [740.0, 772.0],
      'S_G1_D': [790.0, 822.0],
      'S_G1_E': [838.0, 870.0],
      'S_G2_A': [518.0, 554.0],
      'S_G2_B': [626.0, 662.0],
      'S_G2_C': [740.0, 776.0],
      'S_G2_D': [786.0, 822.0],
      'S_G2_E': [830.0, 866.0],
      'S_G3_A': [516.0, 558.0],
      'S_G3_A2': [518.0, 554.0],
      'S_G3_G': [566.0, 608.0],
      'S_G3_B': [626.0, 668.0],
      'S_G3_B2': [626.0, 662.0],
      'S_G3_C': [734.0, 776.0],
      'S_G3_D': [780.0, 822.0],
      'S_G3_E': [823.0, 865.0],
      'S_G4_A1': [470.0, 516.0],
      'S_G4_A': [516.0, 558.0],
      'S_G4_AS': [520.0, 558.0],
      'S_G4_G': [566.0, 608.0],
      'S_G4_GB': [606.0, 648.0],
      'S_G4_B': [626.0, 668.0],
      'S_G4_C': [734.0, 776.0],
      'S_G4_CTH': [748.2, 757.8],
      'S_G4_D': [780.0, 822.0],
      'S_G4_TH': [794.0, 806.0],
      'S_G4_JB': [806.0, 810.0],
      'S_G4_E': [823.0, 865.0],
      'S_G4_KP': [925.0, 937.5],
      'S_G4_AWPLUS': [470.0, 558.0],
      'S_G4_AW30': [470.0, 558.0],
      'S_G4_GW1': [558.0, 608.0],
      'S_G4_GW': [558.0, 626.0],
      'S_G4_GBW': [606.0, 678.0],
      'S_G4_BW': [626.0, 698.0],
      'S_G4_CW': [718.0, 790.0],
      'S_G4_CWTH': [748.2, 757.8],
      'S_G4_DW': [790.0, 865.0],
      'S_2000_AW': [516.0, 558.0],
      'S_2000_GW': [558.0, 626.0],
      'S_2000_BW': [626.0, 698.0],
      'S_2000_CW': [718.0, 790.0],
      'S_2000_DW': [790.0, 865.0],
      'S_2000_AWPLUS': [470.0, 558.0],
      'S_2000_GW1': [558.0, 608.0],
      'S_2000_GBW': [606.0, 678.0],
      'S_3000_A': [470.0, 560.0],
      'S_3000_B': [518.0, 608.0],
      'S_3000_C': [548.0, 638.0],
      'S_3000_D': [614.0, 704.0],
      'S_3000_E': [678.0, 768.0],
      'S_3000_F': [708.0, 798.0],
      'S_3000_G': [776.0, 866.0],
      'S_3000_H': [814.0, 904.0],
      'S_3000_II_L': [470.0, 638.0],
      'S_3000_II_N': [614.0, 798.0],
      'S_3000_II_P': [776.0, 960.0],
      'A1_A4': [470.0, 558.0],
      'A5_A8': [550.0, 638.0],
      'S_6000_B1_B4': [630.0, 718.0],
      'S_6000_B5_B8': [710.0, 798.0],
      'S_EWD_Q1_6': [470.2, 526.0],
      'S_EWD_R1_6': [520.0, 576.0],
      'S_EWD_R4_9': [552.0, 607.8],
      'S_EWD_S1_7': [606.2, 662.0],
      'S_EWD_S4_7': [630.0, 662.0],
      'S_EWD_S7_10': [662.0, 693.8],
      'S_EWD_U1_5': [823.2, 864.8],
      'S_EWD_V3_4': [925.2, 937.3],
      'VHF': [174.0, 216.0],
      '470_524': [470.0, 524.0],
      '524_620': [524.0, 620.0],
      '608_1000': [608.0, 1000.0],
      'AFTRCC': [1435.0, 1525.0],
      '470_1000': [470.0, 1000.0],
      '470_1766': [470.0, 1766.0],
      '174_1000': [174.0, 1000.0],
      'FULL_SPAN': [24.0, 1766.0]
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

    let currentRtlClients = [];

    function getActiveAntennas() {
      const checked = Array.from(document.querySelectorAll('input[name="antennaCb"]:checked')).map(el => el.value);
      return checked.length > 0 ? checked : ['A'];
    }

    function computeActiveEnvelope() {
      const activeReceivers = currentRtlClients.filter(client => client.enabled &&
        Number.isFinite(Number(client.startMhz)) && Number.isFinite(Number(client.stopMhz)) && Number(client.stopMhz) > Number(client.startMhz));
      if (activeReceivers.length) {
        return [
          Math.min(...activeReceivers.map(client => Number(client.startMhz))),
          Math.max(...activeReceivers.map(client => Number(client.stopMhz)))
        ];
      }
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
    // Highest server config sequence this page has applied or produced. A higher one in /api/status
    // means another viewer changed the shared setup, so this page reloads its cards from the server
    // (otherwise its next change would push stale ranges for every antenna).
    let knownConfigSeq = 0;
    let localSyncPending = false;
    function noteOwnConfigSeq(seq) {
      if (seq) {
        targetConfigSeq = seq;
        knownConfigSeq = Math.max(knownConfigSeq, seq);
      }
    }

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
    // Receiver ranges are managed per profile; this helper updates the shared chart viewport only.
    function syncHardwareAndZoom(immediate = false, push = true) {
      updateCardActiveStyles();
      updateGraphBandLabels();
      const [envStart, envEnd] = computeActiveEnvelope();

      const ind = document.getElementById('hwSweepRangeIndicator');
      if (ind) {
        ind.innerText = currentRtlClients.some(client => client.enabled)
          ? 'Enabled span: ' + envStart.toFixed(1) + ' – ' + envEnd.toFixed(1) + ' MHz'
          : 'No receivers enabled';
      }

      // Immediately clear spectrum view & adjust zoom window to the new target range
      clearSpectrumDisplay(envStart, envEnd);

      if (lockZoom) {
        const opt = document.querySelector('#displayZoomSelect option[value="LOCKED"]');
        if (opt) {
          opt.innerText = 'Auto-Fit (' + envStart.toFixed(0) + '–' + envEnd.toFixed(0) + ' MHz)';
        }
      }

      clearTimeout(syncDebounceTimer);
      localSyncPending = false;
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
        refreshTraceBandLabels();
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
        refreshTraceBandLabels();
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
        refreshTraceBandLabels();
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
        refreshTraceBandLabels();
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

    function extendChartLabelsForViewport(startMhz, endMhz) {
      // The x axis is numeric MHz, so zooming only changes its bounds. The labels remain useful
      // to channel overlays and markers without resampling receiver traces.
      chart.data.labels = buildBaselineLabels(startMhz, endMhz);
    }

    function applyChartZoom(startMhz, endMhz) {
      if (!chart) return;
      const s = Math.min(startMhz, endMhz);
      const e = Math.max(startMhz, endMhz);
      const hasRealData = chart.data.datasets && chart.data.datasets.some(d => d.data && d.data.length > 0 && !d.label.includes('Grid Baseline'));

      if (!hasRealData || !chart.data.labels || chart.data.labels.length === 0) {
        chart.data.labels = buildBaselineLabels(s, e);
        chart.options.scales.x.min = s;
        chart.options.scales.x.max = e;
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

      extendChartLabelsForViewport(s, e);
      chart.options.scales.x.min = s;
      chart.options.scales.x.max = e;
    }

    function refreshTraceBandLabels() {
      if (!chart || !Array.isArray(chart.data.datasets)) return;
      updateGraphBandLabels();
      ['A', 'B', 'C', 'D', 'E', 'F'].forEach(ant => {
        const seriesLabel = ant === 'A' ? 'RTL-SDR' : 'Antenna ' + ant;
        const select = document.getElementById('antRangeSelect_' + ant);
        const selectedBand = select && select.value !== 'CUSTOM'
          ? select.options[select.selectedIndex]?.textContent.split(':')[0].trim()
          : 'Custom';
        const range = localAntennaRanges[ant];
        if (!range) return;
        chart.data.datasets.forEach(dataset => {
          if (!dataset.label || !dataset.label.startsWith(seriesLabel + ' — ')) return;
          const maxHoldSuffix = dataset.label.endsWith(' Max Hold') ? ' Max Hold' : '';
          dataset.label = seriesLabel + ' — ' + (selectedBand || 'Band') + ' (' +
            range[0].toFixed(1) + '–' + range[1].toFixed(1) + ' MHz)' + maxHoldSuffix;
        });
      });
      chart.update('none');
    }

    function updateGraphBandLabels() {
      const container = document.getElementById('graphBandLabels');
      if (!container) return;
      const visibleLabels = [];
      const displayedClients = currentRtlClients.filter(client => client.enabled);
      (displayedClients.length ? displayedClients : currentRtlClients).forEach(client => {
        const startMhz = Number(client.startMhz);
        const stopMhz = Number(client.stopMhz);
        if (!Number.isFinite(startMhz) || !Number.isFinite(stopMhz) || stopMhz <= startMhz) return;
        const preset = Object.keys(RANGE_PRESETS).find(key =>
          Math.abs(RANGE_PRESETS[key][0] - startMhz) < 0.001 && Math.abs(RANGE_PRESETS[key][1] - stopMhz) < 0.001);
        const label = (client.slot || 'A') + ' ' + client.name + ' · ' + (preset || 'Custom') +
          ' (' + startMhz.toFixed(1) + '–' + stopMhz.toFixed(1) + ' MHz)';
        if (!visibleLabels.includes(label)) visibleLabels.push(label);
      });
      container.textContent = visibleLabels.join('  ·  ');
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
        if (json) noteOwnConfigSeq(json.sweepConfigSeq);
      } catch (e) {
        console.error('Spectrum bin-width update failed:', e);
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
          interaction: { intersect: false, mode: 'nearest', axis: 'x' },
          plugins: {
            legend: { display: true, labels: { color: '#8a99ad' } },
            tooltip: {
              filter: (item) => !hoveredDtvChannel,
              backgroundColor: 'rgba(18, 24, 38, 0.95)',
              callbacks: {
                title: (items) => 'Frequency: ' + Number(items[0].parsed.x).toFixed(3) + ' MHz',
                label: (item) => item.dataset.label + ': ' + item.parsed.y + ' dBFS'
              }
            }
          },
          scales: {
            x: {
              type: 'linear',
              min: initStart,
              max: initEnd,
              grid: { color: 'rgba(255, 255, 255, 0.08)' },
              ticks: {
                color: '#8a99ad',
                maxTicksLimit: 16,
                callback: function(val) {
                  const f = Number(val);
                  if (!Number.isFinite(f)) return val;
                  return (f % 1 === 0 ? f.toFixed(0) : f.toFixed(1)) + ' MHz';
                }
              },
              title: { display: true, text: 'Frequency (MHz)', color: '#8a99ad' }
            },
            y: {
              min: -120,
              max: 0,
              grid: { color: 'rgba(255, 255, 255, 0.06)' },
              ticks: { color: '#8a99ad', stepSize: 10 },
              title: { display: true, text: 'Power (dBFS)', color: '#8a99ad' }
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

    async function toggleScan() {
      const newAction = isScanning ? 'stop' : 'start';
      if (newAction === 'start') {
        clearSpectrumDisplay();
        currentRtlClients.filter(client => client.enabled).forEach(client => { maxHoldBuffers[client.id] = []; });
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

    let renderedRtlClientSignature = '';
    let displayedRtlClientSignature = '';

    async function postRtlClientAction(payload) {
      const message = document.getElementById('rtlClientMessage');
      if (message) message.textContent = '';
      try {
        const res = await fetch('/api/rtl-clients', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error || 'Could not update rtl_tcp client list');
        if (message) message.textContent = '';
        await fetchStatus();
        return true;
      } catch (e) {
        if (message) message.textContent = e.message || 'Could not update rtl_tcp client list';
        return false;
      }
    }

    function receiverProgressText(client) {
      const progress = client && client.progress;
      if (!progress) return '';
      return 'Sweep ' + progress.percent.toFixed(0) + '% · ' +
        (progress.centerHz / 1e6).toFixed(1) + ' MHz · ' + progress.elapsedSeconds.toFixed(1) + ' s';
    }

    function renderRtlClients(clients) {
      const list = document.getElementById('rtlClientList');
      if (!list) return;
      currentRtlClients = clients;
      list.querySelectorAll('[data-progress-client]').forEach(element => {
        const client = clients.find(item => item.id === element.dataset.progressClient);
        element.textContent = receiverProgressText(client);
      });
      const signature = JSON.stringify(clients.map(client => [client.id, client.name, client.host, client.port,
        client.startMhz, client.stopMhz, client.slot, client.color, client.enabled, client.state, client.error]));
      if (signature === renderedRtlClientSignature) return;
      renderedRtlClientSignature = signature;
      list.replaceChildren();

      clients.forEach(client => {
        const card = document.createElement('div');
        card.className = 'rtl-client-card';
        card.style.setProperty('--receiver-color', client.color || ANT_COLORS[client.slot] || ANT_COLORS.A);

        const head = document.createElement('div');
        head.className = 'rtl-client-card-head';

        const main = document.createElement('label');
        main.className = 'rtl-client-main';
        const enabled = document.createElement('input');
        enabled.type = 'checkbox';
        enabled.checked = !!client.enabled;
        enabled.setAttribute('aria-label', 'Enable ' + client.name);
        enabled.addEventListener('change', () => postRtlClientAction({
          action: 'setEnabled', id: client.id, enabled: enabled.checked
        }));

        const meta = document.createElement('span');
        meta.className = 'rtl-client-meta';
        const slot = document.createElement('span');
        slot.className = 'rtl-client-slot';
        slot.style.color = client.color || ANT_COLORS[client.slot] || ANT_COLORS.A;
        slot.textContent = client.slot || 'A';
        const name = document.createElement('span');
        name.className = 'rtl-client-name';
        name.textContent = client.name;
        const endpoint = document.createElement('span');
        endpoint.className = 'rtl-client-endpoint';
        endpoint.textContent = (client.host.includes(':') ? '[' + client.host + ']' : client.host) + ':' + client.port;
        const state = document.createElement('span');
        state.className = 'rtl-client-state' + (client.state === 'CONNECTED' ? ' connected' : (client.state === 'ERROR' ? ' error' : ''));
        state.textContent = client.error ? ('Error: ' + client.error) : (client.state === 'RECONNECTING' ? 'Reconnecting' : (client.state || 'DISCONNECTED'));
        if (client.error) state.classList.add('error');
        const progress = document.createElement('span');
        progress.className = 'rtl-client-endpoint';
        progress.dataset.progressClient = client.id;
        progress.textContent = receiverProgressText(client);
        meta.append(name, endpoint, state, progress);
        main.append(enabled, slot, meta);

        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'rtl-client-remove';
        remove.textContent = client.id === 'rtl-client-1' ? 'Default' : 'Remove';
        remove.disabled = client.id === 'rtl-client-1';
        remove.title = client.id === 'rtl-client-1' ? 'Disable the default endpoint to stop using it' : 'Remove this rtl_tcp client';
        remove.addEventListener('click', () => postRtlClientAction({ action: 'remove', id: client.id }));

        head.append(main, remove);

        const startMhz = Number(client.startMhz || 470);
        const stopMhz = Number(client.stopMhz || 524);
        const preset = Object.keys(RANGE_PRESETS).find(key =>
          Math.abs(RANGE_PRESETS[key][0] - startMhz) < 0.001 && Math.abs(RANGE_PRESETS[key][1] - stopMhz) < 0.001) || 'CUSTOM';
        const rangeSelect = document.createElement('select');
        rangeSelect.className = 'rtl-client-range-select';
        rangeSelect.setAttribute('aria-label', client.name + ' frequency range');
        rangeSelect.innerHTML = ${JSON.stringify(bandOptionsHtml('CUSTOM'))};
        rangeSelect.value = preset;
        const customRange = document.createElement('div');
        customRange.className = 'rtl-client-custom-range';
        customRange.hidden = preset !== 'CUSTOM';
        const customStart = document.createElement('input');
        customStart.type = 'number';
        customStart.min = '24';
        customStart.max = '1765.9';
        customStart.step = '0.1';
        customStart.value = startMhz.toFixed(1);
        customStart.setAttribute('aria-label', client.name + ' scan start MHz');
        const separator = document.createElement('span');
        separator.textContent = '–';
        const customStop = document.createElement('input');
        customStop.type = 'number';
        customStop.min = '24.1';
        customStop.max = '1766';
        customStop.step = '0.1';
        customStop.value = stopMhz.toFixed(1);
        customStop.setAttribute('aria-label', client.name + ' scan stop MHz');
        const mhz = document.createElement('span');
        mhz.textContent = 'MHz';
        const applyRange = document.createElement('button');
        applyRange.type = 'button';
        applyRange.className = 'btn-scan';
        applyRange.textContent = 'APPLY';
        applyRange.addEventListener('click', () => setRtlClientRange(client.id, customStart.value, customStop.value));
        customRange.append(customStart, separator, customStop, mhz, applyRange);
        rangeSelect.addEventListener('change', () => {
          if (rangeSelect.value === 'CUSTOM') {
            customRange.hidden = false;
            return;
          }
          const range = RANGE_PRESETS[rangeSelect.value];
          if (range) setRtlClientRange(client.id, range[0], range[1]);
        });
        card.append(head, rangeSelect, customRange);
        list.appendChild(card);
      });

      const atLimit = clients.length >= 6;
      const form = document.getElementById('rtlClientForm');
      if (form) {
        form.querySelectorAll('input, button').forEach(input => { input.disabled = atLimit; });
        form.title = atLimit ? 'The AD600 has six antenna slots' : '';
      }
    }

    async function setRtlClientRange(id, startMhz, stopMhz) {
      const start = Number.parseFloat(startMhz);
      const stop = Number.parseFloat(stopMhz);
      if (!Number.isFinite(start) || !Number.isFinite(stop) || start < 24 || stop > 1766 || stop <= start) {
        const message = document.getElementById('rtlClientMessage');
        if (message) message.textContent = 'Enter a valid range from 24 to 1766 MHz';
        return;
      }
      maxHoldBuffers[id] = [];
      await postRtlClientAction({ action: 'setRange', id, startMhz: start, stopMhz: stop });
      syncHardwareAndZoom(true, false);
    }

    async function addRtlClient(event) {
      event.preventDefault();
      const payload = {
        action: 'add',
        name: document.getElementById('rtlClientName').value,
        host: document.getElementById('rtlClientHost').value,
        port: document.getElementById('rtlClientPort').value
      };
      if (await postRtlClientAction(payload)) {
        document.getElementById('rtlClientName').value = 'RTL-SDR';
        document.getElementById('rtlClientHost').value = '';
        document.getElementById('rtlClientPort').value = '1234';
      }
    }

    function clientColor(client) {
      return client.color || ANT_COLORS[client.slot] || ANT_COLORS.A;
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();

        const isConnected = data.connectionState === 'CONNECTED';
        renderRtlClients(data.rtlClients || []);

        const statusEl = document.getElementById('statusText');
        if (statusEl) {
          statusEl.innerText = data.status || (isConnected ? 'CONNECTED' : 'DISCONNECTED');
        }

        document.body.classList.toggle('view-only', data.controlAllowed === false);
        const enabledClientSignature = (data.rtlClients || []).filter(client => client.enabled).map(client => client.id).join('|');
        if (enabledClientSignature !== displayedRtlClientSignature) {
          displayedRtlClientSignature = enabledClientSignature;
          currentRtlClients.forEach(client => { maxHoldBuffers[client.id] = []; });
          syncHardwareAndZoom(true, false);
        }
        if (!localSyncPending && (data.sweepConfigSeq || 0) > knownConfigSeq) {
          applyServerConfig(data);
          updateCardActiveStyles();
          syncHardwareAndZoom(true, false);
        }
        document.getElementById('targetIp').innerText = data.activeTargetIp || '--.--.--.--';
        document.getElementById('antennaVal').innerText = String((data.rtlClients || []).filter(client => client.enabled).length);
        document.getElementById('scansCaptured').innerText = data.scansCaptured;

        const grid = data.grid || { startHz: 470000000, stopHz: 524000000, stepHz: 350000, pointCount: 155 };
        const rbwKhz = Math.round((grid.stepHz || 350000) / 1000);
        document.getElementById('resVal').innerText = rbwKhz + ' kHz bins (' + (grid.pointCount || 155) + ' Pts)';

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

        // Sync Antenna Rename Buttons (locked until connected)
        const isConn = (data.connectionState === 'CONNECTED');
        document.querySelectorAll('.ant-rename-btn').forEach(btn => {
          btn.disabled = !isConn;
          btn.classList.toggle('locked', !isConn);
          btn.title = isConn ? 'Rename antenna (label shown in this app)' : 'Connect to AD600 to rename antenna';
        });

        // Sync Bias Buttons and channel lighting
        if (data.antennaBias) {
          // A requested change shows as pending (pulsing) until the AD600 reports it back.
          const pendingBias = data.antennaBiasPending || {};
          const biasOf = ant => (pendingBias[ant] ? !!pendingBias[ant].enabled : !!data.antennaBias[ant]);
          ['A','B','C','D','E','F'].forEach(ant => {
            const bBtn = document.getElementById('biasBtn_' + ant);
            const card = document.getElementById('card_' + ant);
            const isOn = biasOf(ant);
            if (bBtn) {
              bBtn.classList.toggle('active', isOn);
              bBtn.classList.toggle('pending', !!pendingBias[ant]);
              bBtn.title = pendingBias[ant]
                ? 'Waiting for the AD600 to confirm Antenna ' + ant + ' bias ' + (isOn ? 'ON' : 'OFF')
                : (isOn ? 'Antenna ' + ant + ' Bias is ACTIVE (12V DC)' : 'Toggle Antenna ' + ant + ' Bias Power');
            }
            if (card) {
              card.classList.toggle('bias-powered', isOn);
            }
          });

          // Sync Joined Pair Cards bias
          for (const [pairKey, [ant1, ant2]] of Object.entries(DIVERSITY_PAIRS)) {
            const pairBtn = document.getElementById('biasBtn_' + pairKey);
            const pairCard = document.getElementById('card_' + pairKey);
            const isPairOn = biasOf(ant1) && biasOf(ant2);
            const isAnyOn = biasOf(ant1) || biasOf(ant2);
            if (pairBtn) {
              pairBtn.classList.toggle('active', isPairOn);
              pairBtn.classList.toggle('pending', !!(pendingBias[ant1] || pendingBias[ant2]));
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
        const activeClients = (data.rtlClients || []).filter(client => client.enabled);
        const hasDevice = activeClients.length > 0;
        isScanning = data.scanState === 'SCANNING';

        if (!hasDevice) {
          btn.disabled = true;
          btn.className = 'btn-scan btn-disabled';
          btn.innerText = 'ENABLE A RECEIVER TO SCAN';
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

        const activeKeys = activeClients.map(client => client.id);
        const rtlClientById = new Map(activeClients.map(client => [client.id, client]));

        if (data.traces) {
          // Plot every rtl_tcp receiver on a numeric MHz axis so different ranges and bin grids
          // retain their actual frequency positions.
          const isReArming = (data.status && data.status.includes('RE-ARMING'));
          const isPendingSeq = targetConfigSeq > 0 && (data.sweepConfigSeq === undefined || data.sweepConfigSeq < targetConfigSeq);
          const hasAnyData = !isReArming && !isPendingSeq && activeKeys.some(ant => data.traces[ant] && data.traces[ant].length > 0);

          if (hasAnyData) {
            needsTraceWipe = false;
            const [envelopeStart, envelopeEnd] = computeActiveEnvelope();
            chart.data.labels = buildBaselineLabels(envelopeStart, envelopeEnd);

            // Re-build multi-series datasets for Chart.js with phosphor persistence and Max Hold
            const newDatasets = [];
            activeKeys.forEach(clientId => {
              const client = rtlClientById.get(clientId) || {};
              const raw = data.traces[clientId] || [];
              const clientGrid = client.grid || grid;
              const startMhz = clientGrid.startHz / 1e6;
              const stopMhz = clientGrid.stopHz / 1e6;
              const stepMhz = clientGrid.stepHz / 1e6;
              const seriesLabel = client.name || 'RTL-SDR';
              const existingDs = chart.data.datasets && chart.data.datasets.find(d => d.clientId === clientId && !d.label.includes('Max Hold'));
              const existingValuesByFrequency = new Map();
              if (existingDs && Array.isArray(existingDs.data)) {
                existingDs.data.forEach(point => {
                  if (point && Number.isFinite(Number(point.x)) && Number.isFinite(Number(point.y))) {
                    existingValuesByFrequency.set(Number(point.x).toFixed(3), point.y);
                  }
                });
              }
              const endpoint = client.host.includes(':') ? '[' + client.host + ']' : client.host;
              const traceLabel = (client.slot || '') + ' · ' + seriesLabel + ' (' + endpoint + ':' + client.port + ') — ' +
                startMhz.toFixed(1) + '–' + stopMhz.toFixed(1) + ' MHz';

              const pts = [];
              const maxPts = [];
              if (maxHoldActive[clientId] && (!maxHoldBuffers[clientId] || maxHoldBuffers[clientId].length !== raw.length)) {
                maxHoldBuffers[clientId] = new Array(raw.length).fill(null);
              }
              for (let i = 0; i < raw.length; i++) {
                const frequencyMhz = startMhz + i * stepMhz;
                const frequency = frequencyMhz.toFixed(3);
                const val = raw[i];
                const previousValue = existingValuesByFrequency.get(frequency);
                let traceValue;
                // Keep the previous point for an empty or below-floor dBFS bin.
                if (val !== undefined && val !== null && val > -125.0) {
                  traceValue = val;
                } else if (previousValue !== undefined && previousValue !== null && previousValue > -125.0) {
                  traceValue = previousValue;
                } else {
                  traceValue = val !== undefined ? val : -115.0;
                }
                pts.push({ x: frequencyMhz, y: traceValue });
                if (maxHoldActive[clientId]) {
                  const prev = maxHoldBuffers[clientId][i];
                  const peak = (prev === null || prev === undefined) ? traceValue : Math.max(prev, traceValue);
                  maxHoldBuffers[clientId][i] = peak;
                  maxPts.push({ x: frequencyMhz, y: peak });
                }
              }

              // 1. Live Instantaneous Trace
              newDatasets.push({
                clientId,
                label: traceLabel,
                data: pts,
                borderColor: clientColor(client),
                borderWidth: 1.5,
                tension: 0.1,
                spanGaps: false,
                pointRadius: 0,
                parsing: false
              });

              // 2. Max Hold Peak Trace (if enabled for this receiver)
              if (maxHoldActive[clientId]) {
                newDatasets.push({
                  clientId,
                  label: traceLabel + ' Max Hold',
                  data: maxPts,
                  borderColor: clientColor(client),
                  borderWidth: 1.2,
                  borderDash: [4, 4],
                  tension: 0.1,
                  spanGaps: false,
                  pointRadius: 0,
                  parsing: false
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
            const hasRealData = chart.data.datasets && chart.data.datasets.some(d => d.data && d.data.length > 0 && !d.label.includes('Grid Baseline'));
            if (needsTraceWipe || !hasRealData) {
              chart.data.labels = buildBaselineLabels(curTargetStart, curTargetEnd);
              chart.options.scales.x.min = curTargetStart;
              chart.options.scales.x.max = curTargetEnd;
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

    // Adopt the server's current antenna selection and per-antenna ranges (shared by every viewer).
    function applyServerConfig(data) {
        const selected = (data.selectedAntennas && data.selectedAntennas.length) ? data.selectedAntennas : ['A'];
        document.querySelectorAll('input[name="antennaCb"]').forEach(cb => {
          cb.checked = selected.includes(cb.value);
        });
        const ranges = data.antennaRanges || {};
        Object.keys(ranges).forEach(ant => {
          const r = ranges[ant];
          if (!Array.isArray(r) || r.length !== 2) return;
          const currentPreset = document.getElementById('antRangeSelect_' + ant)?.value;
          const currentRange = localAntennaRanges[ant];
          const sameRange = currentRange && Math.abs(currentRange[0] - r[0]) < 0.001 && Math.abs(currentRange[1] - r[1]) < 0.001;
          const currentPresetRange = RANGE_PRESETS[currentPreset];
          const currentPresetMatches = currentPreset === 'CUSTOM' || (currentPresetRange &&
            Math.abs(currentPresetRange[0] - r[0]) < 0.001 && Math.abs(currentPresetRange[1] - r[1]) < 0.001);
          const presetKey = sameRange && currentPresetMatches
            ? currentPreset
            : Object.keys(RANGE_PRESETS).find(k => RANGE_PRESETS[k][0] === r[0] && RANGE_PRESETS[k][1] === r[1]);
          mirrorRangeToCard(ant, presetKey || 'CUSTOM', r[0], r[1]);
        });
        refreshTraceBandLabels();
        knownConfigSeq = Math.max(knownConfigSeq, data.sweepConfigSeq || 0);
    }

    async function hydrateFromServer() {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        applyServerConfig(await res.json());
      } catch (e) {}
    }

    window.addEventListener('DOMContentLoaded', async () => {
      initChart();
      await hydrateFromServer();
      updateCardActiveStyles();
      syncHardwareAndZoom(true, false);

      fetchStatus();
      setInterval(fetchStatus, 200); // 5 Hz poll
    });
  </script>
</body>
</html>`;

// 4. HTTP Web Server
// Set RTL_REMOTE_CONTROL=0 to make every other device on the LAN view-only. Local controls remain enabled.
const REMOTE_CONTROL = process.env.RTL_REMOTE_CONTROL !== '0' && process.env.AD600_REMOTE_CONTROL !== '0';
const CHART_JS_LOCAL = path.join(__dirname, 'vendor', 'chart.umd.min.js');
const CHART_JS_CDN = 'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js';

function isLoopback(req) {
  const a = (req.socket && req.socket.remoteAddress) || '';
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
}

function startWebServer() {
  const server = http.createServer((req, res) => {
    const urlPath = req.url.split('?')[0];
    const controlAllowed = REMOTE_CONTROL || isLoopback(req);
    if (req.method === 'POST' && urlPath.startsWith('/api/') && !controlAllowed) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'View-only: controls are limited to the host computer' }));
      return;
    }
    if (req.url === '/api/status' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const payload = Object.assign({}, appState, { traces: sourceTraces, rtlClients: rtlClientsForStatus(), controlAllowed });
      res.end(JSON.stringify(payload));
    } else if (urlPath === '/vendor/chart.umd.min.js' && req.method === 'GET') {
      // Served locally when vendored (works on a show network with no internet), else the CDN.
      fs.readFile(CHART_JS_LOCAL, (err, data) => {
        if (err) {
          res.writeHead(302, { Location: CHART_JS_CDN });
          res.end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'max-age=86400' });
        res.end(data);
      });
    } else if (urlPath === '/api/rtl-clients' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body || '{}');
          if (payload.action === 'add') {
            if (appState.rtlClients.length >= RTL_CLIENT_LIMIT) {
              res.writeHead(409, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'Maximum of six receivers reached (one per AD600 antenna slot)' }));
              return;
            }
            const name = String(payload.name || '').trim().slice(0, 64);
            const host = String(payload.host || '').trim();
            const port = Number.parseInt(payload.port, 10);
            if (!name || /[\u0000-\u001f\u007f]/.test(name) || !host || /\s/.test(host) || host.length > 253 ||
                !Number.isInteger(port) || port < 1 || port > 65535) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'Enter a name, host without spaces, and a port from 1 to 65535' }));
              return;
            }
            if (appState.rtlClients.some(client => client.host.toLowerCase() === host.toLowerCase() && client.port === port)) {
              res.writeHead(409, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'That rtl_tcp host and port are already in the list' }));
              return;
            }
            const client = {
              id: `rtl-${crypto.randomUUID()}`,
              name,
              host,
              port,
              startMhz: RTL_SLOT_RANGES[RTL_SLOTS[appState.rtlClients.length] || 'F'][0],
              stopMhz: RTL_SLOT_RANGES[RTL_SLOTS[appState.rtlClients.length] || 'F'][1],
              enabled: false,
              state: 'DISCONNECTED'
            };
            appState.rtlClients.push(client);
            sourceTraces[client.id] = [];
            if (!saveRtlClientProfiles()) {
              appState.rtlClients = appState.rtlClients.filter(item => item.id !== client.id);
              delete sourceTraces[client.id];
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'Could not save receiver profile on this host' }));
              return;
            }
          } else {
            const client = appState.rtlClients.find(item => item.id === payload.id);
            if (!client) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'rtl_tcp client not found' }));
              return;
            }
            if (payload.action === 'setRange') {
              const startMhz = Number.parseFloat(payload.startMhz);
              const stopMhz = Number.parseFloat(payload.stopMhz);
              if (!Number.isFinite(startMhz) || !Number.isFinite(stopMhz) || startMhz < 24 || stopMhz > 1766 || stopMhz <= startMhz) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'RTL-SDR scan range must be within 24 to 1766 MHz' }));
                return;
              }
              const previousRange = clientRange(client);
              const rangeChanged = previousRange[0] !== startMhz || previousRange[1] !== stopMhz;
              if (rangeChanged) {
                client.startMhz = startMhz;
                client.stopMhz = stopMhz;
                sourceTraces[client.id] = [];
                const runtime = rtlClientRuntimes.get(client.id);
                const nextGrid = gridForRange(startMhz, stopMhz, appState.rbwHz);
                if (!saveRtlClientProfiles()) {
                  client.startMhz = previousRange[0];
                  client.stopMhz = previousRange[1];
                  sourceTraces[client.id] = [];
                  res.writeHead(500, { 'Content-Type': 'application/json' });
                  res.end(JSON.stringify({ success: false, error: 'Could not save receiver frequency range on this host' }));
                  return;
                }
                appState.sweepConfigSeq = (appState.sweepConfigSeq || 0) + 1;
                if (runtime) {
                  runtime.grid = nextGrid;
                  runtime.lastProcessedSweepId = -1;
                  runtime.lastSweepComplete = false;
                  const configuration = { startHz: nextGrid.startHz, stopHz: nextGrid.stopHz, rbwHz: appState.rbwHz };
                  if (appState.scanState === 'SCANNING') restartRtlSweep(runtime, configuration);
                  else requestBridge(runtime, '/configuration', configuration);
                }
              }
            } else if (payload.action === 'setEnabled') {
              client.enabled = !!payload.enabled;
              delete client.error;
              if (client.enabled) {
                sourceTraces[client.id] = [];
                startRtlTcpClient(client);
              } else {
                stopRtlTcpClient(client.id);
                if (enabledRtlClients().length === 0 && appState.scanState === 'SCANNING') {
                  appState.scanState = 'STOPPED';
                  broadcastBridgeRequest('/sweep/stop');
                }
              }
            } else if (payload.action === 'remove') {
              if (client.id === 'rtl-client-1') {
                res.writeHead(409, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Disable the default receiver instead of removing it' }));
                return;
              }
              const clientIndex = appState.rtlClients.indexOf(client);
              stopRtlTcpClient(client.id);
              appState.rtlClients = appState.rtlClients.filter(item => item.id !== client.id);
              delete sourceTraces[client.id];
              if (!saveRtlClientProfiles()) {
                appState.rtlClients.splice(clientIndex, 0, Object.assign({}, client, { enabled: false, state: 'DISCONNECTED' }));
                sourceTraces[client.id] = [];
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Could not save receiver profile changes on this host' }));
                return;
              }
              if (enabledRtlClients().length === 0 && appState.scanState === 'SCANNING') {
                appState.scanState = 'STOPPED';
                broadcastBridgeRequest('/sweep/stop');
              }
            } else {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'Action must be add, setRange, setEnabled, or remove' }));
              return;
            }
          }
          syncRtlConnectionState();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, rtlClients: rtlClientsForStatus(), connectionState: appState.connectionState }));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Invalid JSON request' }));
        }
      });
    } else if (req.url === '/api/connect' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const client = appState.rtlClients.find(item => item.id === payload.id) || appState.rtlClients[0];
          if (client && payload.action === 'connect') {
            client.enabled = true;
            startRtlTcpClient(client);
          } else if (client && payload.action === 'disconnect') {
            client.enabled = false;
            stopRtlTcpClient(client.id);
          }
          syncRtlConnectionState();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, rtlClients: rtlClientsForStatus(), connectionState: appState.connectionState }));
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
            if (enabledRtlClients().length === 0) {
              res.writeHead(409, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'Enable at least one rtl_tcp client before starting a scan' }));
              return;
            }
            appState.scanState = 'SCANNING';
            clearSourceTraces();
            for (const client of enabledRtlClients()) {
              const existingRuntime = rtlClientRuntimes.get(client.id);
              if (existingRuntime) {
                restartRtlSweep(existingRuntime);
              } else {
                startRtlTcpClient(client);
              }
            }
            syncRtlConnectionState();
          } else {
            appState.scanState = 'STOPPED';
            for (const runtime of rtlClientRuntimes.values()) {
              runtime.commandEpoch++;
              runtime.pendingSweepStart = false;
              runtime.progress = null;
            }
            broadcastBridgeRequest('/sweep/stop');
            syncRtlConnectionState();
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

          if (Number.isFinite(startMhz) && Number.isFinite(endMhz) &&
              (startMhz < 24 || endMhz > 1766)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'RTL-SDR scan range must be within 24 to 1766 MHz' }));
            return;
          }

          if (!isNaN(startMhz) && !isNaN(endMhz) && endMhz > startMhz) {
            const rangeChanged = (appState.startFreqMhz !== startMhz || appState.endFreqMhz !== endMhz);
            appState.startFreqMhz = startMhz;
            appState.endFreqMhz = endMhz;
            appState.grid = gridForRange(startMhz, endMhz, appState.rbwHz);
            appState.sweepConfigSeq = (appState.sweepConfigSeq || 0) + 1;
            console.log(`[RANGE CONFIG] Setting RTL-SDR scan range to ${startMhz} – ${endMhz} MHz (seq=${appState.sweepConfigSeq})`);

            if (rangeChanged) {
              clearSourceTraces();
              if (appState.scanState === 'SCANNING') {
                appState.status = `UPDATING RTL-SDR SCAN RANGE (${startMhz.toFixed(1)}–${endMhz.toFixed(1)} MHz)...`;
              }
            }

            broadcastBridgeRequest('/configuration', {
              startHz: Math.round(startMhz * 1e6),
              stopHz: Math.round(endMhz * 1e6),
              curveMask: computeCurveMask(appState.selectedAntennas),
              repeat: appState.scanMode === 'SINGLE' ? 1 : 255
            }, (_res, response) => console.log(`[BRIDGE CONFIG RESPONSE] Range updated: ${response}`));
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
          // Keep the output-bin widths aligned with the Python spectrum bridge.
          const VALID_BIN_WIDTHS = [50000, 100000, 350000, 900000];
          if (!VALID_BIN_WIDTHS.includes(rbw)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: `Unsupported bin width; valid values: ${VALID_BIN_WIDTHS.join(', ')} Hz` }));
            return;
          }
          if (appState.rbwHz !== rbw) {
            appState.rbwHz = rbw;
            appState.rbwComp = Math.round(rbw / 25000); // retained for older status clients
            appState.grid = gridForRange(appState.startFreqMhz, appState.endFreqMhz, rbw);
            appState.sweepConfigSeq = (appState.sweepConfigSeq || 0) + 1;
            console.log(`[RBW CONFIG] Set output-bin width to ${appState.rbwHz} Hz (seq=${appState.sweepConfigSeq})`);

            // The old trace uses a different frequency grid. Clear it even while scanning is
            // stopped, then wait for the next completed sweep at this bin width.
            clearSourceTraces();
            if (appState.scanState === 'SCANNING') {
              appState.status = `UPDATING RTL-SDR BIN WIDTH (${Math.round(rbw / 1000)} kHz)...`;
            } else {
              appState.status = `BIN WIDTH SET TO ${Math.round(rbw / 1000)} kHz - START SCAN FOR A NEW TRACE`;
            }

            // Keep each receiver on its own frequency span while applying the shared bin width.
            for (const client of enabledRtlClients()) {
              const runtime = rtlClientRuntimes.get(client.id);
              if (!runtime) continue;
              const [clientStart, clientStop] = clientRange(client);
              runtime.grid = gridForRange(clientStart, clientStop, appState.rbwHz);
              if (appState.scanState === 'SCANNING') restartRtlSweep(runtime, { rbwHz: appState.rbwHz });
              else requestBridge(runtime, '/configuration', { rbwHz: appState.rbwHz });
            }
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
              clearSourceTraces();
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

            broadcastBridgeRequest('/configuration', configPayload);
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
            const requested = String(payload.interface);
            getNetworkInterfaces();
            // Only accept a name that's actually a real NIC on this machine (or 'ALL') — this
            // value is later passed to the Python bootstrap and to a discovery subprocess call,
            // so it must never be arbitrary client-supplied text.
            const isValidIface = requested === 'ALL' || appState.interfaces.some(nic => nic.name === requested);
            if (!isValidIface) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: 'Unknown network interface' }));
              return;
            }
            appState.selectedInterface = requested;
            appState.status = `PROBING INTERFACE ${requested}...`;
            console.log(`[NIC SELECTION] User selected interface ${requested}`);
            runDiscovery(requested);
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
          if (appState.connectionState !== 'CONNECTED') {
            res.writeHead(409, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Not connected to the AD600' }));
            return;
          }
          if (appState.antennaBias && appState.antennaBias[ant] !== undefined) {
            // Not applied locally: the device's BIAS report confirms it (see antennaBiasPending).
            appState.antennaBiasPending[ant] = { enabled, t: Date.now() };
            console.log(`[ANTENNA BIAS] Requesting port ${ant} 12V DC bias ${enabled ? 'ON' : 'OFF'}`);

            broadcastBridgeRequest('/bias', { antenna: ant, enabled });
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, antennaBias: appState.antennaBias, antennaBiasPending: appState.antennaBiasPending }));
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

            broadcastBridgeRequest('/antenna_name', { antenna: ant, name });
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

            const repeat = appState.scanMode === 'SINGLE' ? 1 : 255;
            if (appState.scanState === 'SCANNING') {
              clearSourceTraces();
              for (const runtime of rtlClientRuntimes.values()) restartRtlSweep(runtime);
            } else {
              broadcastBridgeRequest('/configuration', { repeat });
            }
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, scanMode: appState.scanMode }));
        } catch (e) {
          res.writeHead(400); res.end();
        }
      });
    } else if (urlPath.startsWith('/api/') || urlPath.startsWith('/vendor/')) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Not found' }));
    } else if (req.method === 'GET' && (urlPath === '/' || urlPath === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(HTML_TEMPLATE);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  });

  server.listen(WEB_PORT, () => {
    console.log('===========================================================');
    console.log('  RTL-SDR Web Spectrum Scanner');
    console.log('===========================================================');
    console.log(`  [+] Web Dashboard : http://localhost:${WEB_PORT}`);
    console.log(`  [+] rtl_tcp node  : ${RTL_TCP_HOST}:${RTL_TCP_PORT}`);
    console.log(`  [+] LAN control   : ${REMOTE_CONTROL ? 'enabled' : 'VIEW-ONLY for other devices (RTL_REMOTE_CONTROL=0)'}`);
    console.log(`  [+] Chart library : ${fs.existsSync(CHART_JS_LOCAL) ? 'local (offline-capable)' : 'CDN (needs internet - see README)'}`);
    console.log('  [+] Engine logs   : server console');
    console.log('===========================================================');
  });
}

// Start All Services
loadRtlClientProfiles();
stopAllRtlTcpClients();
initAcnSpectrumIngest();
startWebServer();

function shutdownScanner() {
  stopAllRtlTcpClients();
  process.exit(0);
}
process.once('SIGINT', shutdownScanner);
process.once('SIGTERM', shutdownScanner);
