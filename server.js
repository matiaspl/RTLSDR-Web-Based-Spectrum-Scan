const http = require('http');
const dgram = require('dgram');
const os = require('os');

const WEB_PORT = 8080;
const SLP_PORT = 8427;
const SLP_MULTICAST_ADDR = '239.255.254.253';

// App State
let appState = {
  interfaces: [], // list of { name, address }
  selectedInterface: 'ALL', // 'ALL' = auto: pick the NIC whose subnet contains the device
  discoveredDevices: {}, // ip -> { ip, model, cid, iface, sdtPort, lastSeen }
  activeTargetIp: null,
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
  antennaBiasPending: {}, // ant -> { enabled, t } awaiting device confirmation
  scanSlotOwned: false,
  antennaNames: {
    'A': '',
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
const { spawn, exec, execSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const ENGINE_DIR = path.join(__dirname, 'engine');
// App-private scratch dir (console_cmd.txt / console_out.log). Deliberately NOT ~/.ad600_scanner,
// which the SoundBase AD600 plugin also uses.
const SCRATCH_DIR = process.env.AD600_ENGINE_SCRATCH || path.join(os.homedir(), '.ad600_node_app');
const CMD_FILE = path.join(SCRATCH_DIR, 'console_cmd.txt');
const PYTHON_BIN = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
const BRIDGE_PORT = 8088;
// Physically impossible readings are decode artifacts (findings §6.3), never real RF.
const SANE_MIN_DBM = -125.0;
const SANE_MAX_DBM = 20.0;

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

let bridgePollInterval = null;

// Engine stdout lines worth echoing to this console. Everything else (per-PDU DMP chatter) is still
// in SCRATCH_DIR/console_out.log — echoing it all here produced ~30 MB/hour of output.
const ENGINE_LOG_NOISE_RE = /FIREHOSE EVENT|SWEEP-ID EVENT|BIG PACKET|DEEP-TREE SUB ACCEPTED/;
const ENGINE_LOG_RE = /★|⚠|✪|JOIN|REFUSE|IDENTITY|OWNERSHIP CLAIMED|NOT OWNER|ABORT|RELEASE|clean disconnect|QUIT|SLP advert|re-arm|Traceback|Error|error|DISCOVERY|\[RF ENGINE\]|\[ENGINE STATUS\]|RUNNING ON PORT/;

// Handshake milestones → operator-facing progress. JOIN → ownership → first sweep takes ~20-30 s
// on real hardware (findings §6.1), so each stage is surfaced rather than looking like a hang.
function applyEngineMilestone(line, targetIp) {
  if (/SLP advert sent/.test(line)) {
    appState.status = `ANNOUNCING TO AD600 @ ${targetIp}...`;
  } else if (/JOIN sent/.test(line)) {
    appState.status = `JOINING SESSION WITH AD600 @ ${targetIp}...`;
  } else if (/JOIN_REFUSE|IDENTITY IN USE/.test(line)) {
    appState.status = 'AD600 REFUSED THE SESSION - RETRYING...';
  } else if (/^CONNECTED$/.test(line.trim()) || /\*\*\* JOINED/.test(line)) {
    if (appState.connectionState !== 'CONNECTED') {
      appState.connectionState = 'CONNECTED';
      console.log('[CONNECTION] AD600 session established');
    }
    appState.status = appState.scanState === 'SCANNING'
      ? 'CONNECTED - CLAIMING SCAN SLOT (FIRST SWEEP IN ~30 s)...'
      : `CONNECTED TO AD600 @ ${targetIp} - READY`;
  } else if (/clean-grant fan-out complete/.test(line)) {
    if (appState.scanState === 'SCANNING') appState.status = 'CONNECTED - PRIMING SCAN ENGINE...';
  } else if (/OWNERSHIP CLAIMED/.test(line)) {
    appState.scanSlotOwned = true;
    if (appState.scanState === 'SCANNING') appState.status = 'SCAN SLOT CLAIMED - WAITING FOR FIRST SWEEP...';
  } else if (/NOT OWNER \(|ABORTING arm|NOT-OWNER \(GET_FAIL/.test(line)) {
    appState.scanSlotOwned = false;
    appState.status = 'SCAN SLOT HELD BY ANOTHER CONTROLLER (WWB / SOUNDBASE?) - CLOSE IT OR POWER-CYCLE THE AD600';
  } else if (/^\[ENGINE STATUS\]/.test(line) && /slot-0|power-cycle|couldn't start|launch failed|reconnecting/.test(line)) {
    appState.status = line.replace(/^\[ENGINE STATUS\]\s*/, '').toUpperCase();
  } else if (/^\[DISCOVERY FAILED\]/.test(line)) {
    appState.status = line.replace(/^\[DISCOVERY FAILED\]\s*/, '').toUpperCase();
  }
}

function start18EngineScan() {
  if (engineProcess) return;

  // Best-effort cleanup of orphaned engine processes left behind by a prior Node process
  // lifetime (e.g. this server crashed without going through stop18EngineScan). Scoped to this
  // installation's own absolute script paths rather than bare filenames, so it can't match an
  // unrelated process that happens to share a script name.
  try {
    const consolePyPath = path.join(ENGINE_DIR, 'ad600_console.py');
    const bootstrapPyPath = path.join(os.tmpdir(), 'ad600_bridge_launch.py');
    execSync(`pkill -15 -f "${consolePyPath}" 2>/dev/null || true`);
    execSync(`pkill -15 -f "${bootstrapPyPath}" 2>/dev/null || true`);
  } catch (e) {}

  getNetworkInterfaces();
  const targetIp = appState.activeTargetIp;
  if (!targetIp) {
    appState.connectionState = 'DISCONNECTED';
    appState.status = 'NO AD600 DISCOVERED YET - CHECK CABLING / INTERFACE';
    return;
  }
  const targetDev = appState.discoveredDevices[targetIp];

  // An explicitly chosen NIC wins; otherwise pick the one whose real subnet contains the device.
  let ifaceObj = null;
  if (appState.selectedInterface && appState.selectedInterface !== 'ALL') {
    ifaceObj = appState.interfaces.find(i => i.name === appState.selectedInterface) || null;
  }
  if (!ifaceObj) ifaceObj = ifaceForHost(targetIp);
  if (!ifaceObj && targetDev && targetDev.iface) {
    ifaceObj = appState.interfaces.find(i => i.name === targetDev.iface) || null;
  }
  if (!ifaceObj) {
    appState.connectionState = 'DISCONNECTED';
    appState.status = `NO NETWORK INTERFACE ON THE SAME SUBNET AS ${targetIp}`;
    return;
  }

  console.log(`[RF ENGINE] Spawning Python bridge for ${targetIp} on ${ifaceObj.name} (${ifaceObj.address}/${ifaceObj.netmask})...`);

  const env = Object.assign({}, process.env, {
    PYTHONPATH: ENGINE_DIR,
    AD600_ENGINE_DIR: ENGINE_DIR,
    AD600_CLIENT_DIR: ENGINE_DIR,
    AD600_CONSOLE_PY: path.join(ENGINE_DIR, 'ad600_console.py'),
    AD600_REACTIVE_FEED: 'BUILTIN',
    AD600_ENGINE_SCRATCH: SCRATCH_DIR,
    AD600_RT_COMPRESSION: String(appState.rbwComp || '14'),
    AD600_CURVE_SELECT: String(computeCurveMask(appState.selectedAntennas)),
    AD600_REPEAT: appState.scanMode === 'SINGLE' ? '1' : '255',
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
    fs.mkdirSync(SCRATCH_DIR, { recursive: true });
    fs.writeFileSync(CMD_FILE, '');
  } catch (e) {}

  // Runtime values (interface, device record) are passed to the bootstrap script via a JSON file
  // rather than interpolated into Python source, so nothing here can inject Python.
  const bridgeConfigPath = path.join(os.tmpdir(), 'ad600_bridge_config.json');
  const bridgeConfig = {
    iface: { name: ifaceObj.name, ipv4: ifaceObj.address, netmask: ifaceObj.netmask, mac: ifaceObj.mac },
    device: {
      device_ip: targetIp,
      device_cid: (targetDev && targetDev.cid) || null,
      device_port: (targetDev && targetDev.sdtPort) || 57383
    },
    bridgePort: BRIDGE_PORT,
    startHz: Math.round((appState.startFreqMhz || 470.0) * 1e6),
    stopHz: Math.round((appState.endFreqMhz || 608.0) * 1e6),
    rbwHz: appState.rbwHz || 350000,
    curveMask: computeCurveMask(appState.selectedAntennas),
    repeat: appState.scanMode === 'SINGLE' ? 1 : 255,
    startSweep: appState.scanState === 'SCANNING'
  };
  try {
    fs.writeFileSync(bridgeConfigPath, JSON.stringify(bridgeConfig));
  } catch (e) {
    console.log('[RF ENGINE] Failed to write bridge config JSON:', e.message);
  }

  // Written to a temp file so __file__ is set correctly. The only JS values interpolated below are
  // Node-controlled filesystem paths (JSON.stringify-escaped), never user- or network-supplied data.
  const tmpScript = path.join(os.tmpdir(), 'ad600_bridge_launch.py');
  const pyCode = `
import os, sys, time, signal, atexit, json
sys.path.insert(0, ${JSON.stringify(ENGINE_DIR)})
import ad600_bridge, ad600_engine, ad600_discovery

with open(${JSON.stringify(bridgeConfigPath)}, 'r', encoding='utf-8') as _cf:
    _cfg = json.load(_cf)

iface = _cfg['iface']
dev = _cfg['device']

# The console needs the device's CID for JOIN. If the beacon didn't carry it, ask the device via
# SLP on the chosen interface rather than guessing some other unit's identity.
if not dev.get('device_cid'):
    rec = None
    try:
        rec = ad600_discovery.discover(iface['name'], timeout=6)
    except Exception as e:
        sys.stderr.write('discovery error: %r\\n' % (e,))
    if rec and rec.get('device_ip') == dev['device_ip'] and rec.get('device_cid'):
        dev['device_cid'] = rec['device_cid']
        dev['device_port'] = rec.get('device_port') or dev['device_port']
    else:
        print('[DISCOVERY FAILED] AD600 @ %s did not answer SLP on %s - check cabling' % (dev['device_ip'], iface['name']))
        sys.stdout.flush()
        sys.exit(2)

print('[RF ENGINE] Target device CID: %s (controller CID is regenerated per session)' % dev['device_cid'])

br = ad600_bridge.Bridge(port=_cfg['bridgePort'])
br.serve(block=False)

eng = ad600_engine.Engine(bridge=br)
br.on_config_change = eng.apply_config

try:
    br.apply_configuration({
        'startHz': _cfg['startHz'],
        'stopHz': _cfg['stopHz'],
        'rbwHz': _cfg['rbwHz'],
        'curveMask': _cfg['curveMask'],
        'repeat': _cfg['repeat']
    })
except Exception as e:
    sys.stderr.write('CONFIG ERR: ' + str(e) + '\\n')

def _cleanup(*args):
    # eng.stop() runs the graceful QUIT-FIRST teardown (releases the scan slot) before any hard kill.
    try:
        eng.stop()
    except Exception:
        pass
    try:
        if hasattr(eng, 'proc') and eng.proc and eng.proc.poll() is None:
            eng.proc.kill()
    except Exception:
        pass

atexit.register(_cleanup)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
signal.signal(signal.SIGINT, lambda *a: sys.exit(0))

eng.start(dev, iface)

if _cfg.get('startSweep'):
    br.sweep_start()

sys.stdout.write('PYTHON RF BRIDGE ENGINE RUNNING ON PORT %d\\n' % _cfg['bridgePort'])
sys.stdout.flush()

# Report only the supervisor's human-readable note, and only when it changes.
_last = None
while True:
    time.sleep(1)
    note = (eng.status() or {}).get('note') or ''
    if note and note != _last:
        sys.stdout.write('[ENGINE STATUS] ' + note + '\\n')
        sys.stdout.flush()
    _last = note
`;

  fs.writeFileSync(tmpScript, pyCode);
  const proc = spawn(PYTHON_BIN, [tmpScript], { env });
  engineProcess = proc;
  appState.scanSlotOwned = false;

  let stdoutBuffer = '';
  proc.stdout.on('data', d => {
    if (engineProcess !== proc) return; // a newer engine process has already taken over
    stdoutBuffer += d.toString('utf8');
    const completeLines = stdoutBuffer.split('\n');
    stdoutBuffer = completeLines.pop(); // keep the trailing partial line for the next chunk

    for (const l of completeLines) {
      if (ENGINE_LOG_RE.test(l) && !ENGINE_LOG_NOISE_RE.test(l)) console.log('[ENGINE]', l.trim());
      applyEngineMilestone(l, targetIp);
      const match = l.match(/^BIAS\s+([A-F])\s+([01])/i);
      if (match) {
        const ant = match[1].toUpperCase();
        const isOn = match[2] === '1';
        if (appState.antennaBias[ant] !== isOn) {
          console.log(`[BIAS] Antenna ${ant} bias reported ${isOn ? 'ON' : 'OFF'} by device`);
        }
        appState.antennaBias[ant] = isOn;
        const pend = appState.antennaBiasPending[ant];
        if (pend && pend.enabled === isOn) delete appState.antennaBiasPending[ant];
      }
    }
  });

  proc.stderr.on('data', d => {
    if (engineProcess !== proc) return;
    console.log('[ENGINE STDERR]', d.toString('utf8').trim());
  });

  proc.on('exit', (code) => {
    console.log(`[ENGINE] Process exited with code ${code}`);
    if (engineProcess !== proc) return; // a newer engine process already replaced this one
    engineProcess = null;
    appState.connectionState = 'DISCONNECTED';
    appState.scanSlotOwned = false;
    appState.antennaBiasPending = {};
    if (appState.scanState === 'SCANNING') appState.scanState = 'STOPPED';
    if (!/DISCOVERY|NO NETWORK|SLOT HELD/.test(appState.status)) {
      appState.status = 'DISCONNECTED FROM AD600';
    }
    if (bridgePollInterval) { clearInterval(bridgePollInterval); bridgePollInterval = null; }
  });

  startBridgePolling();
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

let lastProcessedSweepId = -1;
let bridgePollInFlight = false;
function startBridgePolling() {
  if (bridgePollInterval) return;
  bridgePollInterval = setInterval(() => {
    if (!engineProcess) {
      clearInterval(bridgePollInterval);
      bridgePollInterval = null;
      return;
    }
    // /trace long-polls when no trace exists yet — never stack requests behind it.
    if (bridgePollInFlight) return;
    bridgePollInFlight = true;

    const req = http.get(`http://127.0.0.1:${BRIDGE_PORT}/trace`, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        bridgePollInFlight = false;
        if (res.statusCode !== 200) return; // 409 = no sweep yet; the stdout milestones drive status
        try {
          const json = JSON.parse(body);
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
            const isNewData = json.sweepId !== undefined && json.sweepId !== lastProcessedSweepId;
            if (!isNewData) return;
            lastProcessedSweepId = json.sweepId;
            const prevCount = appState.scansCaptured;
            appState.scansCaptured = json.sweepCount || 0;
            appState.lastScanTime = Date.now();

            json.series.forEach(s => {
              const antName = s.name; // 'A'..'F'
              const rawAmps = s.amplitudesDbm || [];
              if (rawAmps.length === 0) return;
              if (!antennaTraces[antName] || antennaTraces[antName].length !== rawAmps.length) {
                antennaTraces[antName] = rawAmps.map(v => (v > SANE_MIN_DBM && v <= SANE_MAX_DBM ? v : SANE_MIN_DBM - 5));
              } else {
                for (let i = 0; i < rawAmps.length; i++) {
                  // Overwrite only with sane readings, retaining the previous value for empty bins
                  // and for decode artifacts above the physical ceiling.
                  const v = rawAmps[i];
                  if ((v > SANE_MIN_DBM && v <= SANE_MAX_DBM) || antennaTraces[antName][i] === undefined) {
                    antennaTraces[antName][i] = v;
                  }
                }
              }
            });

            const curRbwKhz = Math.round((appState.grid?.stepHz || 350000) / 1000);
            const curPts = appState.grid?.pointCount || 0;
            // A wide span at a fine RBW arrives as tiles at very uneven rates (findings §6.2) —
            // say so until every part of the band has been seen at least once.
            appState.status = json.coverageComplete === false
              ? `SCANNING - FILLING BAND ${json.coveragePct || 0}% (${curRbwKhz} kHz RBW, ${curPts} Pts)`
              : `SCANNING AD600 HARDWARE - ${curRbwKhz} kHz RBW (${curPts} Pts)`;
            if (appState.scansCaptured !== prevCount && appState.scansCaptured % 10 === 1) {
              const summary = json.series.map(s => {
                const arr = s.amplitudesDbm || [];
                return `${s.name}: max ${arr.length ? Math.max(...arr).toFixed(1) : 'N/A'} dBm`;
              }).join(' | ');
              console.log(`[SWEEP #${appState.scansCaptured}] ${summary}`);
            }

            if (appState.scanMode === 'SINGLE' && json.sweeping === false) {
              console.log('[SINGLE SWEEP] Captured sweep snapshot. Auto-stopping scan.');
              appState.scanState = 'STOPPED';
              appState.status = 'SINGLE SWEEP COMPLETED (CONNECTED - READY)';
              http.get(`http://127.0.0.1:${BRIDGE_PORT}/sweep/stop`, () => {}).on('error', () => {});
            }
          }
        } catch (e) {}
      });
    });
    req.setTimeout(5000, () => req.destroy());
    req.on('error', () => { bridgePollInFlight = false; });
  }, 200);
}

function stop18EngineScan() {
  lastProcessedSweepId = -1;
  if (bridgePollInterval) { clearInterval(bridgePollInterval); bridgePollInterval = null; }
  appState.antennaBiasPending = {};
  if (engineProcess) {
    // SIGTERM is caught inside the Python bootstrap and triggers its atexit cleanup, which runs
    // eng.stop()'s graceful QUIT-FIRST teardown (releases the scan slot) before the process exits.
    try { engineProcess.kill('SIGTERM'); } catch (e) {}
    engineProcess = null;
  }
}

function initAcnSpectrumIngest() {
  runDiscovery();
  // re-probe periodically so a device plugged in after launch still shows up
  setInterval(() => { if (appState.connectionState === 'DISCONNECTED') runDiscovery(); }, 30000);
}

// Shared frequency-band <optgroup> markup for the display-zoom selector and every per-antenna /
// per-pair range selector, so the preset list only has to be edited in one place.
function bandOptionsHtml(selectedValue, customLabel) {
  customLabel = customLabel || 'Custom...';
  const sel = v => (v === selectedValue ? ' selected' : '');
  return `
            <optgroup label="Shure Bands">
              <option value="G57"${sel('G57')}>G57: 470 – 608 MHz</option>
              <option value="G57_PLUS"${sel('G57_PLUS')}>G57+: 470 – 616 MHz</option>
              <option value="G10"${sel('G10')}>G10: 470 – 542 MHz</option>
              <option value="H22"${sel('H22')}>H22: 518 – 584 MHz</option>
              <option value="J8"${sel('J8')}>J8: 626 – 664 MHz</option>
              <option value="J8A"${sel('J8A')}>J8A: 554 – 616 MHz</option>
              <option value="K54"${sel('K54')}>K54: 608 – 663 MHz</option>
              <option value="X55"${sel('X55')}>X55: 940 – 960 MHz</option>
            </optgroup>
            <optgroup label="Sennheiser Bands">
              <option value="A1_A4"${sel('A1_A4')}>A1-A4: 470 – 558 MHz</option>
              <option value="A5_A8"${sel('A5_A8')}>A5-A8: 550 – 608 MHz</option>
            </optgroup>
            <optgroup label="Frequency Spans">
              <option value="VHF"${sel('VHF')}>VHF: 174 – 216 MHz</option>
              <option value="470_524"${sel('470_524')}>Low UHF: 470 – 524 MHz</option>
              <option value="524_620"${sel('524_620')}>Mid UHF: 524 – 620 MHz</option>
              <option value="608_1000"${sel('608_1000')}>Upper: 608 – 1000 MHz</option>
              <option value="AFTRCC"${sel('AFTRCC')}>AFTRCC: 1435 – 1525 MHz</option>
              <option value="470_1000"${sel('470_1000')}>470 – 1000 MHz (1 GHz)</option>
              <option value="470_2000"${sel('470_2000')}>470 – 2000 MHz (2 GHz)</option>
              <option value="174_1000"${sel('174_1000')}>174 – 1000 MHz (1 GHz)</option>
              <option value="FULL_SPAN"${sel('FULL_SPAN')}>Full Span: 174 – 2000 MHz (2 GHz)</option>
              <option value="CUSTOM"${sel('CUSTOM')}>${customLabel}</option>
            </optgroup>`;
}

// 3. Web UI HTML Dashboard Template
const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shure AD600 Node.js Spectrum Manager</title>
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
      <span class="view-only-badge" title="Controls are limited to the host computer (AD600_REMOTE_CONTROL=0)">VIEW ONLY</span>
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
            ${bandOptionsHtml('', 'Custom Display Span...')}
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
          <option value="50000">50 kHz (Ultra High Res · comp 2)</option>
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
            ${bandOptionsHtml('470_524')}
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
            ${bandOptionsHtml('470_524')}
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
            ${bandOptionsHtml('524_620')}
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
            ${bandOptionsHtml('470_1000')}
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
    // push=false only redraws locally — used on page load so a newly opened viewer adopts the
    // server's live configuration instead of re-arming the AD600 with this page's defaults.
    function syncHardwareAndZoom(immediate = false, push = true) {
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
        localSyncPending = true;
        try {
          const aRes = await fetch('/api/antenna', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ antennas: active })
          });
          const aJson = await aRes.json();
          if (aJson) noteOwnConfigSeq(aJson.sweepConfigSeq);
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
          if (json) noteOwnConfigSeq(json.sweepConfigSeq);
        } catch (e) {}
        localSyncPending = false;
      };

      clearTimeout(syncDebounceTimer);
      if (!push) return;
      localSyncPending = true;
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
        if (json) noteOwnConfigSeq(json.sweepConfigSeq);
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

        document.body.classList.toggle('view-only', data.controlAllowed === false);
        if (!localSyncPending && (data.sweepConfigSeq || 0) > knownConfigSeq) {
          applyServerConfig(data);
          updateCardActiveStyles();
          syncHardwareAndZoom(true, false);
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
            const hasRealData = chart.data.datasets && chart.data.datasets.some(d => d.data && d.data.length > 0 && !d.label.includes('Grid Baseline'));
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
          const presetKey = Object.keys(RANGE_PRESETS).find(k => RANGE_PRESETS[k][0] === r[0] && RANGE_PRESETS[k][1] === r[1]);
          mirrorRangeToCard(ant, presetKey || 'CUSTOM', r[0], r[1]);
        });
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
// Set AD600_REMOTE_CONTROL=0 to make every other device on the LAN view-only (only the host
// computer can connect, change ranges, or switch antenna bias). Default keeps full remote control.
const REMOTE_CONTROL = process.env.AD600_REMOTE_CONTROL !== '0';
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
      const payload = Object.assign({}, appState, { traces: antennaTraces, controlAllowed });
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
    } else if (req.url === '/api/connect' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          if (payload.action === 'connect') {
            if (appState.connectionState === 'DISCONNECTED') {
              appState.connectionState = 'CONNECTING';
              appState.status = `CONNECTING TO AD600 @ ${appState.activeTargetIp || '?'} (TAKES ~20-30 s)...`;
              start18EngineScan();
            } else if (appState.connectionState === 'CONNECTED') {
              requestBiasRefresh();
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
            if (!engineProcess || appState.connectionState === 'DISCONNECTED') {
              appState.connectionState = 'CONNECTING';
              appState.status = `CONNECTING TO AD600 @ ${appState.activeTargetIp || '?'} (FIRST SWEEP IN ~30 s)...`;
              start18EngineScan();
            } else {
              appState.status = appState.scanMode === 'SINGLE'
                ? 'STARTING SINGLE SWEEP...'
                : (appState.scanSlotOwned ? 'STARTING CONTINUOUS SCAN...' : 'WAITING FOR SCAN SLOT / FIRST SWEEP...');
              http.get(`http://127.0.0.1:${BRIDGE_PORT}/sweep/start`, () => {}).on('error', () => {});
            }
          } else {
            appState.scanState = 'STOPPED';
            appState.scansCaptured = 0;
            lastProcessedSweepId = -1;
            appState.status = 'SCAN STOPPED (CONNECTED - READY)';
            http.get(`http://127.0.0.1:${BRIDGE_PORT}/sweep/stop`, () => {}).on('error', () => {});
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
              port: BRIDGE_PORT,
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
          // 25 kHz (comp 1) is excluded: verified live to reproducibly return corrupted
          // amplitudes (a decode bug in ad600_native.py's RF_SCAN_DATA parser, not a hardware
          // limit) — 50 kHz is the lowest RBW confirmed to stream clean data.
          const VALID_RBWS = [50000, 100000, 350000, 900000];
          if (!VALID_RBWS.includes(rbw)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: `Unsupported RBW; valid values: ${VALID_RBWS.join(', ')} Hz` }));
            return;
          }
          {
            appState.rbwHz = rbw;
            appState.rbwComp = Math.max(2, Math.round(rbw / 25000));
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
              port: BRIDGE_PORT,
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
              port: BRIDGE_PORT,
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

            const postData = JSON.stringify({ antenna: ant, enabled: enabled });
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: BRIDGE_PORT,
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

            const postData = JSON.stringify({ antenna: ant, name: name });
            const bridgeReq = http.request({
              hostname: '127.0.0.1',
              port: BRIDGE_PORT,
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
              port: BRIDGE_PORT,
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
    console.log('  Shure AD600 Web Spectrum Scanner');
    console.log('===========================================================');
    console.log(`  [+] Web Dashboard : http://localhost:${WEB_PORT}`);
    console.log(`  [+] LAN control   : ${REMOTE_CONTROL ? 'enabled' : 'VIEW-ONLY for other devices (AD600_REMOTE_CONTROL=0)'}`);
    console.log(`  [+] Chart library : ${fs.existsSync(CHART_JS_LOCAL) ? 'local (offline-capable)' : 'CDN (needs internet - see README)'}`);
    console.log(`  [+] Engine logs   : ${path.join(SCRATCH_DIR, 'console_out.log')}`);
    console.log('===========================================================');
  });
}

// Start All Services
stop18EngineScan();
initAcnSpectrumIngest();
startWebServer();
