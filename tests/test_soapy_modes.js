const assert = require('assert');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const root = path.resolve(__dirname, '..');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function main() {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'soapy-modes-'));
  const port = await freePort();
  let logs = '';
  let proc;
  function launch() {
    proc = spawn(process.execPath, ['server.js'], { cwd: root, env: { ...process.env,
      WEB_PORT: String(port), SOAPY_CLIENT_CONFIG_FILE: path.join(folder, 'clients.json'),
      SOAPY_POWER_BIN: path.join(root, 'tests/fixtures/fake_soapy_power.py'),
      SOAPY_REMOTE_BIN: path.join(root, 'tests/fixtures/fake_soapy_power.py'),
      SSH_BIN: path.join(root, 'tests/fixtures/fake_ssh.py'), RTL_REMOTE_CONTROL: '0'
    }});
    proc.stdout.on('data', data => { logs += data; });
    proc.stderr.on('data', data => { logs += data; });
  }
  async function stop() {
    if (!proc || proc.exitCode !== null) return;
    const done = new Promise(resolve => proc.once('close', resolve));
    proc.kill('SIGTERM');
    await done;
  }
  function request(route, payload) {
    return new Promise((resolve, reject) => {
      const body = payload === undefined ? null : JSON.stringify(payload);
      const req = http.request({ hostname: '127.0.0.1', port, path: route, method: body ? 'POST' : 'GET',
        headers: body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {} }, res => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => { try { resolve({ status: res.statusCode, data: JSON.parse(data) }); } catch (e) { reject(e); } });
      });
      req.on('error', reject);
      req.setTimeout(3000, () => req.destroy(new Error('Request timeout')));
      req.end(body);
    });
  }
  async function waitStatus(predicate) {
    for (let i = 0; i < 150; i++) {
      try {
        const { data } = await request('/api/status?minHz=470000000&maxHz=474000000&pixels=800');
        if (predicate(data)) return data;
      } catch (_) {}
      await pause(100);
    }
    throw new Error('Status timeout\n' + logs);
  }
  const action = payload => request('/api/rtl-clients', payload);
  try {
    launch();
    await waitStatus(data => data.rtlClients.length === 0);
    assert.equal((await action({ action: 'add', name: 'bad', mode: 'remote', host: '-oProxyCommand=bad' })).status, 400);
    assert.equal((await action({ action: 'add', name: 'Local test', mode: 'local', serial: 'LOCAL' })).status, 200);
    assert.equal((await action({ action: 'add', name: 'Duplicate', mode: 'local', serial: 'LOCAL' })).status, 409);
    assert.equal((await action({ action: 'add', name: 'Ambiguous', mode: 'local' })).status, 409);
    assert.equal((await action({ action: 'add', name: 'Remote test', mode: 'remote', host: 'synthetic.example', port: 22, sshUser: 'test', serial: 'REMOTE' })).status, 200);
    const initial = await waitStatus(data => data.rtlClients.length === 2);
    for (const client of initial.rtlClients) {
      assert.equal((await action({ action: 'setRange', id: client.id, startMhz: 470, stopMhz: 474 })).status, 200);
      assert.equal((await action({ action: 'setPpmCorrection', id: client.id, ppmCorrection: 12 })).status, 200);
      assert.equal((await action({ action: 'setEnabled', id: client.id, enabled: true })).status, 200);
    }
    await waitStatus(data => data.rtlClients.every(client => client.state === 'READY'));
    assert.equal((await request('/api/ppm-calibration', { action: 'start', id: initial.rtlClients[0].id })).status, 409);
    await request('/api/scan_mode', { scanMode: 'SINGLE' });
    await request('/api/scan', { action: 'start' });
    const single = await waitStatus(data => data.scanState === 'STOPPED' && data.scansCaptured === 1);
    assert(single.rtlClients.every(client => !client.error));
    assert(Object.values(single.nativeTraces).every(points => points.length > 0));
    await request('/api/scan_mode', { scanMode: 'CONTINUOUS' });
    await request('/api/scan', { action: 'start' });
    await waitStatus(data => data.scansCaptured >= 3);
    await request('/api/scan', { action: 'stop' });
    const added = await action({ action: 'add', name: 'Expected failure', mode: 'local', serial: 'FAIL' });
    assert.equal(added.status, 200);
    const failing = added.data.rtlClients.find(client => client.serial === 'FAIL');
    await action({ action: 'setEnabled', id: failing.id, enabled: true });
    await waitStatus(data => data.rtlClients.find(client => client.id === failing.id).state === 'READY');
    await request('/api/scan_mode', { scanMode: 'SINGLE' });
    await request('/api/scan', { action: 'start' });
    const mixed = await waitStatus(data => data.scanState === 'STOPPED' && data.rtlClients.some(client => client.error));
    assert(mixed.rtlClients.find(client => client.id === failing.id).error.includes('No matching RTL-SDR device'));
    assert(mixed.rtlClients.filter(client => client.id !== failing.id).every(client => !client.error));
    for (const client of initial.rtlClients) await action({ action: 'setEnabled', id: client.id, enabled: false });
    await request('/api/scan', { action: 'start' });
    await waitStatus(data => data.scanState === 'SCANNING');
    await waitStatus(data => data.scanState === 'STOPPED' && data.rtlClients.find(client => client.id === failing.id).state === 'ERROR');
    await action({ action: 'remove', id: failing.id });
    await stop();
    launch();
    const restored = await waitStatus(data => data.rtlClients.length === 2);
    assert(restored.rtlClients.every(client => !client.enabled && client.ppmCorrection === 12));
    assert.deepEqual(restored.rtlClients.map(client => client.mode), ['local', 'remote']);
    console.log('Local/remote API sweeps, native plotting data, validation and disabled profile reload passed');
  } finally {
    await stop();
    fs.rmSync(folder, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
