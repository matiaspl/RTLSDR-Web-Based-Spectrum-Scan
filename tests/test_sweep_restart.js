const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const start = source.indexOf('function restartRtlSweep(');
const end = source.indexOf('// One-shot bias read', start);
const requests = [];
const runtime = { clientId: 'a', commandEpoch: 0, lastSweepComplete: true };
const context = {
  appState: { scanMode: 'CONTINUOUS', scanState: 'SCANNING', rtlClients: [] },
  sourceTraces: { a: [-20] },
  requestBridge: (...args) => requests.push(args),
  syncRtlConnectionState: () => {}
};
vm.createContext(context);
vm.runInContext(source.slice(start, end), context);
context.restartRtlSweep(runtime, { startHz: 470000000 });
assert.equal(runtime.commandEpoch, 1);
assert.equal(runtime.pendingSweepStart, true);
assert.equal(runtime.lastSweepComplete, false);
assert.equal(context.sourceTraces.a.length, 0);
assert.equal(requests.length, 1);
assert.equal(requests[0][1], '/configuration');
assert.equal(requests[0][2].repeat, 255);
requests[0][3]({ statusCode: 200 });
assert.equal(requests[1][1], '/sweep/start');
assert.equal(runtime.pendingSweepStart, true);
requests[1][3]({ statusCode: 200 });
assert.equal(runtime.pendingSweepStart, false);
assert.equal(runtime.lastProcessedSweepId, -1);
console.log('Sweep restart ordering and poll gate passed');
