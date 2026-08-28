const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto} = require('node:crypto');

function runtime({blockedStorage = false} = {}) {
  const timers = new Map();
  let timerId = 0;
  function element() {
    return {
      children: [], textContent: '', checked: true, dataset: {}, scrollHeight: 0,
      classList: {contains: () => false},
      set innerHTML(value) { this.markup = value; this.children = []; },
      get innerHTML() { return this.markup || ''; },
      appendChild(child) { this.children.push(...(child.fragment ? child.children : [child])); },
    };
  }
  const nodes = Object.fromEntries(['eventStreamContainer', 'streamCount', 'autoScrollCheck', 'viewDashboard'].map(id => [id, element()]));
  const context = vm.createContext({
    console, AbortController, DOMException, crypto: webcrypto, Uint8Array, URL,
    localStorage: {getItem() { if (blockedStorage) throw Error('disabled'); return null; }, setItem() {}, removeItem() {}},
    window: {location:{origin:'http://localhost:9001'}}, document: {hidden: false, getElementById: id => nodes[id] || null, addEventListener() {}, createElement: element, createDocumentFragment: () => ({...element(), fragment:true})},
    setTimeout(fn) { timers.set(++timerId, fn); return timerId; },
    clearTimeout(id) { timers.delete(id); }, setInterval() {}, clearInterval() {},
  });
  const load = file => vm.runInContext(fs.readFileSync(path.join(__dirname, '../frontend/js', file), 'utf8'), context, {filename:file});
  load('state.js');
  return {context, timers, nodes, load, run: source => vm.runInContext(source, context)};
}

test('restricted storage does not prevent app initialization', () => {
  const app = runtime({blockedStorage: true});
  assert.match(app.run('getDeviceFingerprint()'), /^device_/);
  assert.equal(app.run('state.authToken'), null);
});

test('inline handler arguments preserve hostile quotes as data', () => {
  const app = runtime();
  app.context.payload = `a'); throw new Error('injected'); // " <img src=x>`;
  const encoded = app.run('jsArg(payload)');
  const decoded = encoded.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  assert.equal(vm.runInNewContext(decoded), app.context.payload);
});

test('10,000 event burst is bounded and renders once', () => {
  const app = runtime();
  app.load('stream.js');
  app.run('for (let i=0; i<10000; i++) addEventToStream({category:"SCAN",message:"event " + i});');
  assert.equal(app.run('state.events.length'), 500);
  assert.equal(app.timers.size, 1);
  const [id, render] = [...app.timers][0];
  app.timers.delete(id);
  render();
  assert.equal(app.nodes.eventStreamContainer.children.length, 120);
  assert.match(app.nodes.eventStreamContainer.children.at(-1).innerHTML, /event 9999/);
});

test('hidden documents retain bounded events without scheduling DOM work', () => {
  const app = runtime();
  app.load('stream.js');
  app.run('document.hidden=true; for(let i=0;i<2000;i++) addEventToStream({message:"hidden"});');
  assert.equal(app.timers.size, 0);
  assert.equal(app.run('state.events.length'), 500);
});

test('late findings response cannot overwrite a newly selected scan', async () => {
  const app = runtime();
  app.load('findings.js');
  let resolveBody;
  const body = new Promise(resolve => { resolveBody = resolve; });
  app.context.fakeFetch = async () => ({ok:true, json:() => body});
  app.run('authFetch=fakeFetch; state.activeScanId="old-scan";');
  const pending = app.run('loadFindings()');
  await Promise.resolve();
  app.run('state.activeScanId="new-scan";');
  resolveBody([{id:'old-finding', severity:'HIGH'}]);
  await pending;
  assert.equal(app.run('state.allFindings.length'), 0);
});

test('late report response cannot overwrite another investigation', async () => {
  const app = runtime();
  app.load('reports.js');
  let resolveOld;
  const oldBody = new Promise(resolve => { resolveOld = resolve; });
  app.context.rendered = [];
  app.context.fakeFetch = async url => ({ok: true, json: () => url.includes('old-scan') ? oldBody : Promise.resolve({overview:{id:'new-scan'}})});
  app.run('authFetch=fakeFetch; renderWorkspace=ws=>rendered.push(ws.overview.id); renderWorkspaceEmpty=()=>{};');
  const previous = app.run('loadWorkspaceData("old-scan")');
  await Promise.resolve();
  await app.run('loadWorkspaceData("new-scan")');
  resolveOld({overview:{id:'old-scan'}});
  await previous;
  assert.deepEqual(app.context.rendered, ['new-scan']);
  assert.equal(app.run('workspaceCache.has("old-scan")'), false);
});

test('export list renders the backend filename and type contract', () => {
  const app = runtime();
  app.nodes.wsExportJobsTbody = {innerHTML:''};
  app.load('reports.js');
  app.run('renderWorkspaceExports([{id:"job", export_type:"full_pdf", filename:"actual.pdf", status:"COMPLETED", download_url:"/api/scans/a/exports/job/download"}])');
  assert.match(app.nodes.wsExportJobsTbody.innerHTML, /FULL_PDF/);
  assert.match(app.nodes.wsExportJobsTbody.innerHTML, /actual\.pdf/);
  assert.match(app.nodes.wsExportJobsTbody.innerHTML, /\/api\/scans\/a\/exports\/job\/download/);
});

test('untrusted links cannot execute script schemes', () => {
  const app = runtime();
  assert.equal(app.run('safeLink("javascript:alert(1)")'), '#');
  assert.equal(app.run('safeLink("data:text/html,<script>alert(1)</script>")'), '#');
  assert.equal(app.run('safeLink("/api/scans/one/report/json")'), 'http://localhost:9001/api/scans/one/report/json');
});

test('scan form requires explicit authorization and sends structured scope', () => {
  const app = runtime();
  app.load('engagement.js');
  app.nodes.engAuthorization = {value: 'LOCAL-TEST-ONLY'};
  app.nodes.engAuthorizationAck = {checked: false};
  assert.throws(() => app.run('readEngagementForm()'), /Konfirmasi izin/);
  app.nodes.engAuthorizationAck.checked = true;
  app.nodes.engScopeHosts = {value: 'app.example.invalid\n*.example.invalid'};
  app.nodes.engAllowedPorts = {value: '80,443,443'};
  const result = JSON.parse(app.run('JSON.stringify(readEngagementForm())'));
  assert.deepEqual(result.scope_hosts, ['app.example.invalid', '*.example.invalid']);
  assert.equal(result.authorization_reference, 'LOCAL-TEST-ONLY');
  assert.deepEqual(result.allowed_ports, [80, 443]);
  app.nodes.engAllowedPorts.value = '80,invalid';
  assert.throws(() => app.run('readEngagementForm()'), /port 1/);
});

test('report refresh preserves unsaved identity only for the same scan', () => {
  const app = runtime();
  app.load('engagement.js');
  app.nodes.reportOrganization = {value: ''};
  app.run('renderReportProfile({report:{organization:"Original"}}, "a")');
  app.nodes.reportOrganization.value = 'Unsaved';
  app.run('reportProfileDirty = true; renderReportProfile({report:{organization:"Old server value"}}, "a")');
  assert.equal(app.nodes.reportOrganization.value, 'Unsaved');
  app.run('renderReportProfile({report:{organization:"Different scan"}}, "b")');
  assert.equal(app.nodes.reportOrganization.value, 'Different scan');
});

test('report header does not use record creation time as execution time', () => {
  const app = runtime();
  app.load('reports.js');
  app.nodes.wsStartTime = {textContent:''};
  app.run('renderWorkspace({overview:{id:"queued", status:"queued", created_at:"2026-08-28T01:00:00Z"}})');
  assert.equal(app.nodes.wsStartTime.textContent, 'Tidak tercatat');
});
