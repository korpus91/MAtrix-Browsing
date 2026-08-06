#!/usr/bin/env node
'use strict';
// Self-test. Proves the install works on THIS machine and reports what is
// actually true here -- it does not assume anything passed.
//   node selftest.js            (server must be running)
//   node selftest.js --spawn    (starts its own server on a spare port)

const http = require('http');
const os = require('os');
const { spawn } = require('child_process');
const path = require('path');

const SPAWN = process.argv.includes('--spawn');
const PORT = SPAWN ? 4199 : (process.env.PORT || 4173); // EDIT: match your server port
const BASE = `http://localhost:${PORT}`;

let pass = 0, fail = 0, warn = 0;
const ok   = (m, d) => { pass++; console.log(`  PASS  ${m}${d ? '  ' + d : ''}`); };
const bad  = (m, d) => { fail++; console.log(`  FAIL  ${m}${d ? '  ' + d : ''}`); };
const note = (m, d) => { warn++; console.log(`  NOTE  ${m}${d ? '  ' + d : ''}`); };

function get(pathname, timeout = 45000) {
  return new Promise((resolve, reject) => {
    const req = http.get(BASE + pathname, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.setTimeout(timeout, () => req.destroy(new Error(`timeout after ${timeout}ms`)));
    req.on('error', reject);
  });
}

// Collapse an SSE body into { stageName: payload }
function parseSSE(body) {
  const out = {};
  for (const block of body.split('\n\n')) {
    const dataLine = block.split('\n').find((l) => l.startsWith('data: '));
    if (!dataLine) continue;
    try {
      const d = JSON.parse(dataLine.slice(6));
      if (d.stage && d.status !== 'running') out[d.stage] = d;
      if (d.ok !== undefined) out.done = d;
    } catch { /* partial frame */ }
  }
  return out;
}

async function main() {
  console.log(`\nCONSTRUCT self-test`);
  console.log(`  node ${process.version} · ${os.platform()} ${os.arch()} · ${os.cpus().length} cores\n`);

  // 1 ---- dependencies -----------------------------------------------------
  console.log('DEPENDENCIES');
  for (const m of ['systeminformation']) {
    try { require(m); ok(`${m} installed`); }
    catch { bad(`${m} missing`, 'run: npm install'); }
  }
  try {
    const tls = require('tls');
    if (typeof tls.getCACertificates === 'function') {
      const b = tls.getCACertificates('bundled').length;
      const s = tls.getCACertificates('system').length;
      ok('interception check available', `${b} bundled / ${s} system CAs`);
    } else {
      note('interception check unavailable', `node ${process.version} < v22.15 — upgrade Node to enable it`);
    }
  } catch (e) { bad('tls.getCACertificates threw', e.message); }

  // 2 ---- parser unit tests ------------------------------------------------
  console.log('\nUNIT TESTS');
  await new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(__dirname, 'test', 'homefront.test.js')], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    p.on('close', (code) => {
      const m = /(\d+) passed, (\d+) failed/.exec(out);
      if (code === 0 && m) ok('census parsers', `${m[1]} passed`);
      else bad('census parsers', (m ? `${m[2]} failed` : 'did not run') + ' — see: node test/homefront.test.js');
      resolve();
    });
  });

  // 3 ---- server -----------------------------------------------------------
  let child = null;
  if (SPAWN) {
    child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
      env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore', detached: false,
    });
    await new Promise((r) => setTimeout(r, 2500));
  }

  console.log('\nSERVER');
  try {
    const r = await get('/', 8000);
    if (r.status === 200 && r.body.includes('CONSTRUCT')) ok('page served', `${r.body.length} bytes`);
    else bad('page served', `status ${r.status}`);
  } catch (e) {
    bad('server not reachable', e.message);
    console.log(`\n  Start it first:  node server.js   (or double-click start.bat)\n`);
    process.exit(1);
  }

  // 4 ---- HOMEFRONT --------------------------------------------------------
  console.log('\nHOMEFRONT  (local, no API calls)');
  try {
    const r = await get('/api/census');
    const c = JSON.parse(r.body);
    if (c.error) { bad('census', c.error); }
    else {
      ok('census ran', `${c.elapsed_ms}ms on ${c.platform}`);
      ok('sockets enumerated', `${c.totals.rows} rows · ${c.totals.established} established · ${c.totals.listening} listening`);
      if (c.privileged) ok('process attribution', `${c.totals.processes} processes named`);
      else note('process attribution incomplete', 'some sockets are owned by other users — run elevated to name them all');
      if (c.totals.exposed > 0) note('reachable listeners', `${c.totals.exposed} bound beyond loopback — expected on a normal desktop, but worth a look`);
      else ok('reachable listeners', 'none — every listener is loopback-only');
    }
  } catch (e) { bad('census request', e.message); }

  // 5 ---- TARGET -----------------------------------------------------------
  console.log('\nTARGET  (server-side URL forensics)');
  try {
    const r = await get('/api/target?url=cnn');
    const s = parseSSE(r.body);

    if (s.resolve && s.resolve.status === 'ok') {
      const raced = (s.resolve.candidates || []).filter((c) => c.ok).length;
      ok('bare hostname resolved', `"cnn" -> ${s.resolve.host} (${raced} candidate${raced === 1 ? '' : 's'} answered)`);
    } else bad('resolve stage', s.resolve ? s.resolve.error : 'no data');

    if (s.http && s.http.status === 'ok') {
      const t = s.http.timing;
      ok('transport measured', `HTTP ${s.http.status_code} · ${s.http.hops.length} hop(s) · dns ${t.dns_ms}ms tls ${t.tls_ms}ms ttfb ${t.ttfb_ms}ms`);
    } else bad('transport stage', s.http ? s.http.error : 'no data');

    if (s.tls && s.tls.cert) ok('certificate read', `${s.tls.cert.protocol} · ${s.tls.cert.issuer} · ${s.tls.cert.days_remaining}d left`);
    else bad('certificate stage', 'no certificate captured');

    if (s.trust && s.trust.available) {
      if (s.trust.verdict === 'clean') ok('interception check', 'CLEAN — no TLS interception on this network');
      else note('interception check', `${s.trust.verdict.toUpperCase()} — ${s.trust.detail}`);
    } else note('interception check', s.trust ? s.trust.reason : 'not run');

    if (s.headers && s.headers.status === 'ok') {
      const f = s.headers.framing;
      if (f.frameable === false) ok('framing decided server-side', `NOT FRAMEABLE — ${f.reason}`);
      else note('framing', f.reason);
      ok('header posture scored', `${s.headers.posture.grade} ${s.headers.posture.score}/100 · ${s.headers.cookies.length} cookies audited`);
    } else bad('headers stage', s.headers ? s.headers.error : 'no data');

    if (s.done && s.done.ok) ok('probe completed', `${s.done.elapsed_ms}ms end to end`);
    else bad('probe did not complete');
  } catch (e) { bad('target request', e.message); }

  // 6 ---- ORACLE -----------------------------------------------------------
  console.log('\nORACLE  (optional)');
  if (process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'paste-your-real-key-here') {
    ok('API key present', 'chat panel will work — costs normal API usage per message');
  } else {
    note('no API key set', 'ORACLE is offline. Everything above works without it.');
  }

  if (child) child.kill();

  console.log(`\n${'-'.repeat(58)}`);
  console.log(`  ${pass} passed · ${fail} failed · ${warn} notes`);
  console.log(fail === 0
    ? '  READY. Open http://localhost:' + PORT + ' and type a domain.\n'
    : '  NOT READY — see the FAIL lines above.\n');
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error('\nself-test crashed:', e.message); process.exit(1); });
