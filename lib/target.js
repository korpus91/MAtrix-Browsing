'use strict';
// TARGET — server-side URL forensics.
//
// The thesis: X-Frame-Options is an instruction to a RENDERING ENGINE. A
// server-side HTTP client ignores it entirely and gets strictly more than a
// browser would show — full headers, the real redirect chain, the raw
// certificate, and honest per-phase timing.
//
// Every number reported here is measured. Nothing is estimated or filled in.

const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const tls = require('tls');
const net = require('net');

const ms = (start) => Number(process.hrtime.bigint() - start) / 1e6;

// ---------------------------------------------------------------------------
// Stage 1: resolve. "cnn" is not a hostname. Rather than guessing a TLD by
// string append, race real DNS lookups and report which candidate answered.
// ---------------------------------------------------------------------------

const TLD_CANDIDATES = ['', '.com', '.net', '.org', '.io'];

function parseInput(raw) {
  let input = String(raw || '').trim();
  if (!input) throw new Error('empty input');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) input = 'https://' + input;

  let u;
  try {
    u = new URL(input);
  } catch {
    throw new Error(`could not parse "${raw}" as a URL`);
  }
  return u;
}

function isBareIp(host) {
  return net.isIP(host.replace(/^\[|\]$/g, '')) !== 0;
}

async function resolveStage(url) {
  const started = process.hrtime.bigint();
  const host = url.hostname;

  // A bare IP needs no DNS at all.
  if (isBareIp(host)) {
    return { host, literal: true, candidates: [], elapsed_ms: +ms(started).toFixed(1) };
  }

  const needsCandidates = !host.includes('.') && host !== 'localhost';
  const names = needsCandidates ? TLD_CANDIDATES.map((t) => host + t).filter((n) => n.includes('.')) : [host];

  const candidates = await Promise.all(
    names.map(async (name) => {
      const t = process.hrtime.bigint();
      try {
        const addrs = await dns.resolve4(name);
        return { name, ok: true, addr: addrs[0], count: addrs.length, elapsed_ms: +ms(t).toFixed(1) };
      } catch (err) {
        return { name, ok: false, error: err.code || err.message, elapsed_ms: +ms(t).toFixed(1) };
      }
    })
  );

  const winner = candidates.find((c) => c.ok);
  if (!winner) {
    const err = new Error(`no DNS answer for ${names.join(', ')}`);
    err.candidates = candidates;
    throw err;
  }

  return {
    host: winner.name,
    literal: false,
    raced: needsCandidates,
    candidates,
    resolved: winner.addr,
    elapsed_ms: +ms(started).toFixed(1),
  };
}

// ---------------------------------------------------------------------------
// Stage 2: one real request, with the socket instrumented so every phase
// boundary is stamped from the actual event rather than inferred.
// ---------------------------------------------------------------------------

function timedRequest(url, { method = 'GET', timeout = 12000 } = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;
    const t0 = process.hrtime.bigint();
    const marks = {};

    const req = lib.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method,
        // Node >= 19 defaults the global agent to keepAlive, which silently
        // reuses a pooled socket: no 'secureConnect' fires, so cert capture
        // goes null and the timing describes a connection we never made.
        // A forensic probe must measure a genuinely cold connection.
        agent: false,
        servername: isBareIp(url.hostname) ? undefined : url.hostname,
        // Deliberate: we want to INSPECT a bad certificate, not be stopped by it.
        rejectUnauthorized: false,
        headers: {
          // Identify honestly. Some origins serve different headers to unknown agents.
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CONSTRUCT/1.0 (+probe)',
          accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          'accept-encoding': 'identity',
        },
      },
      (res) => {
        marks.ttfb = ms(t0);
        // Read the peer directly off the live socket rather than trusting the
        // handshake event to have fired. Works on new and reused connections.
        const sock = res.socket;
        if (sock && sock.encrypted && !peer) {
          peer = {
            authorized: sock.authorized,
            authorizationError: sock.authorizationError ? String(sock.authorizationError) : null,
            protocol: sock.getProtocol(),
            cipher: sock.getCipher(),
            cert: typeof sock.getPeerX509Certificate === 'function' ? sock.getPeerX509Certificate() : null,
            alpn: sock.alpnProtocol || null,
          };
        }
        const chunks = [];
        let bytes = 0;
        res.on('data', (c) => {
          bytes += c.length;
          if (chunks.length < 40) chunks.push(c); // enough for <head>, not the whole page
        });
        res.on('end', () => {
          marks.end = ms(t0);
          resolve({ res, marks, bytes, body: Buffer.concat(chunks).toString('utf8').slice(0, 20000), peer });
        });
        res.on('error', reject);
      }
    );

    let peer = null;
    req.on('socket', (socket) => {
      marks.socket = ms(t0);
      socket.on('lookup', () => { marks.dns = ms(t0); });
      socket.on('connect', () => { marks.tcp = ms(t0); });
      socket.on('secureConnect', () => {
        marks.tls = ms(t0);
        peer = {
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
          cert: typeof socket.getPeerX509Certificate === 'function' ? socket.getPeerX509Certificate() : null,
          alpn: socket.alpnProtocol || null,
        };
      });
    });

    req.setTimeout(timeout, () => req.destroy(new Error(`timeout after ${timeout}ms`)));
    req.on('error', reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Trust-store diff — the interception check.
//
// Conventional advice says to shell out with --use-system-ca. That flag is
// process-level and cannot be applied per-connection, so it is wrong here.
// tls.getCACertificates() (Node >= 22.15) lets us do it in-process instead:
// connect twice, once against Node's bundled Mozilla list and once against
// the OS trust store. Divergence means something is decrypting the wire.
// ---------------------------------------------------------------------------

function tlsProbe(host, port, ca) {
  return new Promise((resolve) => {
    const opts = { host, port, servername: isBareIp(host) ? undefined : host, rejectUnauthorized: false, timeout: 8000 };
    if (ca) opts.ca = ca;
    const socket = tls.connect(opts, () => {
      const cert = typeof socket.getPeerX509Certificate === 'function' ? socket.getPeerX509Certificate() : null;
      resolve({
        ok: socket.authorized,
        error: socket.authorizationError ? String(socket.authorizationError) : null,
        issuer: cert ? cert.issuer : null,
      });
      socket.destroy();
    });
    socket.on('error', (err) => resolve({ ok: false, error: err.code || err.message, issuer: null }));
    socket.on('timeout', () => { socket.destroy(); resolve({ ok: false, error: 'timeout', issuer: null }); });
  });
}

function issuerCN(issuerStr) {
  if (!issuerStr) return null;
  const m = /CN=([^\n,]+)/.exec(issuerStr);
  return m ? m[1].trim() : issuerStr.split('\n')[0];
}

async function trustDiff(host, port) {
  if (typeof tls.getCACertificates !== 'function') {
    return { available: false, reason: `node ${process.version} < v22.15 — tls.getCACertificates unavailable` };
  }
  const started = process.hrtime.bigint();
  const [mozilla, system] = await Promise.all([
    tlsProbe(host, port, tls.getCACertificates('bundled')),
    tlsProbe(host, port, tls.getCACertificates('system')),
  ]);

  let verdict, detail;
  if (mozilla.ok && system.ok) {
    verdict = 'clean';
    detail = 'no interception';
  } else if (!mozilla.ok && system.ok) {
    verdict = 'intercepted';
    detail = `signed by a CA your OS trusts but Mozilla does not — ${issuerCN(system.issuer) || 'unknown issuer'}`;
  } else if (mozilla.ok && !system.ok) {
    verdict = 'os-distrust';
    detail = `your OS trust store rejects this chain: ${system.error}`;
  } else {
    verdict = 'untrusted';
    detail = `chain fails both stores: ${mozilla.error || system.error}`;
  }

  return {
    available: true,
    mozilla: { ok: mozilla.ok, error: mozilla.error },
    system: { ok: system.ok, error: system.error },
    verdict,
    detail,
    elapsed_ms: +ms(started).toFixed(1),
  };
}

// ---------------------------------------------------------------------------
// Header analysis
// ---------------------------------------------------------------------------

function analyzeFraming(headers) {
  const xfo = headers['x-frame-options'] || null;
  const csp = headers['content-security-policy'] || null;
  let ancestors = null;
  if (csp) {
    const m = /frame-ancestors\s+([^;]+)/i.exec(csp);
    if (m) ancestors = m[1].trim();
  }
  let frameable = true;
  let reason = 'no framing restriction';

  // CSP frame-ancestors supersedes X-Frame-Options where both are present.
  // Only a STANDALONE "*" token permits framing by an arbitrary origin --
  // a wildcard inside a host pattern ("*.cnn.com") permits that site's own
  // properties and nobody else. Matching any asterisk here would report
  // half the web as frameable.
  if (ancestors !== null) {
    const tokens = ancestors.split(/\s+/).filter(Boolean);
    frameable = tokens.includes('*');
    reason = `csp frame-ancestors: ${ancestors}`;
  } else if (xfo && /deny|sameorigin/i.test(xfo)) {
    frameable = false;
    reason = `x-frame-options: ${xfo}`;
  } else if (xfo) {
    reason = `x-frame-options: ${xfo}`;
  }

  // The point of the tool: this is a FINDING, not a failure.
  return { frameable, x_frame_options: xfo, frame_ancestors: ancestors, reason };
}

function analyzeCookies(res) {
  const raw = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : [].concat(res.headers['set-cookie'] || []);
  return raw.map((line) => {
    const parts = line.split(';').map((s) => s.trim());
    const [name] = parts[0].split('=');
    const flags = parts.slice(1).map((p) => p.toLowerCase());
    const has = (f) => flags.some((x) => x === f || x.startsWith(f + '='));
    const sameSite = flags.find((f) => f.startsWith('samesite='));
    const issues = [];
    if (!has('httponly')) issues.push('no HttpOnly');
    if (!has('secure')) issues.push('no Secure');
    if (!sameSite) issues.push('no SameSite');
    return { name, httpOnly: has('httponly'), secure: has('secure'), sameSite: sameSite ? sameSite.split('=')[1] : null, issues };
  });
}

// A local reimplementation of the Observatory modifier table. Deliberately
// shown as one line in the UI, never as the headline — he doesn't own websites.
const POSTURE = [
  { key: 'content-security-policy', label: 'CSP', weight: -20 },
  { key: 'strict-transport-security', label: 'HSTS', weight: -10 },
  { key: 'x-content-type-options', label: 'nosniff', weight: -5 },
  { key: 'referrer-policy', label: 'referrer-policy', weight: -5 },
  { key: 'permissions-policy', label: 'permissions-policy', weight: -5 },
];

function analyzePosture(headers) {
  let score = 100;
  const missing = [];
  for (const h of POSTURE) {
    if (!headers[h.key]) { score += h.weight; missing.push({ label: h.label, weight: h.weight }); }
  }
  score = Math.max(0, score);
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B+' : score >= 70 ? 'B' : score >= 60 ? 'C' : score >= 50 ? 'D' : 'F';
  return { score, grade, missing };
}

function certInfo(peer) {
  if (!peer || !peer.cert) return null;
  const c = peer.cert;
  const validTo = c.validTo ? new Date(c.validTo) : null;
  const days = validTo ? Math.round((validTo - Date.now()) / 86400000) : null;
  return {
    subject: c.subject ? c.subject.replace(/\n/g, ' ') : null,
    issuer: issuerCN(c.issuer),
    san: c.subjectAltName ? c.subjectAltName.slice(0, 400) : null,
    valid_to: c.validTo || null,
    days_remaining: days,
    fingerprint256: c.fingerprint256 || null,
    protocol: peer.protocol,
    cipher: peer.cipher ? peer.cipher.name : null,
    alpn: peer.alpn,
    authorized: peer.authorized,
    authorization_error: peer.authorizationError,
  };
}

// ---------------------------------------------------------------------------
// The probe. Emits stages as they complete so the UI streams real progress.
// ---------------------------------------------------------------------------

async function probeTarget(rawInput, emit) {
  const t0 = process.hrtime.bigint();
  const url = parseInput(rawInput);

  // --- resolve -------------------------------------------------------------
  emit('stage', { stage: 'resolve', status: 'running' });
  let resolved;
  try {
    resolved = await resolveStage(url);
  } catch (err) {
    emit('stage', { stage: 'resolve', status: 'failed', error: err.message, candidates: err.candidates || [] });
    emit('done', { ok: false, elapsed_ms: +ms(t0).toFixed(1) });
    return;
  }
  if (resolved.host !== url.hostname) url.hostname = resolved.host;
  emit('stage', { stage: 'resolve', status: 'ok', ...resolved });

  const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);

  // --- redirect chain + timing --------------------------------------------
  emit('stage', { stage: 'http', status: 'running' });
  const hops = [];
  let current = new URL(url.toString());
  let final = null;

  try {
    for (let i = 0; i < 10; i++) {
      const r = await timedRequest(current);
      const loc = r.res.headers.location;
      hops.push({
        url: current.toString(),
        status: r.res.statusCode,
        location: loc || null,
        ttfb_ms: +r.marks.ttfb.toFixed(1),
        insecure: current.protocol === 'http:',
      });
      if (loc && r.res.statusCode >= 300 && r.res.statusCode < 400) {
        current = new URL(loc, current);
        continue;
      }
      final = r;
      break;
    }
  } catch (err) {
    emit('stage', { stage: 'http', status: 'failed', error: err.message, hops });
    emit('done', { ok: false, elapsed_ms: +ms(t0).toFixed(1) });
    return;
  }

  if (!final) {
    emit('stage', { stage: 'http', status: 'failed', error: 'too many redirects', hops });
    emit('done', { ok: false, elapsed_ms: +ms(t0).toFixed(1) });
    return;
  }

  const m = final.marks;
  emit('stage', {
    stage: 'http',
    status: 'ok',
    hops,
    status_code: final.res.statusCode,
    timing: {
      dns_ms: m.dns != null ? +(m.dns - (m.socket || 0)).toFixed(1) : null,
      tcp_ms: m.tcp != null && m.dns != null ? +(m.tcp - m.dns).toFixed(1) : null,
      tls_ms: m.tls != null && m.tcp != null ? +(m.tls - m.tcp).toFixed(1) : null,
      ttfb_ms: +m.ttfb.toFixed(1),
      total_ms: +m.end.toFixed(1),
    },
    bytes: final.bytes,
    // A plaintext hop anywhere in the chain is a finding in its own right.
    plaintext_hop: hops.some((h) => h.insecure),
  });

  // --- tls / cert ----------------------------------------------------------
  emit('stage', { stage: 'tls', status: 'running' });
  const cert = certInfo(final.peer);
  emit('stage', { stage: 'tls', status: cert ? 'ok' : 'skipped', cert, reason: cert ? null : 'plaintext http — no certificate' });

  // --- interception check --------------------------------------------------
  if (cert) {
    emit('stage', { stage: 'trust', status: 'running' });
    const diff = await trustDiff(url.hostname, port);
    emit('stage', { stage: 'trust', status: diff.available ? 'ok' : 'unavailable', ...diff });
  }

  // --- header posture ------------------------------------------------------
  emit('stage', { stage: 'headers', status: 'running' });
  const headers = final.res.headers;
  emit('stage', {
    stage: 'headers',
    status: 'ok',
    framing: analyzeFraming(headers),
    cookies: analyzeCookies(final.res),
    posture: analyzePosture(headers),
    server: headers.server || null,
    hsts: headers['strict-transport-security'] || null,
    raw: Object.fromEntries(Object.entries(headers).filter(([k]) => !/^set-cookie$/i.test(k))),
  });

  emit('done', { ok: true, elapsed_ms: +ms(t0).toFixed(1) });
}

module.exports = { probeTarget, parseInput };
