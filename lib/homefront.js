'use strict';
// HOMEFRONT — the socket census.
//
// Windows already knows what every socket is doing, which process owns it, and
// what it resolves to. Nothing joins those facts together. The join is the
// product: every connection, its owning process, and the other end named.
//
// Deliberate scoping decisions:
//  - No external IP-intelligence API. It needs a key, it rate-limits, and it
//    would ship a list of everywhere this machine connects to a third party.
//    Reverse DNS uses the local resolver and leaks nothing new.
//  - Authenticode signature checks are opt-in per request, not part of the
//    base census: Get-AuthenticodeSignature costs ~40-80ms per distinct binary.

const { execFile } = require('child_process');
const dns = require('dns').promises;
const os = require('os');

const EXEC_TIMEOUT = 15000;     // EDIT: raise on a very busy host
const RDNS_TIMEOUT = 1500;      // EDIT: per-lookup reverse DNS budget
const RDNS_CONCURRENCY = 24;    // EDIT: parallel reverse lookups

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: EXEC_TIMEOUT, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        // netstat exits non-zero on some hosts while still producing usable
        // output; treat stdout as authoritative when it is non-empty.
        if (err && !stdout) return reject(new Error(`${cmd} failed: ${err.message}${stderr ? ' :: ' + stderr.trim() : ''}`));
        resolve(stdout);
      });
  });
}

// ---------------------------------------------------------------------------
// Parsers. Split out from the exec so they can be tested against fixtures on
// any platform -- these are where the bugs live, not in the process spawn.
// ---------------------------------------------------------------------------

// netstat -ano   ->   [{proto, local, localPort, remote, remotePort, state, pid}]
function parseNetstat(stdout) {
  const rows = [];
  for (const raw of String(stdout).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || !/^(TCP|UDP)\s/i.test(line)) continue;
    const parts = line.split(/\s+/);
    const proto = parts[0].toUpperCase();
    // TCP rows carry a state column, UDP rows do not.
    const [local, remote, ...rest] = parts.slice(1);
    let state = null, pid = null;
    if (proto === 'TCP') { state = rest[0] || null; pid = rest[1]; }
    else { pid = rest[0]; state = null; }
    if (!/^\d+$/.test(String(pid))) continue;
    const l = splitAddr(local), r = splitAddr(remote);
    rows.push({
      proto, state,
      pid: Number(pid),
      local: l.host, localPort: l.port,
      remote: r.host, remotePort: r.port,
    });
  }
  return rows;
}

// Handles 1.2.3.4:443, [::1]:443, *:*, 0.0.0.0:0
function splitAddr(addr) {
  if (!addr) return { host: null, port: null };
  const m = /^\[(.+)\]:(.+)$/.exec(addr);           // bracketed IPv6
  if (m) return { host: m[1], port: normPort(m[2]) };
  const i = addr.lastIndexOf(':');
  if (i === -1) return { host: addr, port: null };
  return { host: addr.slice(0, i), port: normPort(addr.slice(i + 1)) };
}
const normPort = (p) => (p === '*' ? null : Number(p) || null);

// tasklist /fo csv /nh   ->   Map<pid, imageName>
function parseTasklist(stdout) {
  const map = new Map();
  for (const line of String(stdout).split(/\r?\n/)) {
    if (!line.trim()) continue;
    const cells = line.match(/"([^"]*)"/g);
    if (!cells || cells.length < 2) continue;
    const name = cells[0].slice(1, -1);
    const pid = Number(cells[1].slice(1, -1));
    if (pid) map.set(pid, name);
  }
  return map;
}

// ss -tunap (Linux)   ->   same row shape as parseNetstat
function parseSs(stdout) {
  const rows = [];
  for (const raw of String(stdout).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || /^Netid/i.test(line)) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 5) continue;
    const proto = parts[0].toUpperCase();
    if (proto !== 'TCP' && proto !== 'UDP') continue;
    const state = proto === 'TCP' ? parts[1] : null;
    const l = splitAddr(parts[4]);
    const r = splitAddr(parts[5]);
    // users:(("chrome",pid=1234,fd=88))
    const um = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
    rows.push({
      proto,
      state: state === 'ESTAB' ? 'ESTABLISHED' : state === 'LISTEN' ? 'LISTENING' : state,
      pid: um ? Number(um[2]) : null,
      process: um ? um[1] : null,
      local: l.host, localPort: l.port,
      remote: r.host, remotePort: r.port,
    });
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Classification -- deterministic, zero API calls. This is what keeps token
// spend at zero for routine use: code decides what is ordinary, and only a
// genuinely unexplained row is ever a candidate for escalation.
// ---------------------------------------------------------------------------

// Loopback means UNREACHABLE from the network. The unspecified address
// (0.0.0.0 / :: / *) means the exact opposite -- bound to every interface.
// Conflating them hides every network-reachable listener, so they are
// deliberately separate predicates.
function isLoopback(host) {
  if (!host) return false;
  return host === '::1' || host.startsWith('127.');
}

function isUnspecified(host) {
  if (!host) return false;
  return host === '0.0.0.0' || host === '::' || host === '*';
}

function isPrivate(host) {
  if (!host) return false;
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (/^169\.254\./.test(host)) return true;
  if (/^f[cd]/i.test(host)) return true;       // fc00::/7 unique-local
  if (/^fe80/i.test(host)) return true;        // link-local
  return false;
}

// A listener bound to a routable interface is reachable from the network.
// A listener on loopback is not. That distinction is the whole finding.
function classifyListener(row) {
  if (isLoopback(row.local)) return { exposure: 'loopback', severity: 'benign' };
  if (isUnspecified(row.local)) return { exposure: 'all-interfaces', severity: 'notable' };
  if (isPrivate(row.local)) return { exposure: 'lan', severity: 'notable' };
  return { exposure: 'public', severity: 'warning' };
}

// ---------------------------------------------------------------------------
// Reverse DNS with a bounded pool and a process-lifetime cache.
// ---------------------------------------------------------------------------

const rdnsCache = new Map();

async function reverseOne(ip) {
  if (rdnsCache.has(ip)) return rdnsCache.get(ip);
  let name = null;
  try {
    const names = await Promise.race([
      dns.reverse(ip),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), RDNS_TIMEOUT)),
    ]);
    name = names && names[0] ? names[0] : null;
  } catch {
    name = null; // NXDOMAIN or timeout is a normal, expected answer here
  }
  rdnsCache.set(ip, name);
  return name;
}

async function reverseAll(ips) {
  const out = new Map();
  const queue = [...ips];
  const workers = Array.from({ length: Math.min(RDNS_CONCURRENCY, queue.length) }, async () => {
    while (queue.length) {
      const ip = queue.shift();
      out.set(ip, await reverseOne(ip));
    }
  });
  await Promise.all(workers);
  return out;
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

async function collectWindows() {
  const [netstatOut, tasklistOut] = await Promise.all([
    run('netstat', ['-ano']),
    run('tasklist', ['/fo', 'csv', '/nh']).catch(() => ''),
  ]);
  const names = parseTasklist(tasklistOut);
  return parseNetstat(netstatOut).map((r) => ({ ...r, process: names.get(r.pid) || null }));
}

// /proc/net/{tcp,tcp6,udp,udp6} -- addresses are little-endian hex.
// Used when `ss` is absent (minimal containers); needs no external binary.
const PROC_STATE = { '01': 'ESTABLISHED', '0A': 'LISTENING', '06': 'TIME_WAIT', '08': 'CLOSE_WAIT' };

function hexToIp(hex) {
  if (hex.length === 8) {
    // little-endian 32-bit
    return [6, 4, 2, 0].map((i) => parseInt(hex.substr(i, 2), 16)).join('.');
  }
  // IPv6: four little-endian 32-bit words
  const words = [];
  for (let w = 0; w < 4; w++) {
    const g = hex.substr(w * 8, 8);
    const be = g.substr(6, 2) + g.substr(4, 2) + g.substr(2, 2) + g.substr(0, 2);
    words.push(be.substr(0, 4), be.substr(4, 4));
  }
  return words.join(':').replace(/(^|:)0{1,3}/g, '$1');
}

function parseProcNet(text, proto) {
  const rows = [];
  const lines = String(text).split('\n').slice(1);
  for (const line of lines) {
    const p = line.trim().split(/\s+/);
    if (p.length < 10) continue;
    const [lHex, lPort] = p[1].split(':');
    const [rHex, rPort] = p[2].split(':');
    rows.push({
      proto,
      state: proto === 'UDP' ? null : (PROC_STATE[p[3]] || p[3]),
      pid: null,
      process: null,
      inode: Number(p[9]),
      local: hexToIp(lHex), localPort: parseInt(lPort, 16),
      remote: hexToIp(rHex), remotePort: parseInt(rPort, 16),
    });
  }
  return rows;
}

async function collectLinux() {
  // -p needs privileges to name other users' processes; rows still return
  // without it, just with a null process name. That is reported, not hidden.
  try {
    const out = await run('ss', ['-tunap']).catch(() => run('ss', ['-tuna']));
    const rows = parseSs(out);
    if (rows.length) return rows;
  } catch { /* ss absent -- fall through to /proc */ }

  const fsp = require('fs').promises;
  const files = [['/proc/net/tcp', 'TCP'], ['/proc/net/tcp6', 'TCP'], ['/proc/net/udp', 'UDP'], ['/proc/net/udp6', 'UDP']];
  let rows = [];
  for (const [file, proto] of files) {
    try { rows = rows.concat(parseProcNet(await fsp.readFile(file, 'utf8'), proto)); } catch { /* absent is fine */ }
  }

  // Map socket inode -> pid by scanning /proc/<pid>/fd. Unreadable entries
  // belong to other users; those rows keep a null process name.
  const byInode = new Map();
  for (const r of rows) if (r.inode) byInode.set(r.inode, r);
  try {
    for (const pid of await fsp.readdir('/proc')) {
      if (!/^\d+$/.test(pid)) continue;
      let fds;
      try { fds = await fsp.readdir(`/proc/${pid}/fd`); } catch { continue; }
      let name = null;
      for (const fd of fds) {
        let link;
        try { link = await fsp.readlink(`/proc/${pid}/fd/${fd}`); } catch { continue; }
        const m = /^socket:\[(\d+)\]$/.exec(link);
        if (!m) continue;
        const row = byInode.get(Number(m[1]));
        if (!row) continue;
        if (name === null) {
          try { name = (await fsp.readFile(`/proc/${pid}/comm`, 'utf8')).trim(); } catch { name = ''; }
        }
        row.pid = Number(pid);
        row.process = name || null;
      }
    }
  } catch { /* /proc unreadable -- rows still return, unattributed */ }

  return rows;
}

async function census({ resolve = true } = {}) {
  const started = Date.now();
  const platform = os.platform();
  const rows = platform === 'win32' ? await collectWindows() : await collectLinux();

  const connections = rows.filter((r) => r.state === 'ESTABLISHED' && r.remote && !isLoopback(r.remote) && !isUnspecified(r.remote));
  const listeners = rows.filter((r) => r.state === 'LISTENING' || (r.proto === 'UDP' && !r.remote));

  // Reverse-resolve only public remote addresses. Private and loopback
  // addresses have no useful PTR and would just burn the budget.
  let ptr = new Map();
  if (resolve) {
    const targets = [...new Set(connections.map((c) => c.remote).filter((h) => h && !isPrivate(h)))];
    ptr = await reverseAll(targets);
  }

  // Group connections by owning process -- the readout he actually wants.
  const byProcess = new Map();
  for (const c of connections) {
    const key = c.process || `pid ${c.pid}`;
    if (!byProcess.has(key)) byProcess.set(key, { process: c.process, pid: c.pid, count: 0, peers: new Map() });
    const g = byProcess.get(key);
    g.count++;
    const host = ptr.get(c.remote) || c.remote;
    g.peers.set(host, (g.peers.get(host) || 0) + 1);
  }

  const processes = [...byProcess.values()]
    .map((g) => ({
      process: g.process, pid: g.pid, count: g.count,
      peers: [...g.peers.entries()].map(([host, n]) => ({ host, n })).sort((a, b) => b.n - a.n).slice(0, 8),
    }))
    .sort((a, b) => b.count - a.count);

  const exposed = listeners
    .map((l) => ({ ...l, ...classifyListener(l) }))
    .filter((l) => l.exposure !== 'loopback')
    .sort((a, b) => (a.localPort || 0) - (b.localPort || 0));

  return {
    platform,
    elapsed_ms: Date.now() - started,
    privileged: rows.some((r) => r.process),      // false on Linux without root
    totals: {
      rows: rows.length,
      established: connections.length,
      listening: listeners.length,
      exposed: exposed.length,
      processes: processes.length,
    },
    processes,
    exposed: exposed.map((l) => ({
      proto: l.proto, port: l.localPort, bind: l.local,
      pid: l.pid, process: l.process,
      exposure: l.exposure, severity: l.severity,
    })),
  };
}

module.exports = { census, parseNetstat, parseTasklist, parseSs, splitAddr, classifyListener, isPrivate, isLoopback, isUnspecified };
