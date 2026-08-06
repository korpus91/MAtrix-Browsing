#!/usr/bin/env node
// CONSTRUCT — local server.
//   /api/target  SSE stream of URL forensics (pure Node, works anywhere)
//   /api/specs   local machine readout (no API calls, no tokens)
//   /api/chat    ORACLE proxy — degrades gracefully with no API key
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const si = require('systeminformation');
const { probeTarget } = require('./lib/target');

const PORT = process.env.PORT || 4173; // EDIT: change if 4173 is taken
const PUBLIC_DIR = __dirname;

// Minimal .env loader so the key is typed once into a file, not per session.
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('#')) continue;
      const eq = t.indexOf('=');
      if (eq === -1) continue;
      const k = t.slice(0, eq).trim();
      if (k && !(k in process.env)) process.env[k] = t.slice(eq + 1).trim();
    }
  }
} catch (err) {
  console.warn('[.env] unreadable:', err.message);
}

if (process.env.ANTHROPIC_API_KEY === 'paste-your-real-key-here') delete process.env.ANTHROPIC_API_KEY;

let client = null;
if (process.env.ANTHROPIC_API_KEY) {
  try {
    const Anthropic = require('@anthropic-ai/sdk');
    client = new Anthropic();
  } catch (err) {
    console.warn('[oracle] SDK unavailable:', err.message);
  }
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };

function serveStatic(req, res) {
  const reqPath = req.url.split('?')[0] === '/' ? '/index.html' : req.url.split('?')[0];
  const safe = path.normalize(reqPath).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(PUBLIC_DIR, safe);
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

// --- TARGET: stream stages as they genuinely complete ----------------------
async function handleTarget(req, res, url) {
  const input = url.searchParams.get('url');
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  const emit = (event, data) => {
    if (res.writableEnded) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  try {
    await probeTarget(input, emit);
  } catch (err) {
    emit('stage', { stage: 'fatal', status: 'failed', error: err.message });
    emit('done', { ok: false });
  }
  res.end();
}

// --- SPECS: local only, cached briefly so polling stays cheap --------------
let specsCache = null;
let specsAt = 0;
const SPECS_TTL = 2000;

async function gatherSpecs() {
  const [cpu, mem, osInfo, load, temp] = await Promise.all([
    si.cpu(), si.mem(), si.osInfo(), si.currentLoad(),
    si.cpuTemperature().catch(() => ({ main: null })),
  ]);
  return {
    os: `${osInfo.distro} ${osInfo.release}`,
    arch: osInfo.arch,
    hostname: osInfo.hostname,
    cpu: {
      model: `${cpu.manufacturer} ${cpu.brand}`.trim(),
      cores: cpu.cores,
      physicalCores: cpu.physicalCores,
      speedGhz: cpu.speed,
      loadPercent: Math.round(load.currentLoad),
      tempC: temp.main,
    },
    memory: {
      totalGb: +(mem.total / 1e9).toFixed(1),
      usedGb: +((mem.total - mem.available) / 1e9).toFixed(1),
      usedPercent: Math.round(((mem.total - mem.available) / mem.total) * 100),
    },
  };
}

async function handleSpecs(req, res) {
  try {
    const now = Date.now();
    if (!specsCache || now - specsAt > SPECS_TTL) { specsCache = await gatherSpecs(); specsAt = now; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(specsCache));
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: err.message }));
  }
}

// --- ORACLE ---------------------------------------------------------------
const SYSTEM_PROMPT = `You are ORACLE, the analysis layer of CONSTRUCT — a local network and
system forensics tool used by a senior network/security engineer.

Rules:
- You are handed real measurements. Never invent a number, never restate a value the user can
  already see without adding judgment to it.
- Be terse and technical. He knows what TLS, CSP, ASN and HSTS are. Do not explain them.
- If evidence does not support a conclusion, say so plainly rather than hedging into vagueness.
- No preamble, no "great question", no summary of what you are about to do.`;

async function handleChat(req, res) {
  if (!client) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'No ANTHROPIC_API_KEY set — ORACLE offline. Everything else works.' }));
    return;
  }
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', async () => {
    try {
      const { message, history, context } = JSON.parse(body || '{}');
      if (!message) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'message required' })); return; }
      const messages = [...(Array.isArray(history) ? history : [])];
      messages.push({
        role: 'user',
        content: context ? `Measurements from the current probe:\n${JSON.stringify(context)}\n\n${message}` : message,
      });
      const resp = await client.messages.create({
        model: 'claude-opus-5',
        max_tokens: 1024,
        output_config: { effort: 'low' },
        system: SYSTEM_PROMPT,
        messages,
      });
      if (resp.stop_reason === 'refusal') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ reply: 'ORACLE declined that request.' }));
        return;
      }
      const text = resp.content.find((b) => b.type === 'text')?.text ?? '';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ reply: text, usage: resp.usage }));
    } catch (err) {
      console.error('[oracle]', err.message);
      res.writeHead(err.status && err.status < 500 ? err.status : 500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === 'GET' && url.pathname === '/api/target') return handleTarget(req, res, url);
  if (req.method === 'GET' && url.pathname === '/api/specs') return handleSpecs(req, res);
  if (req.method === 'POST' && url.pathname === '/api/chat') return handleChat(req, res);
  return serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log(`CONSTRUCT running at http://localhost:${PORT}`);
  console.log(process.env.ANTHROPIC_API_KEY ? '  ORACLE: online' : '  ORACLE: offline (no ANTHROPIC_API_KEY — everything else works)');
});
