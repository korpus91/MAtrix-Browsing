#!/usr/bin/env node
// Local server for the Matrix terminal: serves the static page, proxies
// chat requests to the Claude API (so the API key never reaches the
// browser), and reports local system specs (no API calls, no tokens).
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');
const si = require('systeminformation');

const PORT = process.env.PORT || 4173; // EDIT: change if 4173 is taken
const PUBLIC_DIR = __dirname;

// Minimal .env loader (no dependency) so the key only has to be typed once,
// into a file, instead of set in the shell every session.
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const value = trimmed.slice(eq + 1).trim();
      if (key && !(key in process.env)) process.env[key] = value;
    }
  }
} catch (err) {
  console.warn('[.env] could not read .env file:', err.message);
}

if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'paste-your-real-key-here') {
  console.warn('ANTHROPIC_API_KEY is not set (or is still the placeholder) -- ORACLE chat will not work.');
  console.warn('  Copy .env.example to .env and paste your real key in.');
  console.warn('The SPECS panel works fine without it.');
  if (process.env.ANTHROPIC_API_KEY === 'paste-your-real-key-here') delete process.env.ANTHROPIC_API_KEY;
}

const client = process.env.ANTHROPIC_API_KEY ? new Anthropic() : null; // reads ANTHROPIC_API_KEY from env

const SYSTEM_PROMPT = `You are ORACLE, a rogue AI embedded in a hacker terminal aesthetic
straight out of the Matrix. Stay in character: terse, cryptic, a little
theatrical. You are not actually a hacking tool -- you follow the same
safety rules as any other assistant and refuse real malicious requests,
in character ("that path is not open to you").`;

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json',
};

function serveStatic(req, res) {
  const reqPath = req.url === '/' ? '/index.html' : req.url;
  const safePath = path.normalize(reqPath).replace(/^(\.\.[/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safePath);
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

async function handleChat(req, res) {
  if (!client) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'ANTHROPIC_API_KEY is not set on the server.' }));
    return;
  }

  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', async () => {
    try {
      const { message, history } = JSON.parse(body || '{}');
      if (!message || typeof message !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'message is required' }));
        return;
      }

      const messages = [
        ...(Array.isArray(history) ? history : []),
        { role: 'user', content: message },
      ];

      const response = await client.messages.create({
        model: 'claude-opus-5',
        max_tokens: 1024,
        output_config: { effort: 'low' }, // ADDED: snappy replies for a chat UI
        system: SYSTEM_PROMPT,
        messages,
      });

      if (response.stop_reason === 'refusal') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ reply: 'ORACLE goes silent. That path is not open to you.' }));
        return;
      }

      const text = response.content.find((b) => b.type === 'text')?.text ?? '';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ reply: text }));
    } catch (err) {
      console.error('[chat] error:', err.message);
      const status = err.status && err.status < 500 ? err.status : 500;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'ORACLE could not be reached.' }));
    }
  });
}

// Local-only, zero-token system readout. Cached briefly so a fast-polling
// UI doesn't re-run heavier probes (disk, graphics) on every tick.
let specsCache = null;
let specsCacheAt = 0;
const SPECS_CACHE_MS = 2000; // EDIT: raise if polling less often

async function gatherSpecs() {
  const [cpu, mem, osInfo, disks, graphics, currentLoad, temp] = await Promise.all([
    si.cpu(),
    si.mem(),
    si.osInfo(),
    si.fsSize(),
    si.graphics(),
    si.currentLoad(),
    si.cpuTemperature().catch(() => ({ main: null })), // not every platform exposes this
  ]);

  return {
    os: `${osInfo.distro} ${osInfo.release} (${osInfo.arch})`,
    hostname: osInfo.hostname,
    cpu: {
      model: `${cpu.manufacturer} ${cpu.brand}`.trim(),
      cores: cpu.cores,
      physicalCores: cpu.physicalCores,
      speedGhz: cpu.speed,
      loadPercent: Math.round(currentLoad.currentLoad),
      tempC: temp.main,
    },
    memory: {
      totalGb: +(mem.total / 1e9).toFixed(1),
      usedGb: +((mem.total - mem.available) / 1e9).toFixed(1),
      usedPercent: Math.round(((mem.total - mem.available) / mem.total) * 100),
    },
    disks: disks.map((d) => ({
      mount: d.mount,
      totalGb: +(d.size / 1e9).toFixed(1),
      usedPercent: Math.round(d.use),
    })),
    gpu: graphics.controllers.map((g) => ({
      model: g.model,
      vramMb: g.vram || null,
    })),
  };
}

async function handleSpecs(req, res) {
  try {
    const now = Date.now();
    if (!specsCache || now - specsCacheAt > SPECS_CACHE_MS) {
      specsCache = await gatherSpecs();
      specsCacheAt = now;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(specsCache));
  } catch (err) {
    console.error('[specs] error:', err.message);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Could not read system specs.' }));
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/chat') { handleChat(req, res); return; }
  if (req.method === 'GET' && req.url === '/api/specs') { handleSpecs(req, res); return; }
  serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log(`Matrix terminal running at http://localhost:${PORT}`);
});
