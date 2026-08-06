# Matrix Web Access Terminal

A Matrix-style "hacker terminal": web-access iframe browser, a local system
specs readout, and an in-character AI chat panel ("ORACLE") backed by the
Claude API.

## Run it (Windows -- double-click)

1. Clone or download this repo.
2. Copy `.env.example` to `.env` (same folder) and paste your real key from
   console.anthropic.com in place of the placeholder. Skip this if you only
   want the SPECS panel -- ORACLE chat is the only part that needs it.
3. Double-click `start.bat`. First run installs dependencies (~1 min), then
   it opens `http://localhost:4173` in your browser automatically. Leave
   the black window open -- closing it stops the server.

## Run it (any OS -- terminal)

```
cd matrix-browsing
npm install
cp .env.example .env   # then edit .env and paste your real key in
node server.js
```

(`set ANTHROPIC_API_KEY=...` in a Windows terminal, or `export
ANTHROPIC_API_KEY=...` in bash/zsh, also works instead of `.env` --
`.env` just means you don't have to retype it every session.)

Open `http://localhost:4173`. Click/press any key to skip the boot
animation. Two panels dock top-right:

- **SPECS** — CPU, RAM, disk, GPU, read straight from your machine via the
  `systeminformation` library. Polls every 3 seconds. No network calls, no
  API tokens spent — it's pure local `os`/hardware queries.
- **ORACLE** — a themed chat panel that calls the real Claude API
  (`claude-opus-5`) through `server.js`, so your API key stays on the
  server and never reaches the browser. Requires `ANTHROPIC_API_KEY` to be
  set; each message costs normal API usage.

The original address bar still works the same way: type a destination
(e.g. `wikipedia.org`) and hit **JACK IN**.

## Known limitation (web access)

Many sites (Google, most banks, GitHub, etc.) send an `X-Frame-Options` or
`Content-Security-Policy: frame-ancestors` header that blocks being loaded
inside anyone else's iframe — that's the target site's own security policy
and can't be bypassed from here. When a site refuses to load within ~3
seconds, the terminal logs it and opens the real page in a new browser tab
instead ("opens a portal").

## Notes

This is a real Node app now (`server.js` + `package.json`), not a static
file — it needs `node server.js` running, and it's not embeddable as a
Claude Artifact (iframes to arbitrary origins are blocked by Artifact CSP,
and the chat/specs endpoints need a real server). `node_modules/` and any
`.env` file are gitignored — never commit your API key.
