# Matrix Web Access Terminal

A Matrix-style "hacker terminal": web-access iframe browser, a local system
specs readout, and an in-character AI chat panel ("ORACLE") backed by the
Claude API.

## Run it

Now needs a local server (for the specs readout and the chat proxy):

```
cd matrix-browsing
npm install
export ANTHROPIC_API_KEY=sk-ant-...   # only needed for ORACLE chat
node server.js
```

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
