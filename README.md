# CONSTRUCT

URL forensics with a Matrix face. Type a domain, get the intelligence dossier
your browser refuses to show you.

## The idea

**Node is not a browser, and that is a capability — not a limitation.**

`X-Frame-Options` is an instruction to a *rendering engine*. A server-side HTTP
client ignores it completely and gets strictly more than a browser would ever
show you: the full redirect chain, the raw certificate, the negotiated cipher,
and honest per-phase timing.

The previous version of this project tried to render sites in a green iframe and
failed on most real destinations, because most real sites forbid framing. Now
that refusal is reported as a *finding* rather than experienced as a failure.

## Run it

**Windows:** double-click `start.bat`. First run installs dependencies, then
opens `http://localhost:4173`.

**Any OS:**

```
npm install
node server.js
```

No API key is needed. ORACLE chat is optional and off by default — copy
`.env.example` to `.env` and paste a real key only if you want it.

## What a probe reports

| Stage | What it answers |
|---|---|
| **Resolve** | `cnn` is not a hostname. Rather than guessing a TLD by string append, it races real DNS lookups in parallel and shows you which candidate answered, and how fast. |
| **Transport** | The real redirect chain, and per-phase timing stamped from actual socket events — DNS, TCP, TLS handshake, TTFB. Flags any hop that traverses plaintext HTTP. |
| **Certificate** | Issuer, expiry with days remaining, SAN, SHA-256 fingerprint, protocol and cipher. Reads a *bad* certificate rather than refusing to connect. |
| **Interception** | Connects twice — once against Node's bundled Mozilla CA list, once against the OS trust store. If Mozilla rejects the chain and your OS accepts it, **something is decrypting your traffic**, and the intercepting CA is named. |
| **Posture** | Frameability decided server-side from `X-Frame-Options` and CSP `frame-ancestors`; cookie flag audit (HttpOnly / Secure / SameSite); a security-header score. |

## Design notes

The palette is deliberate. Green is used as a *light source*, not as a text
color: body text is a green-tinted bone grey (`#C5D0C9`) and saturated phosphor
is rationed to things that are actually live. Pure `#00FF41` on `#000000` passes
WCAG AAA at 15.38:1 and is still fatiguing — it draws 99.5% of its luminance
from one subpixel (so ClearType has nothing to work with), sits at essentially
maximum chroma, and true black maximizes halation. Severity is encoded in
background fill rather than glyph color, so a critical row costs no extra
reading effort and survives color blindness.

Rendering runs on a `requestAnimationFrame` accumulator at a fixed 30Hz step
rather than `setInterval`, stops entirely when the tab is hidden, and honors
`prefers-reduced-motion`. The measured frame cost is displayed in the masthead;
it currently runs about 0.2ms of main-thread JS per frame.

## Honest limitations

- The socket census (mapping every local connection to its owning process) is
  not built yet. It is Windows-specific and needs testing on real hardware.
- `expired.badssl.com` and `self-signed.badssl.com` cannot be tested from behind
  an intercepting proxy — the proxy refuses them and returns its own 503 before
  the real certificate is ever presented.
- Nothing here fakes a delay, fabricates a value, or fakes progress. If a number
  is shown, it was measured.
