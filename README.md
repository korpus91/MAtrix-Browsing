# Matrix Web Access Terminal

A single-file, no-build HTML/CSS/JS toy: a Matrix-style "hacker terminal" that
lets you type in any URL and load it in a green, scanlined iframe view.

## Run it

No server, no dependencies. Just open `index.html` in a browser:

```
open matrix-browser/index.html      # macOS
xdg-open matrix-browser/index.html  # Linux
```

Click/press any key to skip the boot animation, then type a destination
(e.g. `wikipedia.org`) and hit **JACK IN**.

## Known limitation

Many sites (Google, most banks, GitHub, etc.) send an `X-Frame-Options` or
`Content-Security-Policy: frame-ancestors` header that blocks being loaded
inside anyone else's iframe — that's the target site's own security policy
and can't be bypassed from here. When a site refuses to load within ~3
seconds, the terminal logs it and opens the real page in a new browser tab
instead ("opens a portal").

This is a plain static page, not sandboxed — it's meant to be opened
directly in a browser, not embedded as a Claude Artifact (which blocks
cross-origin iframes by policy).
