# Route pip, npm, and other HTTP-only tools through sockLight

Most CLI tools support `ALL_PROXY=socks5h://...` directly and work with sockLight out of the box. Some tools — `pip`, `npm`, `Claude Code`, most AI agents — only speak **HTTP proxy** and cannot connect to a SOCKS5 proxy directly. A lightweight bridge process translates between the two.

## Linux / macOS — Privoxy

[Privoxy](https://www.privoxy.org/) is a small HTTP proxy that can forward to SOCKS5. It's available in most package managers (`apt install privoxy`, `brew install privoxy`).

**Terminal 1 — start sockLight:**
```bash
socklight
```

**Terminal 2 — start Privoxy bridge, then run your tool:**
```bash
# One-liner: pipe a minimal config via stdin — no config file needed
echo 'forward-socks5 / 127.0.0.1:1080 .' | privoxy --no-daemon /dev/stdin &

export http_proxy=http://127.0.0.1:8118
export https_proxy=http://127.0.0.1:8118
export HTTP_PROXY=http://127.0.0.1:8118
export HTTPS_PROXY=http://127.0.0.1:8118

pip install requests        # traffic now visible in sockLight
npm install                 # traffic now visible in sockLight
claude                      # Claude Code traffic visible in sockLight
```

Privoxy listens on `127.0.0.1:8118` by default. The single config line tells it to forward all traffic (`/`) to sockLight at `1080`, with no parent proxy (trailing `.`).

To stop Privoxy when done: `kill %1` or `pkill privoxy`.

### Custom port or host

```bash
printf 'forward-socks5 / 127.0.0.1:1080 .\nlisten-address 127.0.0.1:9999\n' \
  | privoxy --no-daemon /dev/stdin &

export http_proxy=http://127.0.0.1:9999
export https_proxy=http://127.0.0.1:9999
export HTTP_PROXY=http://127.0.0.1:9999
export HTTPS_PROXY=http://127.0.0.1:9999
```

## Linux / macOS — 3proxy (alternative)

[3proxy](https://3proxy.ru/) is a tiny cross-platform proxy server — a single binary, no config file needed. Available via `apt install 3proxy` or build from source; on macOS via `brew install 3proxy` (if available) or a binary download.

```bash
3proxy --proxy -p8118 -a -n -e127.0.0.1 parent 1000 socks5 127.0.0.1 1080 &
```

3proxy accepts the same arguments on Linux, macOS, and Windows — useful if you want the same script to work across platforms.

## Windows

Both Privoxy and 3proxy work on Windows.

**Privoxy** — installer at [privoxy.org](https://www.privoxy.org/). Add these two lines to its `config.txt`:

```
forward-socks5 / 127.0.0.1:1080 .
listen-address 127.0.0.1:8118
```

Then in a Command Prompt or PowerShell:

```powershell
set HTTP_PROXY=http://127.0.0.1:8118
set HTTPS_PROXY=http://127.0.0.1:8118
pip install requests
```


## Why not just use `ALL_PROXY`?

`ALL_PROXY=socks5h://127.0.0.1:1080` works for tools built on `libcurl` (curl, wget, most system tools). It does **not** work for tools that implement their own HTTP client without SOCKS5 support — which includes most language package managers and many AI development tools.

The HTTP bridge adds one process but requires no changes to the tools themselves.

## Keeping rules when sockLight is not running

After tuning your deny/allow rules in sockLight, export them to Privoxy format so they apply even when sockLight is not running:

```
save privoxy
```

This writes a `.action` file and a `.conf.snippet` you can include in your Privoxy config.
