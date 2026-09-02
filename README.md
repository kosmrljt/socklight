# sockLight — SOCKS5 Dev Proxy

**A development SOCKS5 proxy with a live terminal dashboard.**

Point your containers or tools at it and see every outbound connection in real time — with the ability to block, allow, throttle, and categorize traffic without restarting anything.

```
┌─ Connections ──────────────────────────────────────────────────┬─ Categories ──────┐
│ ID  Status     Cat   Target                    ↑KB/s  ↓KB/s    │ ADV ✗ advertising │
│  9  ACTIVE     ANA   analytics.google.com:443   0      142     │ ANA   analytics   │
│  8  CLOSED     ADV   doubleclick.net:443                       │ TEL   telemetry   │
│  7  DENIED     FPR   fingerprint.com:443                       ├─ Filter rules ────┤
├─ Activity log ─────────────────────────────────────────────────┤ ✗ *.ads.com      │
│ 14:23:01 ACTIVE  api.github.com:443 [ANA]                      │ ✓ api.myapp.com  │
│ 14:23:02 DENIED  fingerprint.com:443 [FPR]                     │                   │
├─ Command ──────────────────────────────────────────────────────┘                   │
│ > deny @advertising                                                                │
└──────────────────────────────────────────────────────────────────────────────── ───┘
```

## Why

When you run AI coding agents or dev tools in containers, they make dozens of outbound connections — telemetry, ads, analytics, fingerprinting services — and you have no visibility into what leaves your machine.

sockLight puts a traffic light on every TCP connection:

- **See** every connection with hostname, category, and live transfer speed in KB/s
- **Inspect** any connection on demand — DNS lookup, reverse DNS, GeoIP, country flag
- **Block** by domain or by category (`deny @advertising` blocks 200+ ad domains at once)
- **Allow** only specific hosts with allowlist mode — block everything else by default
- **Throttle** bandwidth and add latency per host or category — without restarting connections
- **Export** rules to Privoxy or as a PAC file for browsers

curl and browsers connect to SOCKS5 directly. Most other tools (pip, npm, AI agents) speak only HTTP proxy — use Privoxy inside the container to bridge HTTP → SOCKS5 (built into dev-sandbox's `research` profile).

## Quick start

```bash
pip install git+https://github.com/kosmrljt/socklight.git

socklight                              # 32 categories loaded automatically
socklight --rules-file rules/dev.rules # with saved rules
socklight --categories simple          # 10 broad categories instead
socklight --categories-file my.toml   # custom category definitions
```

First run without a rules file: type `deny @advertising` → `save` inside the TUI. sockLight creates the rules file on first save.

Other options:
```bash
socklight --port 9050
socklight --no-tui --log-file proxy.log   # headless service
```

## Connecting clients

### Option 1 — Firefox

Settings → General → Network Settings → Settings… → Manual proxy configuration:

```
SOCKS Host: 127.0.0.1    Port: 1080    ● SOCKS v5
☑ Proxy DNS when using SOCKS v5
```

The checkbox routes DNS through sockLight — without it you see IP addresses instead of hostnames in the dashboard.

### Option 2 — curl, wget, CLI tools

```bash
export ALL_PROXY=socks5h://127.0.0.1:1080
```

`socks5h://` — the `h` means DNS is resolved by the proxy, same as the Firefox checkbox.

### Option 3 — Podman containers

```bash
podman run --rm -it \
  -e ALL_PROXY=socks5h://host.containers.internal:1080 \
  python:3.12 bash
```

`host.containers.internal` resolves to the host automatically (Podman 4.1+).

### Option 4 — HTTP → SOCKS5 via Privoxy (pip, npm, AI agents)

Most tools (pip, npm, Claude Code) only support HTTP proxy via `HTTP_PROXY` / `HTTPS_PROXY`. Privoxy bridges the gap — it runs inside the container and forwards HTTP proxy traffic to sockLight's SOCKS5.

[dev-sandbox](https://github.com/kosmrljt/dev-sandbox) includes Privoxy. Start sockLight first, then:

```bash
dev-sandbox --proxy 1080    # Privoxy → sockLight wired automatically
```

sockLight's `save privoxy` command exports your current rules directly into Privoxy format.

## What you can do

### Monitor live connections

The connections table updates every second — status, category, hostname, live KB/s, cumulative bytes. Press `H` to show/hide closed connections.

### Inspect a connection

Select a row and press `I` — sockLight queries DNS and GeoIP in the background:

```
#9 analytics.google.com:443
  IP:      142.250.185.206
  rDNS:    fra24s06-in-f14.1e100.net
  GeoIP:   🇺🇸 United States, Mountain View  AS15169 Google LLC
```

→ [Debug app traffic — step by step](docs/howto-debug.md)

### Filter connections

Block or allow by domain, wildcard, or entire category. Takes effect immediately — no restart.

```
deny  *.doubleclick.net      block domain and all subdomains
allow api.github.com:443     allow specific host + port
deny  @advertising           block entire category (200+ domains at once)
mode allowlist               block everything, allow only explicit rules
```

Select a row and press `D` to deny that host instantly, `A` to allow it.

→ [Block ads & trackers by category](docs/howto-categories.md)

### Throttle connections

Limit bandwidth or add latency per host or category, without dropping active connections.

```
throttle *.cdn.com down:2m up:100k    asymmetric limits
throttle api.slow.com delay:200ms     add latency only
throttle #9 100k                      live override for one connection
```

→ [Simulate a slow network](docs/howto-network.md)

### Mark, export, save

```
M (key)              mark host to marks.log for later review
Y (key)              copy hostname to clipboard
save                 save rules to --rules-file
save privoxy         export Privoxy .action + config snippet
save pac             export PAC file for browser proxy auto-config
dump <path>          snapshot of all connections + log
```

→ [Browser via PAC file](docs/howto-pac.md) · [Full command reference](docs/COMMANDS.md)

## Common parameters

| Parameter | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Listen address |
| `--port` | `1080` | Listen port |
| `--no-tui` | off | Headless mode, log to stdout |
| `--rules-file` | — | Load rules on startup; `save` writes back here |
| `--categories` | `full` | Built-in category preset: `simple` (10) or `full` (32) |
| `--categories-file` | — | Custom category definitions TOML (overrides `--categories`) |
| `--log-file` | — | Write activity log to file (works in both modes) |
| `--log-level` | `info` | `all` / `connections` / `denied` / `errors` / `none` |
| `--connect-timeout` | `10` | Seconds to wait for outbound connection |

## Not for production

sockLight is a development tool — no authentication, no encryption between client and proxy, not designed for high throughput or multi-user access.

## Documentation

| File | Description |
|---|---|
| [docs/HOWTO.md](docs/HOWTO.md) | How-to guides index |
| [docs/COMMANDS.md](docs/COMMANDS.md) | Full command & rules reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Code architecture and module overview |

## Related

[dev-sandbox](https://github.com/kosmrljt/dev-sandbox) — run AI agents in isolated Podman containers. Use `--proxy 1080` to route all container traffic through sockLight.

## License

MIT © Tomaž Košmrlj

---
Built through iterative pair programming with [Claude](https://claude.ai) (Anthropic).
