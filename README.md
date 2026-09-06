# sockLight — SOCKS5 Dev Proxy

**A development SOCKS5 proxy with a live terminal dashboard.**

Point your containers or tools at it and see every outbound connection in real time — with the ability to block, allow, throttle, and categorize traffic without restarting anything.

![sockLight dashboard](docs/demo.gif)


## Why

- **No certificate installation, no HTTPS decryption.** sockLight sees where a connection goes and how much moves through it — never the payload. Works with any app, container, or CLI tool out of the box: no custom CA, no per-app trust store, no certificate pinning failures.
- **Works directly with any SOCKS5h client.** `curl`, `wget`, Firefox, Podman/Docker containers — set `ALL_PROXY=socks5h://...` and you're done. Tools that only speak HTTP proxy (`pip`, `npm`, Claude Code, most AI agents) need a one-line Privoxy bridge — see [Works well with dev-sandbox](#works-well-with-dev-sandbox).
- **Hostnames, not IPs.** Because apps route DNS through the proxy (`socks5h://`), you see `analytics.google.com` in the dashboard, not `142.250.74.100`.
- **Runs as a normal user.** No root, no firewall rules, no system-wide changes. Start it, point your app at it, stop it.
- **Block and throttle without restarting.** Rules take effect on active connections immediately — no app restart, no reconnect.
- **Categories.** 34 pre-defined groups (advertising, telemetry, fingerprinting, CDN, …). One command blocks an entire category at once.
- **Live speed per connection.** Distinguish "broken" from "extremely slow" at a glance — useful when a build or API call hangs silently with no error message.

### Not a mitmproxy replacement

sockLight deliberately stops at the connection level: hostname, port, bytes, speed. If you need to inspect or rewrite request bodies, use [mitmproxy](https://mitmproxy.org) instead and accept the CA installation that comes with it.

## Quick start

Requires **Python 3.11+**. Developed and tested on Linux; macOS and Windows should work but are not tested yet.

```bash
pip install git+https://github.com/kosmrljt/socklight.git

socklight                              # binds 0.0.0.0:1080 — containers can reach it
socklight --host 127.0.0.1             # local only, blocks container access
socklight --rules-file rules/dev.rules # with saved rules
socklight --categories simple          # 10 broad categories instead
socklight --categories-file my.toml    # custom category definitions
```

> `0.0.0.0` is the default so Podman/Docker containers can reach the proxy on the host.
> On a shared or untrusted network, start with `--host 127.0.0.1`.

Then point something at it:

```bash
# curl, wget, most CLI tools
export ALL_PROXY=socks5h://127.0.0.1:1080

# Podman / Docker container
podman run --rm -it -e ALL_PROXY=socks5h://host.containers.internal:1080 python:3.12 bash
```

For Firefox: Settings → Network Settings → Manual proxy → SOCKS Host `127.0.0.1`, Port `1080`, SOCKS v5, and tick **Proxy DNS when using SOCKS v5**.

The `h` in `socks5h://` and the Firefox DNS checkbox do the same thing: they make the proxy resolve names, so the dashboard shows hostnames instead of IP addresses.

First run without a rules file: type `deny @advertising` → `save` inside the TUI. sockLight creates the rules file on first save.

→ [Connect your app or browser — full guide](docs/howto-debug.md)

## What you can do

### Monitor live connections

The connections table updates every second — status, category, hostname, live KB/s, cumulative bytes. Press `H` to show/hide closed connections. Press `q` or type `quit` to stop the proxy; the TUI lists the other keybindings on screen.

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
deny  doubleclick.net        block exactly this host
deny  *.doubleclick.net      block subdomains only
deny  @advertising           block entire category
allow api.github.com:443     allow specific host + port
mode  allowlist              block everything, allow only explicit rules
```

`*.example.com` matches `sub.example.com` but not `example.com` itself — SOCKS5 receives the exact hostname the app sent, and these are two distinct strings. To block both, add two rules:

```
deny doubleclick.net
deny *.doubleclick.net
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

## Example use cases

**Build or install hangs silently.** A Node.js compile stalled — no error, no timeout, just hanging. sockLight showed the connection to the npm registry was alive but transferring at ~7 KB/s over 20 seconds. Switching to a mirror fixed it. Without connection speed visibility there is no way to distinguish "broken" from "extremely slow".

**Testing app behaviour against a slow API.** Use `throttle api.example.com down:50k delay:300ms` to simulate a slow upstream service during development — without a mock server, without touching the router, without restarting the app. Remove or adjust the rule at any time, even mid-connection.

**Keeping an eye on what your app calls.** During development it is easy to lose track of which third-party services an app depends on. sockLight shows every outbound connection by hostname and category in real time. Unexpected calls (telemetry, analytics, ads) are visible immediately.

**Blocking noise during development.** `deny @telemetry` and `deny @advertising` take effect instantly. Export to Privoxy or a PAC file to keep the rules when sockLight is not running.

## Works well with dev-sandbox

[dev-sandbox](https://github.com/kosmrljt/dev-sandbox) runs AI agents and dev tools in isolated Podman containers. The two tools are designed to work together.

Start sockLight first, then launch the container with:

```bash
dev-sandbox --proxy 1080
```

dev-sandbox includes Privoxy, which bridges HTTP proxy → SOCKS5 inside the container. This means all container traffic — including tools that only support HTTP proxy (`pip`, `npm`, Claude Code, AI agents) — is routed through sockLight automatically via `HTTP_PROXY` / `HTTPS_PROXY`. You get full visibility and control over everything the container calls, without any per-tool configuration.

Use `save privoxy` to export your current sockLight rules into Privoxy format and keep them active inside the container when sockLight is not running.

## Not for production

sockLight is a development tool: no authentication, no encryption between client and proxy, not designed for high throughput or multi-user access.

It also [binds to `0.0.0.0` by default](#quick-start) so containers can reach it. On a shared or untrusted network, start it with `--host 127.0.0.1`.

## Documentation

| File | Description |
|---|---|
| [docs/HOWTO.md](docs/HOWTO.md) | How-to guides index |
| [docs/COMMANDS.md](docs/COMMANDS.md) | Full command & rules reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Code architecture and module overview |

## License

MIT © Tomaž Košmrlj

Built through iterative pair programming with [Claude](https://claude.ai) (Anthropic).
