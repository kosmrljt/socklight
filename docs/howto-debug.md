# Debug app traffic

See every outbound connection your app or container makes — hosts, categories, byte counts, live speed. Block unwanted calls without touching app code.

## 1. Start sockLight

```bash
socklight                              # 32 categories loaded automatically
socklight --rules-file rules/dev.rules # with saved rules from a previous session
```

The rules file is created on first `save`. Categories classify connections automatically (ADV, ANA, FPR, …).

## 2. Point your app at the proxy

**Firefox:**

Settings → General → scroll to *Network Settings* → Settings… → Manual proxy configuration:

```
SOCKS Host: 127.0.0.1    Port: 1080    ● SOCKS v5
☑ Proxy DNS when using SOCKS v5
```

The last checkbox is important — without it Firefox resolves DNS locally and you see
IP addresses instead of hostnames in the dashboard.

**CLI tools (curl, wget):**
```bash
export ALL_PROXY=socks5h://127.0.0.1:1080
```

The `h` in `socks5h://` means the same thing as the Firefox checkbox — DNS goes through
sockLight, not your local resolver.

**Podman container:**
```bash
podman run --rm -it \
  -e ALL_PROXY=socks5h://host.containers.internal:1080 \
  python:3.12 bash
```

## 3. Watch connections live

The connections table updates every second. Press `H` to show closed connections alongside active ones.

Each row shows: status, category (from TOML), hostname:port, live KB/s, cumulative bytes.

Press `I` on any row for a DNS + GeoIP lookup:

```
#9 analytics.google.com:443
  IP:      142.250.185.206
  rDNS:    fra24s06-in-f14.1e100.net
  GeoIP:   🇺🇸 United States, Mountain View  AS15169 Google LLC
```

## 4. Block what you don't want

Select a row and press `D` — the host is denied and the connection killed immediately. Press `R` to undo.

Or type a rule manually:

```
deny *.doubleclick.net
deny @fingerprinting
```

Rules take effect immediately, no restart needed. See [COMMANDS.md](COMMANDS.md) for full syntax.

## 5. Find hidden calls with allowlist mode

Switch to allowlist to see everything your app calls that you didn't expect:

```
mode allowlist
allow api.myapp.com
allow *.myapp-cdn.com
```

Everything else is refused. Unexpected connections appear as DENIED in the log.

Switch back when done:

```
mode denylist
```

## 6. Save rules for next session

```
save
```

Writes all rules (deny/allow, categories, throttle) to `--rules-file`. Loaded automatically on next start.
