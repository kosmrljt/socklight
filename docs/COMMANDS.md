# sockLight — Commands & Rules Reference

## TUI commands

Type in the command bar at the bottom. `Tab` autocompletes, `↑ ↓` browse history.

### Filter rules

```
deny  *.ads.com              block all subdomains (not the root ads.com itself)
deny  tracker.io:443         block specific host + port
allow api.myapp.com          add allow rule
remove *.ads.com             remove a rule
clear                        remove all filter rules
clear deny                   remove all deny rules only
clear allow                  remove all allow rules only
mode denylist                allow all, block deny matches  (default)
mode allowlist               block all, allow only explicit rules
```

### Category overrides

Use full name or abbreviation (case-insensitive): `@advertising` = `@ADV`

```
deny   @advertising          block all connections in this category
allow  @analytics            explicitly allow (useful in allowlist mode)
remove @advertising          clear override — back to default allow
cats                         list all categories with current status
```

Press `F2` in TUI for a formatted category reference sorted by severity.

### Throttle

```
throttle *.slow.com 500k              both directions, 500 KB/s
throttle *.cdn.com down:2m up:100k   asymmetric limits
throttle api.com delay:200ms          latency only — no bandwidth limit
throttle api.com 500k delay:100ms     bandwidth + latency combined
throttle @video down:300k             throttle entire category
throttle #9 100k                      live override for one active connection (not saved)
throttle *.slow.com off               remove rule
throttles                             list all throttle rules
throttles clear                       remove all throttle rules
```

Speed units: `200k` = 200 KB/s · `1m` = 1 MB/s · `500` = 500 B/s

Host rule takes priority over category rule when both match.

### Inspection and management

```
I (key)          DNS + GeoIP lookup for selected connection
D (key)          Deny selected host (adds rule + kills connection)
A (key)          Allow selected host
R (key)          Remove deny/allow rule for selected host
T (key)          Prefill throttle command for selected host
K (key)          Kill selected connection (force-close relay)
M (key)          Mark host to marks.log (for later review)
Y (key)          Copy hostname to clipboard
kill <id>        Force-close connection by ID
dump <path>      Save full snapshot to file (connections + log)
loglevel <level> Filter activity log: all / connections / denied / errors / none
```

### Persistence

```
save                    write current rules to --rules-file
save privoxy [path]     export Privoxy .action + .conf.snippet
save pac [path]         export PAC file for browser proxy auto-config
reload                  reload rules file from disk
```

---

## Rules file format

Rules are plain text. Pass `--rules-file` on startup to load them; `save` writes changes back.
sockLight creates the file on first `save` if it doesn't exist yet.

```
# comment
mode denylist              # or: allowlist

# host rules — checked first, in order
deny  *.doubleclick.net
deny  tracker.io:443
allow api.github.com:443

# category overrides — checked after host rules
deny  @advertising
deny  @fingerprinting
allow @analytics

# throttle rules
throttle @video down:500k up:2m
throttle slow-api.example.com delay:300ms
```

**Priority order** (first match wins):

1. Host DENY rule → block
2. Host ALLOW rule → pass through (bypasses category check)
3. Category blocked? → block
4. Category explicitly allowed? → pass through
5. Mode default: DENYLIST = allow, ALLOWLIST = block

---

## Filter patterns

| Pattern | Matches |
|---|---|
| `example.com` | Exact host, any port |
| `example.com:443` | Exact host + port |
| `*.example.com` | Any subdomain of example.com — **not** `example.com` itself |
| `*.example.com:8080` | Any subdomain on port 8080 |
| `*` | Everything |

Patterns use fnmatch wildcards — `*` matches any string including dots.
**Note:** `*.example.com` matches `sub.example.com` but **not** the root `example.com`.
To block both, add two rules: `deny *.example.com` and `deny example.com`.

---

## Category definitions

Categories are loaded from a TOML file (`--categories-file`). The built-in `full` preset
covers 34 categories: advertising, analytics, telemetry, fingerprinting, session recording,
CDN, cloud providers, social tracking, data brokers, and more.

Each category has:
- `abbrev` — 3–5 char label shown in the connections table (e.g. `ADV`, `ANA`, `FPR`)
- `severity` — `high` / `medium` / `low` / `info` — controls sort order in the panel
- `color` — Rich color name shown in TUI
- `geo_hint` — optional country code (e.g. `CN`, `RU`) shown in categories panel
- `patterns` — list of fnmatch hostname patterns

Categories are checked in definition order — more specific categories must come before broad ones.
Default is allow; use `deny @name` in rules file or TUI to block a category.

---

## Key bindings (full)

| Key | Action |
|---|---|
| `I` | DNS + GeoIP lookup for selected connection |
| `D` | Deny selected host (adds rule + kills connection) |
| `A` | Allow selected host |
| `R` | Remove rule for selected host |
| `T` | Prefill throttle command for selected host |
| `K` | Kill selected connection |
| `M` | Mark host to marks.log |
| `Y` | Copy hostname to clipboard |
| `H` | Toggle history (show/hide closed rows) |
| `C` | Clear activity log |
| `End` | Resume log auto-scroll |
| `Tab` | Move focus between panels |
| `Shift+↑↓` | Scroll filter rules panel |
| `Ctrl+↑↓` | Scroll categories panel |
| `F1` / `?` | Help |
| `F2` | Category reference |
| `Q` / `Ctrl+Q` | Quit |
