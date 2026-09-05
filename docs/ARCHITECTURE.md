# sockLight — SOCKS5 Dev Proxy — Architecture

## Purpose

Development tools (IDEs, package managers, scripts) are often configured to use a SOCKS5 proxy.
sockLight hooks into that: every outbound TCP connection passes through it, giving you full
visibility — see what is happening in real time, block unwanted domains, throttle bandwidth per
category, and export rules for Privoxy.

---

## Module overview

```
socklight/cli.py            CLI arguments, main(), entry point after pip install
run.py                      development wrapper (calls socklight.cli:main)
socklight/
  socks5.py                 SOCKS5 protocol (handshake, request parsing)
  server.py                 TCP listener, allow/deny decision, connection lifecycle
  relay.py                  bidirectional byte transfer between client and target
  tracker.py                tracking of active and closed connections (stats, history)
  classifier.py             domain classification into categories (trie + RE)
  filters.py                allow/deny rules for domains and categories
  throttle.py               bandwidth and latency limiting
  tui.py                    Textual ProxyApp — dashboard, commands, tick loop
  tui_screens.py            HelpScreen, CatsScreen, category display helpers
  tui_exporters.py          PAC / Privoxy / Adblock export functions
socklight/data/
  categories-simple.toml   10 broad categories (built-in preset)
  categories-full.toml     32 detailed categories (built-in preset, default)
rules/                      user rules files (saved settings, not part of the package)
```

---

## How one connection travels

```
Client (IDE, curl, …)
  │
  │  TCP connection to localhost:1080
  ▼
socks5.py — SOCKS5 handshake
  │  reads: version, auth method, target domain/IP, port
  │  replies: connection granted / rejected
  ▼
server.py — decision
  │
  ├─ classifier.py     which category is this domain? (advertising, analytics, …)
  ├─ filters.py        is the domain/category blocked?
  │
  ├─ DENY  → sends SOCKS5 Connection Refused, closes
  │
  └─ ALLOW → opens TCP to target
       │
       ▼
     relay.py — bidirectional transfer
       ├─ task 1: client → target  (upload)    ← throttle.py limits speed
       └─ task 2: target → client  (download)  ← throttle.py limits speed
```

---

## Module by module

### socks5.py — SOCKS5 protocol

Implements the [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) handshake:

1. Client sends: supported auth methods → proxy replies: chosen method (0x00 = none)
2. Client sends: request (CONNECT + target domain/IP + port)
3. Proxy replies: success or error

Result is a `ConnectRequest` object with fields `address_type`, `host`, `port`.
The module knows nothing about allow/deny — it only parses the protocol.

---

### server.py — proxy core

`ProxyServer` accepts TCP connections and spawns an async handler for each one.

**Decision chain** (per connection):

```
1. URL DENY rule       → block (regardless of category)
2. URL ALLOW rule      → pass through (regardless of category)
3. Category blocked?   → block
4. Category allowed?   → pass through (useful in ALLOWLIST mode)
5. Default mode:
     DENYLIST   → pass through
     ALLOWLIST  → block
```

When the decision is ALLOW, the server opens a TCP connection to the target and hands
both streams to `relay.py`.

**Throttle:** before relaying, the server asks `ThrottleEngine` for speed settings and
creates a `ThrottleState` object that relay reads on every chunk.

---

### relay.py — byte transfer

Two AnyIO tasks run concurrently in a task group:
- `pipe_upload`: reads from client, writes to target
- `pipe_download`: reads from target, writes to client

**Structured concurrency:** when one finishes (EOF or error), the task group automatically
cancels the other. No manual cleanup needed — the `async with tg` block does not exit
until both tasks have finished.

**Throttle:** each chunk passes through `ThrottleState`, which:
1. Checks the bandwidth limit → if exceeded, sleeps until the next window
2. Adds artificial latency (`delay_ms`) for slow-network simulation

---

### tracker.py — connection tracking

`ConnectionRecord` is a mutable dataclass for one TCP session:
- `bytes_sent` / `bytes_recv` — incremented in real time from relay callbacks
- `status` — CONNECTING → ACTIVE → CLOSED / DENIED / FAILED
- `category` — category name (set by server after classification)

`ConnectionTracker` holds:
- `_active` dict: live connections (ID → record)
- `_history` deque: closed connections, `maxlen=200` (oldest evicted automatically)

The TUI reads both every second and renders the table. No locks needed — everything runs
in the same async event loop.

---

### classifier.py — domain classification

Every domain is matched against categories from the TOML file. A category is e.g.
`advertising`, `analytics`, `cloud_cdn`, `us_bigtech`, …

**Hybrid trie + RE index** for fast lookup:
- At load time: each pattern (`*.doubleclick.net`) is indexed by `(TLD, domain)` → `com/doubleclick`
- At classification time: 2 dict lookups by TLD and domain produce a small bucket (~10-20 patterns)
- Only those patterns are tested with RE — not all of them

Patterns with wildcards in the TLD (e.g. `*.google.com.*`) go into a `_fallback` list and
are only tested when the bucket produces no match.

**Categories are not blocked by default.** They are blocked only by an explicit
`deny @categoryName` in the rules file or via a TUI command.

**Overrides:** `_cat_overrides: dict[str, bool]` holds runtime decisions:
- `True` = explicitly blocked (`deny @cat`)
- `False` = explicitly allowed (`allow @cat`)
- absent = default allow

---

### filters.py — URL and category rules

`FilterEngine` holds a list of `FilterRule` objects (pattern + port + kind).

**Two modes:**
- `DENYLIST` (default): everything allowed except what is explicitly blocked
- `ALLOWLIST`: everything blocked except what is explicitly allowed

Rules are checked in insertion order — first match wins.
`check_verbose()` returns `(allowed: bool, rule | None)` — the server knows which rule
matched and shows it in the log.

Category overrides are mirrored between `FilterEngine._cat_overrides` and
`Classifier._cat_overrides` — one is the source of truth for persistence (rules file),
the other for classification (runtime).

---

### throttle.py — bandwidth limiting

`ThrottleEngine` holds rules for domains and categories.
`ThrottleState` is a per-connection mutable object (download_bps, upload_bps, delay_ms).

Relay reads `ThrottleState` on every chunk — no restart needed when the TUI changes a
rule on an active session.

Rule format: `throttle *.slow.com 200k`, `throttle @analytics down:100k up:2m delay:50ms`

---

### tui.py — Textual dashboard

Core module (~2140 lines). Built with [Textual](https://textual.textualize.io/).
Screen widgets live in `tui_screens.py`; export helpers in `tui_exporters.py`.

**Layout:**
```
┌─ Connections table ─────────────────────┬─ Categories ──┐
│ ID  Status  Cat  Target  ↑KB/s  ↓KB/s … │  ADV  ads…    │
│ …                                       │  ANA  analy…  │
├─ Activity log ──────────────────────────┤  …            │
│ 10:42:01 ACTIVE  google.com:443         ├─ Filter rules ┤
│ 10:42:02 DENIED  ads.example.com        │  ✗ *.ads.com  │
├─ Command input ─────────────────────────┤  ✓ safe.io    │
│ >                                       └───────────────┘
└─────────────────────────────────────────┘
```

**Tick system:** `_on_tick()` is called every second and:
1. Reads active and historical connections from the tracker
2. Updates the table (changed cells only, no full rebuild)
3. Refreshes the categories panel every 3 ticks
4. Calculates EMA speed for each active connection

**EMA speed:** `speed = 0.3 * raw + 0.7 * prev_ema` — smoothed over ~3 seconds,
displayed in KB/s, hidden below 1 KB/s.

**Commands** (typed into the command input):
- `deny / allow / remove <host|*.pat>` — URL rules
- `deny / allow / remove @<cat|abbrev>` — categories
- `throttle <host|@cat> <speed>` — bandwidth limiting
- `mode denylist|allowlist` — switch mode
- `save [path]` — save rules
- `save pac [path]` — export PAC file for browser proxy configuration
- `save privoxy [path]` — export Privoxy action + config snippet
- `save adblock [path]` — export Adblock Plus / uBlock Origin filter list

---

## Async model

The entire proxy runs in **one AnyIO event loop** (Trio backend):

```
anyio.run()
  └─ ProxyApp (Textual) — TUI event loop
       └─ run_worker(_run_proxy)
            └─ ProxyServer.serve()
                 └─ listener.serve()  — for each connection:
                      └─ _handle_client()  [as async task]
                           └─ relay_streams()  [2 tasks in task group]
```

Textual and AnyIO are compatible — Textual uses AnyIO internally, so the server worker
runs in the same event loop without blocking the TUI.

**Why no locks?**
- `ConnectionRecord.bytes_sent/recv` is written by relay tasks, read by the TUI tick
- Only one task is active at a time in an event loop (cooperative multitasking)
- `await` points are the only places where the context switches — while the TUI tick
  is reading, no relay task can write

---

## Patterns for learning

This project illustrates three concepts that are often poorly explained in async Python.

---

### 1. Tick system — why not reactive

The intuitive idea: when `bytes_sent` increases, immediately update the TUI. The problem:
relay sends packets hundreds of times per second. Each `update_cell()` call in Textual
triggers a re-render — the TUI becomes the bottleneck and slows the proxy.

Solution: **batch update once per second**.

```python
# tui.py
def on_mount(self) -> None:
    self.set_interval(1.0, self._on_tick)   # Textual calls _on_tick every second
```

`set_interval()` is a Textual method that schedules periodic calls inside the event loop
without blocking. `_on_tick()` collects all changes at once and updates the table once.

The relay tasks run undisturbed and only increment `bytes_sent` / `bytes_recv` on
`ConnectionRecord`. The TUI reads those values on each tick — relay neither knows nor
cares about the display.

Trade-off: the TUI lags up to 1 second behind reality. Acceptable for a monitoring tool;
not for a real-time game.

---

### 2. Structured concurrency — why no try/finally

Relay must run in two directions simultaneously (upload and download). The naive approach:

```python
# Unsafe pattern
t1 = asyncio.create_task(pipe_upload())
t2 = asyncio.create_task(pipe_download())
await asyncio.gather(t1, t2)
# Problem: if t1 raises, t2 keeps running in the background forever
```

An AnyIO task group solves this automatically:

```python
# relay.py — structured concurrency
async with anyio.create_task_group() as tg:
    tg.start_soon(pipe_upload)
    tg.start_soon(pipe_download)
# When one finishes (EOF, error, cancel) → tg automatically cancels the other
# The block does not exit until both tasks have finished
```

The `async with` block is the **lifetime boundary** of both tasks — they cannot escape it.
This is structured concurrency: no manual cleanup, no leaks.

---

### 3. Why no locks for shared data

`ConnectionRecord` is written by relay tasks and read by the TUI tick — with no mutex lock.
This is safe only because everything runs in the **same event loop** (cooperative multitasking).

In async code, the context switches only at `await`. Between one `await` and the next, no
other task can run. `bytes_sent += len(chunk)` is one operation with no `await` — atomic
from the event loop's perspective.

```
relay task:   reads chunk → bytes_sent += n → await sock.write(chunk)
                                                     ↑
                                             only here can the context
                                             switch to the TUI tick
```

With `threading` (true parallel threads) you would need a lock — two threads could
genuinely reach the same field at the same time. With async that is impossible.

**Limitation:** this holds only when all code runs in the same event loop.
`anyio.to_thread.run_sync()` (used for DNS lookups) runs in a separate thread —
care is needed there.

---

## Rules file format

```
# comment
mode denylist          # or allowlist

# host rules
deny  *.ads.example.com
allow safe.example.com:443

# categories
deny  @advertising
allow @analytics

# throttle
throttle *.slow.com 200k
throttle @video down:500k up:1m delay:100ms
```

Rules are loaded at startup (`--rules-file`) and on the `reload` command.
Order in the file reflects priority (host rules before category rules).

---

## Categories TOML format

```toml
[categories.advertising]
color       = "red"
abbrev      = "ADV"
severity    = "high"
geo_hint    = ""
description = "Ad networks and tracking pixels"
patterns    = [
    "*.doubleclick.net",
    "googlesyndication.com",
]
```

`severity` determines display order in the TUI (high → medium → low → info).
Categories are matched in definition order — more specific categories must come first.
