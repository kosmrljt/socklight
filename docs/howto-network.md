# Simulate a slow or unreliable network

Test how your app behaves under limited bandwidth or high latency — without touching your router. Throttle rules apply to active connections immediately, no reconnect needed.

## 1. Throttle a specific host

```
throttle api.myapp.com down:50k delay:300ms
```

Limits download to 50 KB/s and adds 300ms latency per chunk. Upload is unrestricted.

```
throttle *.cdn.com 200k          # both directions, 200 KB/s
throttle api.myapp.com delay:200ms  # latency only, no bandwidth limit
```

Speed units: `200k` = 200 KB/s · `1m` = 1 MB/s · `500` = 500 B/s

## 2. Throttle an entire category

```
throttle @cdn 200k
throttle @video down:300k up:1m
```

The category rule applies to all connections in that category. A host rule takes priority if both match.

## 3. Adjust a running connection live

Select a row in the connections table and press `T` — the command input fills with the current throttle for that host. Edit the speed and press Enter.

Or by connection ID:

```
throttle #12 100k
```

This override is not saved to the rules file.

## 4. Watch the speed columns

The `↑KB/s` and `↓KB/s` columns show live EMA-smoothed transfer speed per connection. Values below 1 KB/s are hidden. The throttle column shows the active limit in yellow when throttling is in effect.

## 5. Remove throttle rules

```
throttle api.myapp.com off    # one host
throttle @cdn off             # one category
throttles clear               # all rules
```

See [COMMANDS.md](COMMANDS.md) for full throttle syntax including asymmetric limits and latency-only rules.
