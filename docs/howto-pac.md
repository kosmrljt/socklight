# Browser via PAC file

Export your rules as a PAC (Proxy Auto-Config) file. The browser uses it to decide per-request whether to block, proxy, or connect directly — without sockLight needing to be running.

## 1. Set up rules, then export

```
deny @advertising
deny @fingerprinting
deny *.doubleclick.net
allow api.github.com:443
save pac ~/proxy.pac
```

The PAC file is a static snapshot of your current rules. Re-export after rule changes.

## 2. Launch browser with the PAC file

```bash
# Chromium / Chrome
chromium --proxy-pac-url="file:///home/user/proxy.pac"

# Firefox: Settings → Network → Automatic proxy configuration URL
#   file:///home/user/proxy.pac
```

## 3. What the PAC file does

| sockLight rule | PAC behaviour |
|---|---|
| `deny *.ads.com` | → routed to `PROXY 127.0.0.1:1` (refused instantly) |
| `deny @advertising` | → all category patterns → `PROXY 127.0.0.1:1` |
| `allow api.github.com` | → `DIRECT` (bypasses any block) |
| everything else | → `DIRECT` or through proxy, depending on mode |

Blocked connections are refused at the browser level — no DNS lookup, no network round-trip.

## 4. Combine with an SSH tunnel for remote access

```bash
# Open SSH SOCKS5 tunnel on port 1081
ssh -D 1081 -N user@remote-server
```

Edit the exported PAC file to route specific hosts through the tunnel:

```javascript
if (shExpMatch(host, "*.internal.company.com"))
    return "SOCKS5 127.0.0.1:1081";
```

This way the browser tunnels internal traffic through SSH while blocking ad/tracker domains directly.

## 5. Difference from Privoxy export

| | PAC file | Privoxy |
|---|---|---|
| Runs as | browser-side JS | separate proxy process |
| sockLight needed | no | no (after export) |
| Protocol support | HTTP/HTTPS | HTTP/HTTPS → SOCKS5 |
| Updates | re-export + browser restart | re-export + privoxy reload |
| pip / npm / CLI tools | no | yes (via HTTP_PROXY) |

Use `save privoxy` if you need to filter non-browser tools. See [howto-categories.md § Export to Privoxy](howto-categories.md#7-export-to-privoxy).
