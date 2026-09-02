# Block ads & trackers by category

Categories let you block hundreds of domains at once with a single command. The included `categories-ai.toml` covers 32 categories: advertising, analytics, fingerprinting, session recording, telemetry, CDN, social tracking, data brokers, and more.

## 1. Start with a categories file

```bash
socklight
socklight --rules-file rules/dev.rules
```

## 2. See what categories are loaded

```
cats
```

Lists all categories sorted by severity with abbreviation, status (blocked / allowed / default), and description. Press `F2` in the TUI for a colour-coded panel view.

## 3. Block categories

```
deny @advertising        # block all ad networks
deny @fingerprinting     # block device fingerprinting services
deny @session_recording  # block session replay (Hotjar, FullStory, …)
deny @telemetry          # block OS and app telemetry
```

Use the full name or the abbreviation: `deny @ADV` = `deny @advertising`.

Active connections matching the category are killed immediately. Future ones are refused.

## 4. Allow exceptions within a blocked category

An explicit `allow` rule bypasses the category block:

```
deny @analytics
allow analytics.myownapp.com    # this host passes through anyway
```

URL rules are always checked before category rules — see [COMMANDS.md § Rules file format](COMMANDS.md#rules-file-format) for the full priority order.

## 5. Allowlist mode — block everything unknown

For a strict setup where only known hosts are allowed:

```
mode allowlist
allow api.github.com
allow *.python.org
deny @advertising           # redundant in allowlist, but explicit
```

Everything not in an `allow` rule or category is refused by default.

## 6. Save for next session

```
save
```

Category overrides (`deny @…` / `allow @…`) are saved in the rules file and restored on next start.

## 7. Export to Privoxy

```
save privoxy rules/privoxy
```

Generates `rules/privoxy.action` and `rules/privoxy.conf.snippet`. The action file contains `+block{}` sections for each blocked category's patterns. Import into Privoxy for persistent filtering without running sockLight.
