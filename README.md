# karpinski-claude-plugins

A personal [Claude Code](https://claude.com/claude-code) plugin marketplace.

## Install

Add this marketplace once:

```sh
/plugin marketplace add StefanKarpinski/karpinski-claude-plugins
```

Then install whichever plugins you want:

```sh
/plugin install process-probe@karpinski-claude-plugins
```

To pin a specific tag or branch:

```sh
/plugin marketplace add StefanKarpinski/karpinski-claude-plugins#v0.1.0
```

## Plugins

### `process-probe`

Credential-safe helpers for inspecting a running process — environment variables, command-line argv, file descriptors, network connections — paired with a `PreToolUse` hook that blocks direct reads of `/proc/<pid>/environ` and `/proc/<pid>/cmdline`.

Why it exists: ad-hoc redaction (e.g., a one-line `sed` filter over `/proc/<pid>/environ`) is one regex bug away from emitting credentials in clear into the conversation transcript. This plugin replaces the unsafe path with a small toolkit of vetted helpers (whitelist-style redaction by variable name *and* by value shape) and a tool-call hook that blocks the unsafe path entirely.

Helpers (all take a single `<pid>` argument):

| Helper | Output | What it does |
| --- | --- | --- |
| `env-keys` | one name per line | List the *names* of every env var the process inherited. No values. |
| `env-values <pid> NAME...` | `NAME=value` per line | Read explicit env vars by name. Sensitive ones (by name keyword or value shape) print as `<redacted: REASON>`. Per-name `--unsafe-show NAME` override. |
| `cmdline` | one argv element per line | Print argv with two-layer redaction (secret flags + secret-shaped values). |
| `info` | one JSON object | `ps` summary (pid, state, %CPU, RSS, elapsed, command, started, user). |
| `fds` | JSONL, one object per fd | Open file descriptors (kind + target; sockets summarized). |
| `network` | JSONL, one object per connection | TCP/UDP connections via `ss` (falls back to `lsof`). |

See `plugins/process-probe/skills/process-probe/SKILL.md` for the full reference: usage examples, override semantics, the secret-detection heuristics (both name-keyword and value-shape axes), the hook's coverage matrix, and known bypass surfaces.

The secret-detection heuristics follow the same two-axis shape as [detect-secrets](https://github.com/Yelp/detect-secrets), [gitleaks](https://github.com/gitleaks/gitleaks), and [truffleHog](https://github.com/trufflesecurity/trufflehog): keyword match on the variable name, plus known-credential-format and entropy detection on the value.

## Layout

```
.claude-plugin/
  marketplace.json         # marketplace manifest — lists the plugins
plugins/
  process-probe/
    .claude-plugin/
      plugin.json          # plugin manifest
    skills/process-probe/
      SKILL.md             # skill description + reference docs
      scripts/
        env-keys, env-values, cmdline, info, fds, network
        _secret_heuristics.py, _test_heuristics.py
    hooks/
      hooks.json           # PreToolUse hook wiring
      proc-probe-guard.sh  # the hook script itself
```

Adding a new plugin: drop a directory under `plugins/`, give it `.claude-plugin/plugin.json`, and append an entry to `.claude-plugin/marketplace.json`.

## License

MIT. See [LICENSE](LICENSE).
