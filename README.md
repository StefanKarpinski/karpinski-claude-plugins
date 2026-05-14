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

Why it exists: ad-hoc redaction (e.g., a one-line `sed` filter over `/proc/<pid>/environ`) is one regex bug away from emitting credentials in clear into the conversation transcript. This plugin replaces the unsafe path with a vetted command (whitelist-style redaction by variable name *and* by value shape) and a tool-call hook that blocks the unsafe path entirely.

After install, the plugin puts a single command on your PATH: **`process-probe`**, with six subcommands.

```sh
process-probe --help                                  # list subcommands
process-probe env-keys <pid>                          # var NAMES (no values)
process-probe env-values <pid> NAME...                # explicit reads; sensitive auto-redact
process-probe env-values <pid> --unsafe-show NAME     # per-name override (auditable)
process-probe cmdline <pid>                           # argv, secret-flag/-shape values redacted
process-probe info <pid>                              # one JSON object: ps summary
process-probe fds <pid>                               # JSONL: open file descriptors
process-probe network <pid>                          # JSONL: TCP/UDP connections
```

The `PreToolUse` hook fires automatically across Bash, Read, Edit, Write, and NotebookEdit — any tool call referencing `/proc/<real-pid>/environ` or `/proc/<real-pid>/cmdline` is blocked with a pointer back to `process-probe`.

See [`plugins/process-probe/skills/process-probe/SKILL.md`](plugins/process-probe/skills/process-probe/SKILL.md) for the full reference: usage examples, override semantics, the secret-detection heuristics (both name-keyword and value-shape axes), the hook's coverage matrix, and known bypass surfaces.

The secret-detection heuristics follow the same two-axis shape as [detect-secrets](https://github.com/Yelp/detect-secrets), [gitleaks](https://github.com/gitleaks/gitleaks), and [truffleHog](https://github.com/trufflesecurity/trufflehog): keyword match on the variable name, plus known-credential-format and entropy detection on the value.

## Layout

```
.claude-plugin/
  marketplace.json           # marketplace manifest — lists the plugins
plugins/
  process-probe/
    .claude-plugin/
      plugin.json            # plugin manifest
    bin/
      process-probe          # the only thing on PATH; subcommand dispatcher
    libexec/                 # subcommand implementations (not on PATH)
      env-keys, env-values, cmdline, info, fds, network
    lib/                     # internal Python modules
      _secret_heuristics.py, _test_heuristics.py
    hooks/
      hooks.json             # PreToolUse hook wiring
      proc-probe-guard.sh    # the hook script
    skills/process-probe/
      SKILL.md               # skill description + reference docs
```

Why a single `process-probe` entry point with subcommands rather than separate executables: most of the subcommand names (`info`, `network`, `fds`, …) are generic enough to collide with system tools (`info` shadows `/usr/bin/info` on most Linuxes), and PATH ordering puts plugin `bin/` *after* `/usr/bin`, so a bare `info <pid>` would launch GNU info trying to read manual `<pid>`. One namespaced entry point sidesteps this and matches the conventional shape of `git` / `kubectl` / `docker` / `gh`.

Adding a new plugin to this marketplace: drop a directory under `plugins/`, give it `.claude-plugin/plugin.json`, and append an entry to `.claude-plugin/marketplace.json`.

## License

MIT. See [LICENSE](LICENSE).
