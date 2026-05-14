---
name: process-probe
description: Inspect a running process — its command line, environment variables, file descriptors, and network connections — through credential-safe helpers (env-keys, env-values, cmdline, info, fds, network) that this plugin puts on your PATH. Never read /proc/PID/environ or /proc/PID/cmdline directly; the proc-probe-guard.sh PreToolUse hook blocks those reads across Bash, Read, Edit, Write, and NotebookEdit. The helpers redact values when either the variable name matches a sensitive-name keyword (password, secret, token, key, …) or the value matches a known credential shape (sk-…, ghp_…, AKIA…, JWT, PEM private key) or a length+entropy gate. A two-stage env workflow (list keys first, then explicitly request specific values) is the canonical entry point. Use this skill for any process probing — debugging a hang, diagnosing why something is stuck, checking what arguments or environment a daemon was started with, exploring file descriptors or network connections — even when the specific operation isn't itself credential-sensitive (the goal is one central, judgment-call-free place for all process probing).
---

# Process-probe

## Why this skill exists

Reading `/proc/<pid>/environ` directly is a credential-exposure landmine. Most production daemons inherit credentials from their launching shell — database passwords, OAuth tokens, API keys, encryption passphrases — and those values sit in the process's environment for its lifetime. Anything that prints `/proc/<pid>/environ` (whether `cat`, `tr`, `xargs`, or a Python `open(...).read()`) prints those credentials.

Ad-hoc redaction is unsafe. A one-line `sed`-style filter is one wrong character away from emitting the raw values: subtle regex bugs (anchoring the keyword on the wrong side of `=`, treating `_` as a word boundary, forgetting case-insensitivity, etc.) cause the redaction to silently no-op. The output looks fine until you read it carefully — by which time the secrets are already in your terminal scrollback, your CI logs, or, for an AI agent, the conversation transcript and any session log file.

The lesson: **blacklist redaction fails open.** The correct posture is whitelist redaction (only emit known-safe values; redact anything that looks credential-shaped) *plus* a hook that blocks direct `/proc/*/environ` and `/proc/*/cmdline` reads, so the unsafe path can't be taken accidentally even when someone reaches for `cat` out of habit. This skill is the whitelist side; the `proc-probe-guard.sh` hook is the block side.

## When to invoke

Use these helpers whenever investigating a running process — debugging, diagnosing a hang, checking startup state, etc.

**Do not** invoke raw `cat /proc/<pid>/environ` or `cat /proc/<pid>/cmdline` or equivalent reads — the PreToolUse hook will block them. If a genuinely-novel probe is needed that the helpers don't cover, extend the helpers (and add a test) rather than reaching past them.

## The helpers

All take a single `<pid>` argument unless noted. All exit non-zero on missing-process / permission-denied; stderr explains.

| Helper | Output | What it does |
| --- | --- | --- |
| `env-keys <pid>` | one name per line | List the *names* of every env var the process inherited. No values printed. |
| `env-values <pid> NAME...` | `NAME=value` per line | Read explicit env vars by name. Each requested name prints as `NAME=<value>` by default; if the NAME matches a sensitive-name keyword OR the VALUE matches a credential-shape / entropy gate, it prints as `NAME=<redacted: REASON>` instead (REASON is `sensitive name` or `sensitive value`). Per-name override via `--unsafe-show NAME` — see "Override semantics" below. |
| `cmdline <pid>` | one argv element per line | Print argv with two-layer redaction: (1) tokens following secret-flag patterns (`--password`, `--token`, `--api-key`, `-p`, `-k`, …) become `<redacted: secret flag>`, and `--flag=value` forms become `--flag=<redacted: secret flag>`; (2) any remaining element that matches the shared value-shape heuristic (known credential formats like `sk-…`/`ghp_…`/`AKIA…`/JWT/PEM, or length+entropy gate) becomes `<redacted: secret value>`. `--unsafe` bypasses both layers. |
| `info <pid>` | one JSON object | `ps` summary: `pid`, `state`, `pcpu_percent`, `rss_kb`, `user`, `elapsed_seconds`, `command`, `started`. Username is resolved via `/proc/PID/status` + `pwd` to avoid `ps`'s 8-char truncation. |
| `fds <pid>` | JSONL, one object per fd | Open file descriptors: `{"fd": N, "kind": "REG"\|"DIR"\|"CHAR"\|"FIFO"\|"UNIX"\|"SOCKET"\|"ANON"\|"PIPE"\|"OTHER", "target": "..."}`. `target` is omitted for SOCKET entries (use `network` for per-connection info). To get counts by kind, aggregate after reading. |
| `network <pid>` | JSONL, one object per connection | `{"protocol": "tcp"\|"udp", "state": "ESTAB"\|"LISTEN"\|…, "local": "addr:port", "peer": "addr:port", "recv_q": N, "send_q": N}`. Uses `ss -tunp` on Linux; falls back to `lsof -nP -i -a -p` (which omits `recv_q`/`send_q` because lsof doesn't expose them). |

### Why these helpers, even for the non-sensitive operations?

`info`, `fds`, and `network` wrap `ps`, `lsof`, and `ss` — tools that aren't themselves credential-bearing. They live in this skill anyway for a few reasons:

1. **All process probing routes through one place.** "Need to know something about a running process? → use ``" replaces "decide whether this particular question needs the safe path or whether the raw tool is fine" — a judgment call that's easy to get wrong and is the kind of mistake this skill exists to prevent.
2. **Cross-platform smoothing.** The wrappers paper over per-system tool variation (`ss` vs `lsof`, `ps` field-format differences, Linux vs macOS), so you can probe processes on different systems the same way.
3. **Machine-readable output.** They produce JSON / JSONL, so the result is easy to parse, pipe through `jq`, or feed back into another tool.
4. **Future hook point.** If a field on `ps` / `ss` / `lsof` output ever becomes sensitive, there's one place to add redaction or filtering — no need to update every call site.

### Usage examples

Examples use placeholder values — PID `12345`, username `alice`, `user@example.com`, IPs in the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`).

**`env-keys`** — what env vars does this process have?

```sh
$ env-keys 12345
HOME
LANG
OBSIDIAN_EMAIL
OBSIDIAN_PASSWORD
OBSIDIAN_SYNC_DIR
OBSIDIAN_VAULT_NAME
OBSIDIAN_VAULT_PASSWORD
PATH
USER
```

**`env-values`** — read specific ones; sensitive vars auto-redact, mix is fine:

```sh
$ env-values 12345 \
    OBSIDIAN_VAULT_NAME OBSIDIAN_SYNC_DIR OBSIDIAN_PASSWORD OBSIDIAN_EMAIL
OBSIDIAN_VAULT_NAME=MyVault
OBSIDIAN_SYNC_DIR=/home/alice/MyVault
OBSIDIAN_PASSWORD=<redacted: sensitive name>
OBSIDIAN_EMAIL=user@example.com
```

See "Override semantics" below for the per-name `--unsafe-show` flag.

**`cmdline`** — argv with secret-flag values redacted; one argument per line:

```sh
# A process started with `my-app --token <SECRET> --port 8080 sk-ant-api03-...`:
$ cmdline 12345
my-app
--token
<redacted: secret flag>
--port
8080
<redacted: secret value>
```

The first redaction was triggered by the `--token` flag pattern; the second by the value-shape heuristic catching a positional `sk-ant-…` credential.

**`info`** — single JSON object:

```sh
$ info 12345
{"pid": 12345, "state": "Sl+", "pcpu_percent": 0.0, "rss_kb": 23724, "user": "alice", "elapsed_seconds": 98504, "command": "my-daemon", "started": "Tue May 12 15:26:18 2026"}
```

**`fds`** — JSONL, one open file descriptor per line:

```sh
$ fds 12345 | head -8
{"fd": 0, "kind": "CHAR", "target": "/dev/pts/5"}
{"fd": 1, "kind": "CHAR", "target": "/dev/pts/5"}
{"fd": 2, "kind": "CHAR", "target": "/dev/pts/5"}
{"fd": 5, "kind": "REG", "target": "/home/alice/.my-daemon/state.db"}
{"fd": 6, "kind": "ANON", "target": "anon_inode:[eventpoll]"}
{"fd": 8, "kind": "SOCKET"}
{"fd": 9, "kind": "SOCKET"}

# Aggregate by kind (consumers compute their own summaries):
$ fds 12345 | jq -r '.kind' | sort | uniq -c
      3 ANON
      3 CHAR
      3 REG
     14 SOCKET
```

**`network`** — JSONL, one connection per line:

```sh
$ network 12345
{"protocol": "tcp", "state": "ESTAB", "recv_q": 0, "send_q": 0, "local": "192.0.2.10:53086", "peer": "198.51.100.42:443"}
```

Typical investigation chain — "what is this process doing and why?" — is `info` → `cmdline` → `env-keys` (then `env-values` for specific ones) → `fds` and `network` for file-handle / connection state. Pipe through `jq` for filtering or projection.

## The two-stage env workflow

When you need an env var's value, **always** go through both stages:

1. **`env-keys <pid>`** — confirms the variable is set without exposing its value. Decide which specific names you actually need.
2. **`env-values <pid> NAME1 NAME2 ...`** — request only the names you need. Sensitive names are auto-redacted even when requested.

```sh
# Stage 1
env-keys 12345
# → see that OBSIDIAN_VAULT_NAME, OBSIDIAN_SYNC_DIR, OBSIDIAN_PASSWORD, ... are all set.

# Stage 2: request only what you need.
env-values 12345 OBSIDIAN_VAULT_NAME OBSIDIAN_SYNC_DIR
# → values printed.

# Trying to read a sensitive var (intentional):
env-values 12345 OBSIDIAN_PASSWORD
# → OBSIDIAN_PASSWORD=<redacted: sensitive name>
```

### Override semantics: `--unsafe-show NAME` is per-name, not global

By default, every requested variable prints — sensitive ones (by name OR value, see "Secret-detection heuristics" below) show as `<redacted: REASON>`; everything else prints its value normally. There is **no global "show everything" flag**. Each individual sensitive name you want raw must be named with its own `--unsafe-show`:

```sh
# Default behavior — sensitive ones redact, non-sensitive ones print clean.
env-values 12345 OBSIDIAN_VAULT_NAME OBSIDIAN_PASSWORD
# OBSIDIAN_VAULT_NAME=MyVault
# OBSIDIAN_PASSWORD=<redacted: sensitive name>

# Bypass for ONE specific name only:
env-values 12345 OBSIDIAN_VAULT_NAME OBSIDIAN_PASSWORD --unsafe-show OBSIDIAN_PASSWORD
# OBSIDIAN_VAULT_NAME=MyVault
# OBSIDIAN_PASSWORD=<actual value>

# To bypass multiple, repeat the flag:
env-values 12345 --unsafe-show TOKEN_A --unsafe-show TOKEN_B
```

Each `--unsafe-show NAME` is a literal CLI argument and so appears in the transcript, making the exception auditable. There is no shorthand for "all" because that would defeat the purpose: if unfiltered access is the goal, `cat /proc/<pid>/environ` would be the direct route — and the hook is there to stop exactly that.

Use `--unsafe-show NAME` only when the operator has given explicit permission to read that specific value.

## Secret-detection heuristics

`env-values` redacts a variable when **either** axis fires — same two-axis shape used by [detect-secrets](https://github.com/Yelp/detect-secrets), [gitleaks](https://github.com/gitleaks/gitleaks), and [truffleHog](https://github.com/trufflesecurity/trufflehog). Both axes live in `_secret_heuristics.py` (shared module; unit-tested in `_test_heuristics.py`).

### Axis 1: name-keyword detection

Variable names containing any of these keywords (case-insensitive, with letter-only boundaries so `API_TOKEN` matches but `MONKEY` doesn't):

- `password`, `passwd`, `pword`, `pwrd`, `passphrase`, `passcode`, `pin`
- `secret`
- `token`, `jwt`, `bearer`, `oauth`
- `key` (bare), and `api_key`, `access_key`, `secret_key`, `private_key`, `encryption_key`, `signing_key`, `client_secret`
- `credential`, `creds`
- `auth`
- `session`, `cookie`
- `private`
- `salt`, `nonce`, `signature`, `hmac`
- `sensitive`, `confidential`
- `mfa`, `otp`, `2fa`

The boundary trick: `\b` inside `API_TOKEN` does *not* mark the boundary between `_` and `T` because `_` is a regex word character. The actual pattern uses letter-only lookarounds (`(?<![A-Za-z])keyword(?![A-Za-z])`) so `_`, `-`, digits, and start/end-of-string all count as boundaries.

### Axis 2: value-shape detection

Even if a variable has an innocent name, the value gets redacted when it matches a known credential format or looks long-and-random:

**Known formats** (`KNOWN_SECRET_VALUE_PATTERNS`): Anthropic / OpenAI `sk-…`, GitHub PATs (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_`), Slack tokens (`xoxb-`, `xoxa-`, etc.), AWS access key IDs (`AKIA…`, `ASIA…`), JWTs (`eyJ…` with two more base64-url segments), Google API keys (`AIza…`), Stripe live keys (`sk_live_`, `rk_live_`, `pk_live_`), PEM-encoded private keys.

**Entropy fallback**: values ≥ 20 chars, in the token charset `[A-Za-z0-9+_./=\-]`, with Shannon entropy > 4.5 bits/char. Reference points: random hex ≈ 4.0, random base64 ≈ 6.0, English text ≈ 4.0–4.5, structured config (URLs, paths) ≈ 3.5. The charset gate excludes URLs (`://`), paths-with-other-chars, and email addresses (`@`), so those don't trip the entropy check.

### Tuning + extending

The patterns are heuristics, not guarantees. They err toward redacting more (acceptable — opt out per-name via `--unsafe-show NAME` with audit trail).

To extend: edit the constants in `lib/_secret_heuristics.py` (`SENSITIVE_NAME_PATTERN`, `KNOWN_SECRET_VALUE_PATTERNS`, or the threshold constants). **Whitelist-additions only** — never remove an existing keyword or pattern, since that would silently widen exposure. After every edit, run `python3 lib/_test_heuristics.py` from the plugin root; tests cover both axes and the combined `redaction_reason` entry point.

The redaction placeholder names *which axis* fired: `<redacted: sensitive name>` vs `<redacted: sensitive value>` — useful for understanding why a value was held back.

## The PreToolUse hook

`proc-probe-guard.sh` is a PreToolUse hook wired in `.claude/settings.json` with matcher `Bash|Read|Edit|Write|NotebookEdit`. It JSON-stringifies the entire `tool_input` and scans for a real procfs read — catching the path wherever it appears (Bash `command`, Read/Edit/Write `file_path`, Edit/Write `content` containing source code that would do the read, etc.). On match the hook exits with `decision: block` and points the message at this skill.

The hook deliberately whitelists only the path forms an actual read uses — numeric pids, literal `self` / `thread-self`, and shell-variable references `$pid` / `${pid}` / `$(cmd)` — so prose like `/proc/<pid>/environ` in a commit message or doc passes through. The synthetic test suite covers both block and allow paths across Bash, Read, Edit, Write, NotebookEdit, and Edit's `new_string` (code-being-written) scanning.

The cmdline check is included alongside environ because some programs accept secrets on argv. The `cmdline` helper redacts those tokens; raw access is blocked.

Residual bypass surfaces:

- **Indirect reads via a written-then-run script** — an agent could `Write` a script that doesn't contain the literal path (built via variable concatenation), then `Bash`-run it. The hook can't see inside the rendered script. Trust boundary is at the helper-script interface, not at the syscall — the existence of the helpers and the discipline of using them is the actual safeguard.
- **MCP tool that reads files** — if an MCP tool exposes a generic file-read with a `path` argument, the hook's `tool_input`-wide scan catches it as long as the path literal appears in the input. If the path is somehow obfuscated (base64, etc.), the hook won't see it.

## Extending the helpers

If you need a new probe operation, add it as a new executable in the plugin's `bin/` directory (Python or shell) with:

- A short module docstring at the top (what it does, credential-surface assessment).
- Whitelist-style filtering by default; an explicit `--unsafe` opt-in only when there's a real case.
- Tests against a known-running process before committing (the smoke tests in this repo's history cover the established helpers).

Update this SKILL.md's table when adding a helper.
