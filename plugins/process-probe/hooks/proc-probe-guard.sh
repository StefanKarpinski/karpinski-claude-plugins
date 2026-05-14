#!/bin/bash
# proc-probe-guard.sh — PreToolUse hook that blocks any tool call which
# would read /proc/<pid>/environ or /proc/<pid>/cmdline.
#
# Why: those paths expose process credentials. The 2026-05-13 incident
# (OBSIDIAN_PASSWORD leaked to the transcript when a blacklist-style sed
# redaction silently no-op'd) showed that any path touching them
# without a vetted whitelist filter is a credential-exposure landmine.
#
# Use the  helpers instead — they redact
# values by default and require explicit --unsafe-show opt-in for raw
# access.
#
# Tools covered: Bash (command string), Read / Edit / Write /
# NotebookEdit (file_path). We don't special-case each tool's schema;
# instead the hook JSON-stringifies the entire tool_input and scans
# for a real procfs read. That covers any current or future tool whose
# input includes the credential-bearing path anywhere.
#
# Hook protocol:
#   stdin  = JSON containing tool_name and tool_input
#   exit 0 = allow
#   exit 2 = block (stderr is fed back to Claude as the reason)

set -u

input=$(cat)

# Scan the whole tool_input as a JSON-stringified value. The regex below
# anchors on /proc/ then the pid token; whether the surrounding bytes
# come from a bash command string, a file_path, or some other field
# doesn't matter — a real read attempt will contain the pattern.
scan_target=$(printf '%s' "$input" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(json.dumps(d.get("tool_input", {})), end="")
except Exception:
    pass
')

# Whitelist the forms that an actual read uses, and only those:
#   /proc/<digits>/...        numeric pid     e.g. /proc/293983/environ
#   /proc/self/...            literal         /proc/self/environ
#   /proc/thread-self/...
#   /proc/$VAR/...            shell var       /proc/$pid/environ
#   /proc/${VAR}/...          shell var       /proc/${pid}/environ
#   /proc/$(cmd args)/...     cmd subst       /proc/$(pgrep foo)/environ
#
# Anything else — bare-word placeholders ("PID", "pid"),
# angle/square/curly-bracketed placeholders ("<pid>", "[pid]",
# "{pid}"), other punctuation — is presumed to be documentation prose
# and lets through. The trade-off: a contrived placeholder that
# matches a whitelisted form (e.g. literally `/proc/self/environ` in a
# comment) WILL still be blocked. Acceptable — that exact string in
# tool input would be a real read anyway.
if printf '%s' "$scan_target" | grep -qE '/proc/([0-9]+|self|thread-self|\$\w+|\$\{[^}]+\}|\$\([^)]+\))/(environ|cmdline)\b'; then
    cat >&2 <<'EOF'
Blocked: tool call would read /proc/<pid>/environ or /proc/<pid>/cmdline.

These paths leak process credentials when filtered with anything less
than a whitelist (the 2026-05-13 OBSIDIAN_PASSWORD incident is what
this guard exists to prevent).

Use the vetted `process-probe` command instead (the plugin puts it on
your PATH; run `process-probe --help` for the full list):

  process-probe env-keys <pid>                         # list var NAMES, no values
  process-probe env-values <pid> NAME...               # explicit reads, sensitive auto-redacted
  process-probe env-values <pid> --unsafe-show NAME    # opt-in raw value, audit-trail in transcript
  process-probe cmdline <pid>                          # argv with secret-flag values redacted
  process-probe info <pid>                             # ps state, no creds
  process-probe fds <pid>                              # open fds, sockets summarized
  process-probe network <pid>                          # TCP/UDP connections only

See the process-probe SKILL.md for the full rationale and the
sensitive-name pattern.

If you have a genuine need to read /proc/<pid>/{environ,cmdline} raw
that the helpers don't cover, extend the helpers (and update the
SKILL) rather than bypassing this guard.
EOF
    exit 2
fi

exit 0
