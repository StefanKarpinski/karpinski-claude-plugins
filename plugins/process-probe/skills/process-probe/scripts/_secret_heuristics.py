"""Shared secret-detection heuristics used by env-values and friends.

Two-axis detection, following the same shape as detect-secrets,
gitleaks, and truffleHog:

1. Name-keyword detection. If the variable name contains any of a set
   of credential-suggesting substrings, treat the value as sensitive.
   Patterns drawn from detect-secrets' KeywordDetector defaults plus
   gitleaks' built-in rules.

2. Value-shape detection. If the value matches a known credential
   format (sk-*, AKIA*, ghp_*, JWT, PEM private key, …) or is long
   enough and high-entropy enough to look random, treat it as
   sensitive regardless of the variable name.

These are heuristics, not guarantees. They err on the side of
redacting more (acceptable trade — opt out per-name with
--unsafe-show in env-values).
"""

import math
import re
from collections import Counter


# ---------------------------------------------------------------------------
# Axis 1: name-keyword detection
# ---------------------------------------------------------------------------

# Case-insensitive whole-keyword detection. Boundaries on either side
# use letter-only lookarounds (rather than \b) because `_` is a regex
# word character — so `\b` inside `API_TOKEN` does NOT mark the
# boundary between `_` and `T`. The letter-only lookaround treats `_`,
# `-`, digits, and start/end-of-string as boundaries, which matches
# how env-var and config-key names are usually formed.
SENSITIVE_NAME_PATTERN = re.compile(
    r"""(?<![A-Za-z])(
        passw(?:o?rd|d)
      | passcode | passphrase | pin
      | secret
      | token | jwt | bearer | oauth
      | key
      | api[_-]?key | access[_-]?key | secret[_-]?key | private[_-]?key
      | encryption[_-]?key | signing[_-]?key | client[_-]?secret
      | credential | creds?
      | auth
      | session | cookie
      | private
      | salt | nonce | signature | hmac
      | sensitive | confidential
      | mfa | otp | 2fa
    )(?![A-Za-z])""",
    re.IGNORECASE | re.VERBOSE,
)


def is_sensitive_name(name: str) -> bool:
    return bool(SENSITIVE_NAME_PATTERN.search(name))


# ---------------------------------------------------------------------------
# Axis 2: value-shape detection
# ---------------------------------------------------------------------------

# Known credential format prefixes / structures. Match anywhere via
# .search so values embedded in a longer string (e.g. quoted) still
# trigger.
KNOWN_SECRET_VALUE_PATTERNS = [
    # Anthropic / OpenAI: sk-..., sk-ant-...
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}\b"),
    # GitHub personal-access tokens
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bghs_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bghu_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bghr_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),
    # Slack tokens
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    # AWS access key IDs (long-lived and temporary)
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"\bASIA[A-Z0-9]{16}\b"),
    # JWT: three base64-url segments separated by dots; the eyJ header
    # is the base64-encoded {"alg":..., ...
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    # PEM-encoded private key
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # Google API key
    re.compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"),
    # Stripe live keys
    re.compile(r"\b(?:sk|rk|pk)_live_[A-Za-z0-9]{20,}\b"),
]


# Charset of a value that "looks like" a token (base64ish / alnum +
# common punct used in tokens). Excludes spaces, slashes, colons, @,
# etc. so URLs, paths, and email addresses don't trip the entropy
# check.
TOKEN_CHARSET = re.compile(r"^[A-Za-z0-9+_./=\-]+$")


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character. Reference points:
    random hex ≈ 4.0, random base64 ≈ 6.0, random ASCII ≈ 6.5,
    English text ≈ 4.0–4.5, structured config (paths, URLs) ≈ 3.5."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# Length and entropy thresholds for "looks random". Short strings, even
# if random, are usually not credentials worth redacting (PIN codes,
# short hashes); long strings with high entropy almost always are.
VALUE_LENGTH_THRESHOLD = 20
VALUE_ENTROPY_THRESHOLD = 4.5


def looks_like_secret_value(value: str) -> bool:
    if not value:
        return False
    # 1. Known credential formats (fast, deterministic).
    for pat in KNOWN_SECRET_VALUE_PATTERNS:
        if pat.search(value):
            return True
    # 2. Length + charset + entropy fallback for unknown-format tokens.
    if len(value) < VALUE_LENGTH_THRESHOLD:
        return False
    if not TOKEN_CHARSET.match(value):
        return False
    return shannon_entropy(value) > VALUE_ENTROPY_THRESHOLD


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------

def redaction_reason(name: str, value: str) -> str | None:
    """Returns a short reason string if (name, value) should be
    redacted, else None. Reason is suitable for inclusion in the
    redaction placeholder so the user can tell *why* the value was
    held back."""
    if is_sensitive_name(name):
        return "sensitive name"
    if looks_like_secret_value(value):
        return "sensitive value"
    return None
