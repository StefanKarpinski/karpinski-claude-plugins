#!/usr/bin/env python3
"""Unit tests for _secret_heuristics. Run with `python3 _test_heuristics.py`.

Coverage:
- name pattern: should-trigger vs should-not-trigger cases
- value heuristic: known-format hits, entropy hits, false-positive immunity
- combined entry point
"""

import os
import sys

_HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _HERE)

from _secret_heuristics import (  # noqa: E402
    is_sensitive_name,
    looks_like_secret_value,
    redaction_reason,
    shannon_entropy,
)


def _expect(label: str, got, want) -> bool:
    ok = got == want
    mark = "✓" if ok else "✗"
    note = "" if ok else f" (got {got!r}, want {want!r})"
    print(f"  {mark} {label}{note}")
    return ok


def test_name() -> int:
    print("\n== name-keyword detection ==")
    cases_redact = [
        "PASSWORD", "OBSIDIAN_PASSWORD", "DB_PASSWD", "MY_PASSPHRASE",
        "PIN", "AWS_SECRET_ACCESS_KEY", "API_KEY", "API_TOKEN",
        "OAUTH_TOKEN", "JWT", "BEARER_TOKEN",
        "GITHUB_TOKEN", "STRIPE_SECRET", "PRIVATE_KEY", "SSH_PRIVATE_KEY",
        "ENCRYPTION_KEY", "SIGNING_KEY", "CLIENT_SECRET",
        "ADMIN_CREDENTIAL", "AWS_CREDS",
        "HTTP_AUTH", "AUTH_TOKEN", "BASIC_AUTH",
        "SESSION", "SESSION_COOKIE", "COOKIE",
        "PRIVATE_THING", "SALT", "NONCE", "API_SIGNATURE", "HMAC_KEY",
        "SENSITIVE_FIELD", "CONFIDENTIAL_DATA",
        "MFA_TOKEN", "OTP_CODE", "2FA_BACKUP",
    ]
    cases_allow = [
        "PATH", "HOME", "USER", "SHELL",
        "OBSIDIAN_VAULT_NAME", "OBSIDIAN_SYNC_DIR", "LIFEBASE_VAULT",
        "LANG", "TZ", "TERM",
        "MONKEY", "DONKEY", "KEYBOARD_LAYOUT", "KEYRING_DIR",   # contain "key" but not as word
        "AUTHORITY",                                              # has "AUTH" only as substring of word
        "PINNED",                                                 # "PIN" substring of word
    ]
    failed = 0
    for name in cases_redact:
        if not _expect(f"redact: {name}", is_sensitive_name(name), True):
            failed += 1
    for name in cases_allow:
        if not _expect(f"allow:  {name}", is_sensitive_name(name), False):
            failed += 1
    return failed


def test_value() -> int:
    print("\n== value-shape detection ==")
    cases_redact = [
        # Known format prefixes
        ("anthropic key", "sk-ant-api03-" + "A" * 90),
        ("openai key",    "sk-" + "B" * 48),
        ("github PAT",    "ghp_" + "C" * 36),
        ("github fine",   "github_pat_" + "D" * 82),
        ("aws id",        "AKIAIOSFODNN7EXAMPLE"),
        ("aws temp id",   "ASIA" + "Z" * 16),
        ("slack bot",     "xoxb-1234-5678-abcdefghijklmnop"),
        ("jwt",           "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        ("pem private",   "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END..."),
        ("google api",    "AIzaSy" + "X" * 33),
        ("stripe live",   "sk_live_" + "Y" * 24),
        # Entropy-based catches (long, random-looking, token charset)
        ("base64-ish 30", "aB3+xY9_zP4kL2nM7qR8wT5vU1pE6sJ-"),
    ]
    cases_allow = [
        # Short values
        ("short pin",     "1234"),
        ("short pass",    "hunter2"),
        ("vault name",    "LifeBase"),
        # Long values that aren't credentials
        ("path",          "/home/stefankarpinski/LifeBase/Work/Org/People"),
        ("URL",           "https://api.weather.gov/gridpoints/OKX/34,43/forecast"),
        ("email",         "stefan@karpinski.org"),
        ("english long",  "This is a long sentence written in English."),
        ("locale long",   "en_US.UTF-8:en_US:en"),
        ("device names",  "demeter6:stefan@desktop"),
        # Long path-like with PATH separator chars
        ("PATH var",      "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    ]
    failed = 0
    for label, value in cases_redact:
        if not _expect(f"redact: {label}", looks_like_secret_value(value), True):
            failed += 1
            # Useful debug: show entropy for failing entropy cases.
            print(f"      len={len(value)}  entropy={shannon_entropy(value):.2f}")
    for label, value in cases_allow:
        if not _expect(f"allow:  {label}", looks_like_secret_value(value), False):
            failed += 1
            print(f"      len={len(value)}  entropy={shannon_entropy(value):.2f}")
    return failed


def test_combined() -> int:
    print("\n== combined entry point ==")
    failed = 0
    # Sensitive name → reason "sensitive name"
    r = redaction_reason("OBSIDIAN_PASSWORD", "f7RWzuChR!2A")
    if not _expect("sensitive-name dominates", r, "sensitive name"):
        failed += 1
    # Innocent name + known-format value → reason "sensitive value"
    r = redaction_reason("MISC", "sk-ant-api03-" + "Z" * 80)
    if not _expect("innocent name + value pattern", r, "sensitive value"):
        failed += 1
    # Innocent name + innocent value → None
    r = redaction_reason("HOME", "/home/stefankarpinski")
    if not _expect("innocent + innocent", r, None):
        failed += 1
    return failed


def main() -> int:
    failed = test_name() + test_value() + test_combined()
    if failed:
        print(f"\n{failed} failure(s)")
        return 1
    print("\nall passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
