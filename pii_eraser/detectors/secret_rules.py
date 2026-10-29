"""Secret rules: credentials with a known shape, assignments to secret-named
keys, and long random strings. All are code-safe; that is where secrets live.

Known shapes come first and score highest: a match is almost never anything
else. The assignment and entropy rules catch the rest at lower confidence.
"""

import math
import re

from pii_eraser.detectors.regex import Rule
from pii_eraser.detectors.validators import shannon_entropy
from pii_eraser.types import Kind

_M = re.MULTILINE

# Values that name a secret instead of holding one: env lookups, templates,
# redactions, obvious dummies. Left alone so config docs stay readable.
_NOT_A_VALUE = re.compile(
    r"^(?:\$\{?\w+\}?|\{\{.*\}\}|<[^>]*>|%\(?\w+\)?s?|\*+|x{4,}|\.{3,}|"
    r"(?:your|my|example|dummy|test|fake|mock|sample|changeme|placeholder|redacted|secret|password|token)[-_\w]*)$",
    re.IGNORECASE,
)
# MAX_TOKENS = "max_tokens", "gateway-key": names, not credentials. Costs
# letter-only passwords, which in code are rarer than enum values and fixtures.
_IDENTIFIER = re.compile(r"^[A-Za-z_-]+$")


def _real_value(value: str) -> bool:
    return not _NOT_A_VALUE.match(value) and not _IDENTIFIER.match(value)


def _random_looking(value: str, bar: float = 4.2) -> bool:
    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_letter and has_digit and shannon_entropy(value) > bar


def _char_class(c: str) -> int:
    return 0 if c.isupper() else 1 if c.islower() else 2


def _class_switch_rate(value: str) -> float:
    switches = sum(_char_class(a) != _char_class(b) for a, b in zip(value, value[1:]))
    return switches / (len(value) - 1)


def _random_for_its_length(value: str) -> bool:
    """Entropy is capped at log2(len): an 18-char random value can never reach
    4.2. Behind a secret-named key the bar scales with length, but only for a
    run that keeps switching between upper, lower and digits the way random
    text does; words, CamelCase and snake_case names, versions and paths keep
    the full bar."""
    if re.search(r"[_./-]", value) or _class_switch_rate(value) < 0.5:
        return _random_looking(value)
    return _random_looking(value, min(4.2, 0.8 * math.log2(len(value))))


def _ms(name, pattern, confidence=0.97, validate=None):
    return Rule(name, Kind.SECRET, pattern, confidence, _M, code_safe=True, validate=validate)


SECRET_RULES = [
    _ms(
        "private_key_block",
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        0.99,
    ),
    _ms("aws_access_key_id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    _ms("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    _ms("github_fine_grained_pat", r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    _ms("gitlab_token", r"\bgl(?:pat|dt|rt|ptt|cbt|oas)-[A-Za-z0-9_\-]{20,}"),
    _ms("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    _ms("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    _ms("openai_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}"),
    _ms("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _ms("stripe_key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    _ms("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", 0.93),
    # Password inside a URL: only the password is replaced, the host stays readable.
    _ms("url_credentials", r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s:/@]{3,})@", 0.95, validate=_real_value),
    # password = "…", api_key: '…', SECRET_TOKEN="…" — the quoted value only.
    _ms(
        "secret_assignment",
        r"""(?i:\b\w*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)\w*)"""
        r"""["']?\s*[:=]\s*["']([^"'\s]{8,})["']""",
        0.85,
        validate=_real_value,
    ),
    # Same, unquoted, in .env / YAML style: API_KEY=abc123…, also as a diff line.
    _ms(
        "secret_assignment_bare",
        r"""^[+\- ]?\s*(?:export\s+)?(?i:\w*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential)\w*)\s*[:=]\s*([^\s"'#]{12,})\s*$""",
        0.8,
        validate=lambda v: _real_value(v) and _random_for_its_length(v),
    ),
    # Anything quoted, long and random: hashes in hex stay (entropy <= 4.0).
    _ms("high_entropy_string", r"""["']([A-Za-z0-9+/=_\-]{24,})["']""", 0.6, validate=_random_looking),
]
