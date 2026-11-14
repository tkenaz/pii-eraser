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


# Prefixes that name a digest or an identifier, not a credential: sha512-... in a lock file, commit-..., id_...
_NOT_A_TOKEN_PREFIX = re.compile(r"^(?:sha\d*|md5|crc\d*|uuid|guid|id|rev|commit|build|hash|etag|v\d+)$", re.IGNORECASE)


def _prefixed_token(value: str) -> bool:
    """`prefix_tail` or `prefix-tail` where the tail is random: letters and digits in quantity, almost no
    separators (snake_case names and UUIDs are full of them), and a prefix that does not name a digest."""
    match = re.match(r"([A-Za-z][A-Za-z0-9]{1,9}(?:_[A-Za-z0-9]{1,8})?)[_-](.+)$", value)
    if not match or _NOT_A_TOKEN_PREFIX.match(match.group(1).split("_")[0]):
        return False
    tail = match.group(2)
    separators = sum(c in "_-" for c in tail)
    digits = sum(c.isdigit() for c in tail)
    mixed_case = any(c.isupper() for c in tail) and any(c.islower() for c in tail)
    # Public object ids share the shape (req_..., run_..., toolu_..., chunk-vendors-<hash>): they are shorter,
    # or hex, or in one case. A credential an agent could not pass on would be a smaller loss than an id it
    # cannot pass on.
    return len(tail) >= 32 and mixed_case and separators * 12 <= len(tail) and digits >= 3 and shannon_entropy(tail) > 3.3


_WEAK_KEY = r"(?!(?i:page|next|prev|continuation|cursor|sort|cache|partition|primary|foreign|public|idempotency|csrf|xsrf)[_-]?)"


def _secret_value(value: str) -> bool:
    """A value that could be a credential: not a placeholder, letters and digits, some randomness
    ("token=page2cursor" has none)."""
    has_both = any(c.isalpha() for c in value) and any(c.isdigit() for c in value)
    return _real_value(value) and has_both and shannon_entropy(value) > 3.0


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
    # The user may be empty (redis://:password@host).
    _ms("url_credentials", r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]*:([^\s:/@]{3,})@", 0.95, validate=_real_value),
    # Inside a connection string or a query: ...;Password=...; ...;AccountKey=...; ?user=x&password=... The
    # value only, the rest of the string stays readable.
    # The key is any name that ends in a credential word (client_secret, refresh_token, X-Amz-Signature,
    # AccountKey); SharedAccessKeyName and token_type end in something else, page_token and sort_key are not
    # credentials. A password is what a person chose; any other credential is long and has some randomness.
    _ms(
        "connection_string_password",
        r"(?<=[;?&])\s*[\w-]*(?i:password|passwd|pwd)\s*=\s*([^;&\s\"'<>]{6,})",
        0.9,
        validate=_real_value,
    ),
    _ms(
        "connection_string_secret",
        r"(?<=[;?&])\s*" + _WEAK_KEY + r"[\w-]*(?i:secret|token|signature|sig|key|credential)\s*=\s*([^;&\s\"'<>]{12,})",
        0.9,
        validate=_secret_value,
    ),
    # Authorization: Bearer <token>. Whatever follows the word is the credential, a webhook URL included.
    _ms("bearer_token", r"(?i:\bBearer)[ \t]+([A-Za-z0-9._~+/=:\-]{20,})", 0.9, validate=_real_value),
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
    # A provider prefix and a long random tail: hf_..., dop_v1_..., pypi-..., whsec_... New providers appear
    # faster than rules for them; the shape is what they share.
    Rule(
        "prefixed_token",
        Kind.SECRET,
        r"(?<![\w./-])[A-Za-z][A-Za-z0-9]{1,9}(?:_[A-Za-z0-9]{1,8})?[_-][A-Za-z0-9_\-]{24,}(?![\w-])",
        0.7,
        _M,
        code_safe=True,
        validate=lambda v: _prefixed_token(v),
    ),
    # Provider formats whose tail is hex, which the shape rule above leaves to digests.
    _ms("digitalocean_token", r"\bdo[opr]_v1_[a-f0-9]{64}\b"),
    _ms("shopify_token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    _ms("databricks_token", r"\bdapi[a-f0-9]{32}(?:-\d)?\b"),
    # Anything quoted, long and random: hashes in hex stay (entropy <= 4.0).
    _ms("high_entropy_string", r"""["']([A-Za-z0-9+/=_\-]{24,})["']""", 0.6, validate=_random_looking),
    # ---- prose only (tickets, chats, emails): passwords people type into a sentence
    # "Passwort Blau1827&nOn", "pw war …", "my password is …": the first token after the word that mixes
    # upper case, lower case and digits.
    Rule(
        "password_prose",
        Kind.SECRET,
        r"(?i:passwor[dt]|kennwort|passwd|\bpwd?\b|passcode)[^\n]{0,60}?(?<![\w@])"
        r"((?=[^\s,;()'\"<>]*[A-Z])(?=[^\s,;()'\"<>]*[a-z])(?=[^\s,;()'\"<>]*\d)[^\s,;()'\"<>]{8,64})",
        0.85,
        _M,
        refine=lambda v: len(v.rstrip(".,")) if "@" not in v and "://" not in v else None,
    ),
    # A token shaped like a password on its own: upper, lower, digit and a symbol, no dots, slashes or @.
    Rule(
        "password_shape",
        Kind.SECRET,
        r"(?<![\w@./:\\?=&#%-])(?=[A-Za-z0-9!#$%&*?+~^_-]*[A-Z])(?=[A-Za-z0-9!#$%&*?+~^_-]*[a-z])"
        r"(?=[A-Za-z0-9!#$%&*?+~^_-]*\d)(?=[A-Za-z0-9!#$%&*?+~^_-]*[!#$%&*?+~^])"
        r"[A-Za-z0-9!#$%&*?+~^_-]{8,40}(?![\w!#$%&*?+~^@./:=-])",
        0.70,
        _M,
    ),
]
