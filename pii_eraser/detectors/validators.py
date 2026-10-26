"""Checksums and statistics that turn a format match into a real value."""

import math
import re
from collections import Counter


def luhn_ok(text: str) -> bool:
    """Payment card check digit. A 16-digit build number fails it 9 times in 10."""
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(text: str) -> bool:
    """ISO 13616 mod-97. Hex constants and enum names that look like IBANs fail it."""
    s = re.sub(r"\s", "", text).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97 == 1


def shannon_entropy(text: str) -> float:
    """Bits per character. Short random tokens score 4.5+; hex can't exceed 4.0."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())
