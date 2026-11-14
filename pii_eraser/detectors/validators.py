"""Checksums and statistics that turn a format match into a real value."""

import ipaddress
import math
import re
from collections import Counter
from typing import Optional


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
    return _mod97(s)


def _mod97(s: str) -> bool:
    rearranged = s[4:] + s[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97 == 1


# ISO 13616 registry: IBAN length per country.
IBAN_LENGTH = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
    "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
    "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22,
    "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25,
    "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23,
    "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}
# Where the national part (BBAN) has a fixed letter/digit shape, an OCR-confused character can be read back:
# "n" positions hold digits, "a" positions letters. CH and LI allow letters in the account part on paper,
# but the exact value is always tested first, so reading them as digits only adds a second chance.
_NUMERIC = {"AT", "BE", "CH", "CZ", "DE", "DK", "EE", "ES", "FI", "FO", "GL", "HR", "HU", "IL", "LI", "LT",
            "NO", "PL", "PT", "RS", "SE", "SI", "SK", "TN"}
_BBAN_SHAPE = {c: "n" * (IBAN_LENGTH[c] - 4) for c in _NUMERIC}
_BBAN_SHAPE.update({"GB": "a" * 4 + "n" * 14, "IE": "a" * 4 + "n" * 14, "NL": "a" * 4 + "n" * 10})
# OCR confusions: a letter read where a digit stood, and the reverse.
_OCR_TO_DIGIT = str.maketrans({"O": "0", "Q": "0", "D": "0", "I": "1", "L": "1", "S": "5", "B": "8", "Z": "2"})
_OCR_TO_LETTER = str.maketrans({"0": "O", "1": "I", "5": "S", "8": "B"})


def iban_span(candidate: str) -> Optional[int]:
    """Length of the IBAN at the start of `candidate`, or None.

    `candidate` is a run of 4-character groups that may be separated by blanks or one line break, so it can
    run on into a following number: the country's registry length decides where the IBAN ends, and the cut
    must fall where the text has a break. OCR-confused characters (O/0, I/l/1, S/5, B/8) are read back
    before the check digits are tested; a value is accepted only if mod-97 holds afterwards.
    """
    positions = [i for i, c in enumerate(candidate) if c.isalnum()]
    if len(positions) < 15:
        return None
    raw = "".join(candidate[i] for i in positions).upper()
    country = raw[:2].translate(_OCR_TO_LETTER)
    length = IBAN_LENGTH.get(country)
    if length is None or len(raw) < length:
        return None
    end = positions[length - 1] + 1
    if end < len(candidate) and not candidate[end].isspace():
        return None  # the registry length cuts through a token: not an IBAN of this country
    value = raw[:length]
    exact = country + value[2:]
    if exact[2:4].isdigit() and exact[4:].isalnum() and _mod97(exact):
        return end
    shape = _BBAN_SHAPE.get(country)
    check = value[2:4].translate(_OCR_TO_DIGIT)
    if shape is None or not check.isdigit():
        return None
    bban = "".join(
        c.translate(_OCR_TO_DIGIT) if kind == "n" else c.translate(_OCR_TO_LETTER) for c, kind in zip(value[4:], shape)
    )
    fits = all(c.isdigit() if kind == "n" else c.isalpha() for c, kind in zip(bban, shape))
    return end if fits and _mod97(country + check + bban) else None


def digits_between(low: int, high: int):
    """Validator: the match holds between `low` and `high` digits."""

    def ok(text: str) -> bool:
        return low <= sum(c.isdigit() for c in text) <= high

    return ok


def steuer_id_ok(text: str) -> bool:
    """German tax identification number (IdNr, § 139b AO): 11 digits, no leading zero, ISO 7064 MOD 11,10
    check digit, and in the first ten digits exactly one digit repeated (twice or three times)."""
    d = [int(c) for c in text if c.isdigit()]
    if len(d) != 11 or d[0] == 0:
        return False
    counts = Counter(d[:10])
    repeated = [n for n in counts.values() if n > 1]
    if len(repeated) != 1 or repeated[0] > 3:
        return False
    product = 10
    for digit in d[:10]:
        total = (digit + product) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    check = 11 - product
    if check == 10:
        check = 0
    return check == d[10]


_SV_WEIGHTS = (2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1)


def sv_nummer_ok(text: str) -> bool:
    """German pension insurance number (Rentenversicherungsnummer / SV-Nummer): area (2), birth date DDMMYY
    (6), initial of the birth name (letter), serial (2), check digit. The letter counts as its alphabet
    position in two digits; weights 2-1-2-5-7-1-2-1-2-1-2-1, cross sums of the products, total mod 10."""
    s = re.sub(r"\s", "", text).upper()
    m = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(\d{2})([A-Z])(\d{2})(\d)", s)
    if not m:
        return False
    area, day, month, _year, letter, serial, check = m.groups()
    if not (1 <= int(day) <= 31 and 1 <= int(month) <= 12):
        return False
    digits = area + day + month + _year + f"{ord(letter) - 64:02d}" + serial
    total = 0
    for digit, weight in zip(digits, _SV_WEIGHTS):
        product = int(digit) * weight
        total += product // 10 + product % 10
    return total % 10 == int(check)


def nino_ok(text: str) -> bool:
    """UK National Insurance number: prefix letters from the allowed set, suffix A-D."""
    s = re.sub(r"\s", "", text).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{6}[A-D]", s):
        return False
    first, second = s[0], s[1]
    if first in "DFIQUV" or second in "DFIOQUV":
        return False
    return s[:2] not in {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}


def ip_ok(text: str) -> bool:
    """A routable or private address, not loopback, unspecified or a netmask."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return False
    return not (ip.version == 4 and text.startswith("255."))


def shannon_entropy(text: str) -> float:
    """Bits per character. Short random tokens score 4.5+; hex can't exceed 4.0."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())
