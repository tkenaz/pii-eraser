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


def compact(text: str) -> str:
    """The value without what is printed between its groups, in upper case."""
    return "".join(c for c in text if c.isalnum()).upper()


def single_separator(text: str) -> bool:
    """True when the groups of a printed value are divided the same way throughout: by white space, or by one
    punctuation mark, or not at all. "12 34-56.78" is three numbers that happen to stand together."""
    kinds = set()
    for run in re.findall(r"[^A-Za-z0-9]+", text):
        kinds.add(" " if run.isspace() else run)
    return len(kinds) <= 1


# Issuer ranges (ISO/IEC 7812) and the lengths each scheme issues. Maestro and its 12-15 digit cards are
# left at 16-19: a 12-digit run starting with 5 or 6 is far more often an order number than a card.
_CARD_RANGES = (
    (("34", "37"), (15,)),  # American Express
    (("4",), (13, 16, 19)),  # Visa
    (("51", "52", "53", "54", "55"), (16,)),  # Mastercard
    (("300", "301", "302", "303", "304", "305", "3095", "36", "38", "39"), (14, 15, 16, 17, 18, 19)),  # Diners
    (("35",), (16, 17, 18, 19)),  # JCB 3528-3589, checked below
    (("50", "56", "57", "58", "59", "6"), (16, 17, 18, 19)),  # Maestro, Discover, UnionPay
)


def card_lengths(digits: str) -> tuple:
    """The lengths a card starting like `digits` can have, or () when no scheme issues that start."""
    if digits[:4].isdigit() and 2221 <= int(digits[:4]) <= 2720:
        return (16,)  # Mastercard 2-series
    if digits.startswith("35") and not (digits[:4].isdigit() and 3528 <= int(digits[:4]) <= 3589):
        return ()
    for prefixes, lengths in _CARD_RANGES:
        if digits.startswith(prefixes):
            return lengths
    return ()


def _card_layout_ok(printed: str) -> bool:
    """Cards are printed without separators or the way they are embossed: groups of four with a shorter last
    group, or 4-6-5 and 4-6-4. A row of single digits or of three-digit numbers that happens to satisfy Luhn
    is a row of numbers."""
    sizes = [len(group) for group in re.split(r"[^0-9]+", printed)]
    if len(sizes) == 1 or sizes in ([4, 6, 5], [4, 6, 4]):
        return True
    return len(sizes) >= 4 and all(n == 4 for n in sizes[:-1]) and 1 <= sizes[-1] <= 4


def card_span(candidate: str) -> Optional[int]:
    """Length of the payment card number at the start of `candidate`, or None.

    `candidate` is a run of digits with at most one separator between two digits, so it can run on into a
    following number: the lengths of the scheme decide where the card can end, the cut must fall where the
    text has a break, the groups must be divided the same way throughout, and the Luhn digit must hold."""
    positions = [i for i, c in enumerate(candidate) if c.isdigit()]
    digits = "".join(candidate[i] for i in positions)
    for length in sorted(card_lengths(digits), reverse=True):
        if len(digits) < length:
            continue
        end = positions[length - 1] + 1
        if end < len(candidate) and candidate[end].isdigit():
            continue
        printed = candidate[:end]
        if single_separator(printed) and _card_layout_ok(printed) and luhn_ok(digits[:length]):
            return end
    return None


def iban_ok(text: str) -> bool:
    """ISO 13616 mod-97. Hex constants and enum names that look like IBANs fail it."""
    s = compact(text)
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

    `candidate` is a run of letters and digits with at most one separator (blank, hyphen, dot, line break)
    between two of them, so it can run on into a following word or number: the country's registry length
    decides where the IBAN ends, and the cut must fall where the text has a break. OCR-confused characters (O/0, I/l/1, S/5, B/8) are read back
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
    if end < len(candidate) and candidate[end].isalnum():
        return None  # the registry length cuts through a token: not an IBAN of this country
    if not single_separator(candidate[:end]) or _goes_on(candidate, end):
        return None
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


def _goes_on(candidate: str, end: int) -> bool:
    """The value is cut where the same hyphen or dot that divides its groups is followed by more: the middle
    of a UUID or of a dotted key, not the end of an account number."""
    return (
        end + 1 < len(candidate)
        and candidate[end] in "-."
        and candidate[end] in candidate[:end]
        and candidate[end + 1].isalnum()
    )


def _iban_shape_end(candidate: str) -> Optional[int]:
    """Where a value of the country's registry length ends in `candidate`, check digits unverified. Without
    the check digits to prove it, the country code has to be printed in letters: no OCR reading of "51" as SI."""
    positions = [i for i, c in enumerate(candidate) if c.isalnum()]
    raw = "".join(candidate[i] for i in positions).upper()
    length = IBAN_LENGTH.get(raw[:2]) if raw[:2].isalpha() else None
    if length is None or len(raw) < length:
        return None
    end = positions[length - 1] + 1
    if (end < len(candidate) and candidate[end].isalnum()) or _goes_on(candidate, end):
        return None
    value = raw[:length]
    if sum(c.isdigit() for c in value[2:]) * 10 < (length - 2) * 6:
        return None  # mostly letters: a word run, not an account number
    return end if single_separator(candidate[:end]) else None


def iban_printed_span(candidate: str) -> Optional[int]:
    """An IBAN whose check digits do not hold (a typing or OCR error) but which is printed as one: country
    code, registry length, groups of four divided the same way throughout."""
    end = _iban_shape_end(candidate)
    if end is None:
        return None
    groups = re.split(r"[^A-Za-z0-9]+", candidate[:end])
    in_fours = len(groups) > 1 and all(len(g) == 4 for g in groups[:-1]) and 1 <= len(groups[-1]) <= 4
    return end if in_fours else None


def iban_labeled_span(candidate: str) -> Optional[int]:
    """What stands after the word IBAN and has the country's registry length, whatever its check digits."""
    return _iban_shape_end(candidate)


def printed_as_one(validator):
    """Validator: `validator` holds for the value and its groups are divided the same way throughout."""

    def ok(text: str) -> bool:
        return single_separator(text) and validator(text)

    return ok


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
    s = compact(text)
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
    s = compact(text)
    if not re.fullmatch(r"[A-Z]{2}\d{6}[A-D]", s):
        return False
    first, second = s[0], s[1]
    if first in "DFIQUV" or second in "DFIOQUV":
        return False
    return s[:2] not in {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}


# The postcode areas of the United Kingdom and the Crown dependencies.
_UK_POSTCODE_AREAS = frozenset(
    """
    AB AL B BA BB BD BH BL BN BR BS BT CA CB CF CH CM CO CR CT CV CW DA DD DE DG DH DL DN DT DY E EC EH EN EX
    FK FY G GL GU GY HA HD HG HP HR HS HU HX IG IM IP IV JE KA KT KW KY L LA LD LE LL LN LS LU M ME MK ML N NE
    NG NN NP NR NW OL OX PA PE PH PL PO PR RG RH RM S SA SE SG SK SL SM SN SO SP SR SS ST SY TA TD TF TN TQ TR
    TS TW UB W WA WC WD WF WN WR WS WV YO ZE
    """.split()
)


def uk_postcode_area_ok(text: str) -> bool:
    """The letters a UK postcode starts with name a postcode area that exists."""
    match = re.match(r"[A-Za-z]{1,2}", text)
    return bool(match) and match.group(0).upper() in _UK_POSTCODE_AREAS


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
