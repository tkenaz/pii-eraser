"""A postal address found in pieces is one address.

Rules find the street with its number and the postcode with its town; what is printed between and around
them differs from letterhead to letterhead: "Eschenweg 19 Hs. 2 – 78462 Konstanz", "Lindengasse 27/2/9 in
2340 Mödling", a town on its own line between the street and the postcode. Listing those layouts does not end.
Two address pieces with nothing but such filling between them are joined, and the filling is masked with them.
"""

import re
from typing import List

from pii_eraser.detectors.pii_rules import _NOT_TOWN
from pii_eraser.types import Kind, Span

# Between two pieces of one address: separators, a second house number, staircase or door, the supplement
# words printed with it, "in" before the town, the country letter before the postcode, one line break.
_FILLING_PART = r"""(?:
        [ \t,|/–-]
      | \n
      | \d{1,4}[a-zA-Z]?\b
      | \b[a-zA-Z]\b
      | \b(?:Hs|Haus|HH|VH|Stg|Stiege|Top|Tür|Whg|OG|EG|Flat|Unit|Apt)\b\.?
      | \b(?:in|D|A|CH)\b
    )"""
_FILLING = re.compile(_FILLING_PART + "*", re.VERBOSE)
_FILLING_MAX = 16
# After a street: the filling, then postcode and town. A rule takes "54321 Beispielstadt" for an address only
# where it stands like one; right after a street it is one wherever it stands.
_TOWN_AFTER = re.compile(
    _FILLING_PART
    + r"{0,10}?(?:(?:D|A|CH)-)?(?<![\d/])\d{4,5}[ ]"
    + _NOT_TOWN
    + r"[A-ZÄÖÜ][\w.-]*(?:[ -][A-ZÄÖÜ][\w.-]*){0,2}",
    re.VERBOSE,
)
_STREET_END = re.compile(r"\d[a-zA-Z]?$")
# A line or a comma-separated part made of capitalised words only, between two address pieces: the town
# between street and postcode, the street between house name and town.
_NAMED_PART = re.compile(r"[ \t]*[,\n]?[ \t]*(?:[A-ZÀ-Þ][\w'’.-]*[ \t]*){1,4}[,\n]?[ \t]*")
_NAMED_PART_MAX = 40

_COUNTRY = (
    r"(?:Deutschland|Germany|Österreich|Austria|Schweiz|Switzerland|Suisse|Svizzera"
    r"|United[ ]Kingdom|UK|England|Scotland|Wales|Northern[ ]Ireland)"
)
# What a town name can go on with after the rule's match ended: "St" + ". Gallen", "Homburg" + " v. d. Höhe",
# then the country.
_TAILS = (
    (re.compile(r"\bSt$"), re.compile(r"\.[ ]?[A-ZÄÖÜ][\w-]+")),
    (re.compile(r"\d{4,5}[ ][^\n\d]*[^\W\d_]$"), re.compile(r"[ ](?:v|a|i|b)\.[ ]?(?:d\.[ ]?)?[A-ZÄÖÜ][\w.-]*")),
    (re.compile(r"[^\W_]$"), re.compile(rf",?[ ]{_COUNTRY}\b")),
)


def _is_filling(gap: str) -> bool:
    if gap.count("\n") > 2:
        return False
    if len(gap) <= _FILLING_MAX and gap.count("\n") <= 1 and _FILLING.fullmatch(gap):
        return True
    return len(gap) <= _NAMED_PART_MAX and bool(_NAMED_PART.fullmatch(gap))


def _with_tail(text: str, span: Span, limit: int) -> Span:
    end = span.end
    for ends_with, tail in _TAILS:
        if ends_with.search(text, max(0, span.start), end):
            match = tail.match(text, end)
            if match and match.end() <= limit:
                end = match.end()
    if end == span.end:
        return span
    return Span(start=span.start, end=end, text=text[span.start : end], kind=span.kind, confidence=span.confidence, source=span.source)


def _with_town(text: str, span: Span, limit: int) -> Span:
    """A span that ends in a house number takes the postcode and town that follow it on the line."""
    if not _STREET_END.search(span.text) or re.search(r"\d{4,5}[ ][^\W\d_]", span.text):
        return span
    match = _TOWN_AFTER.match(text, span.end)
    if not match or match.end() > limit or match.end() - span.end > _FILLING_MAX + 40:
        return span
    if text.count("\n", span.end, match.end()) > 1:
        return span
    end = match.end()
    return Span(start=span.start, end=end, text=text[span.start : end], kind=span.kind, confidence=span.confidence, source=span.source)


def join_address_parts(text: str, spans: List[Span]) -> List[Span]:
    """Join address spans divided only by address filling, then let each address run on over the rest of its
    town name and its country. Spans of other kinds are returned as they are and are never run over."""
    ordered = sorted(spans, key=lambda s: s.start)
    for i, span in enumerate(ordered):
        if span.kind is Kind.ADDRESS:
            limit = ordered[i + 1].start if i + 1 < len(ordered) else len(text)
            ordered[i] = _with_town(text, span, limit)
    joined: List[Span] = []
    for span in ordered:
        last = joined[-1] if joined else None
        if (
            last is not None
            and last.kind is Kind.ADDRESS
            and span.kind is Kind.ADDRESS
            and last.end <= span.start
            and _is_filling(text[last.end : span.start])
        ):
            best = last if last.confidence >= span.confidence else span
            joined[-1] = Span(
                start=last.start,
                end=span.end,
                text=text[last.start : span.end],
                kind=Kind.ADDRESS,
                confidence=best.confidence,
                source=best.source,
            )
            continue
        joined.append(span)
    result: List[Span] = []
    for i, span in enumerate(joined):
        if span.kind is Kind.ADDRESS:
            limit = joined[i + 1].start if i + 1 < len(joined) else len(text)
            span = _with_tail(text, span, limit)
        result.append(span)
    return result
