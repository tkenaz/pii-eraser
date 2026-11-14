"""A person's name found once in a text is masked wherever it stands again in that text.

Detectors decide per mention: a model scores "Tamsin Okonkwo" in a greeting and passes over "Tamsin" alone in
the minutes below it, a rule sees the name after "Frau" and not in the table. The reader has no such trouble,
so one confident mention is enough to give the others away.
"""

import re
import unicodedata
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from pii_eraser.types import Kind, Span

# A mention has to be this certain before its words are looked for elsewhere: a model's weak guess on a trade
# noun ("Maler") must not mask that noun through the whole text.
SEED_CONFIDENCE = 0.5
REPEAT_CONFIDENCE = 0.7
_MIN_LETTERS = 3

_WORD = re.compile(r"[^\W\d_]+(?:[-'’][^\W\d_]+)*")
# Words that stand inside a name span and are not the name.
_TITLES = frozenset(
    """
    herr herrn frau fräulein familie fam dr prof dipl ing med mag jur rer nat phil
    mr mrs ms miss mx sir madam dame lord lady und and the
    """.split()
)
_PARTICLES = frozenset(
    "van von vom zu zur zum de der den des du da di del della dos das ter ten al el bin ibn le la los las".split()
)
_INITIALS_BEFORE = re.compile(r"(?:[^\W\d_]\. ?){1,2}$")


def fold(word: str) -> str:
    """Lower case without accents: Zdeněk, ZDENEK and Zdenek are one name."""
    decomposed = unicodedata.normalize("NFKD", word.casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


# Sources whose context proves a person: the model's person label, a title before the name ("Frau", "Mr"),
# a greeting, "Surname, Given" in a list. A name rule that reads a field or a signature block also fires on
# "Kontakt: Stadtwerke München" and "By: Deutsche Bank AG"; what it finds is masked there and not looked for
# elsewhere.
_PERSON_SOURCES = frozenset(
    {"gliner:person", "pii:name_titled", "pii:name_greeting", "pii:name_list_inverted", "pii:name_list_inverted_first"}
)
# A surname that is also a noun, a month or a verb ("Winter", "April", "Will") is the word again after an
# article or a preposition, and the month again on its own.
_BEFORE_A_NOUN = re.compile(
    r"\b(?:der|die|das|den|dem|des|ein|eine|einen|einem|einer|im|am|zum|zur|vom|beim|ins|the|a)[ ]$",
    re.IGNORECASE,
)
_CALENDAR = frozenset(
    """
    januar februar märz marz april mai juni juli august september oktober november dezember
    january february march may june july october december
    montag dienstag mittwoch donnerstag freitag samstag sonntag
    monday tuesday wednesday thursday friday saturday sunday
    """.split()
)


def _is_person(span: Span) -> bool:
    """A NAME span that is a person as far as its source tells: the model's organisation and location labels
    share the NAME placeholder, and so do rules that read fields."""
    return span.kind is Kind.NAME and (not span.source.startswith("gliner:") or span.source == "gliner:person")


def _proves_a_person(span: Span) -> bool:
    return span.kind is Kind.NAME and (span.source in _PERSON_SOURCES or span.source.startswith("test:"))


@dataclass
class _Known:
    """What the confident mentions of a text say about its names."""

    words: Set[str] = field(default_factory=set)  # folded name words of three letters and more
    short: Set[str] = field(default_factory=set)  # "Le", "Vũ": too short to stand alone
    particles: Dict[str, Set[str]] = field(default_factory=dict)  # "heyden" -> {"van der"}
    people: List[Set[str]] = field(default_factory=list)  # the words of each mention with several words

    def same_person(self, left: Set[str], right: Set[str]) -> bool:
        return any(left <= person and right <= person for person in self.people)


def _learn(spans: List[Span]) -> _Known:
    known = _Known()
    for span in spans:
        if not _proves_a_person(span) or span.confidence < SEED_CONFIDENCE:
            continue
        person: Set[str] = set()
        before: List[str] = []
        for match in _WORD.finditer(span.text):
            word, folded = match.group(0), fold(match.group(0))
            if folded in _TITLES:
                before = []
            elif folded in _PARTICLES:
                before.append(folded)
            elif word[0].isupper():
                letters = sum(c.isalpha() for c in word)
                (known.words if letters >= _MIN_LETTERS else known.short).add(folded)
                person.add(folded)
                if before:
                    known.particles.setdefault(folded, set()).add(" ".join(before))
                before = []
        if len(person) > 1:
            known.people.append(person)
    return known


def _stem(word: str, known: Set[str]) -> str:
    """The known name `word` is a form of ("Ludger's", "Pfannenstiels"), or ""."""
    if not word[0].isupper():
        return ""
    folded = fold(word)
    if folded in known:
        return folded
    for ending in ("'s", "’s", "s"):
        if folded.endswith(ending) and folded[: -len(ending)] in known:
            return folded[: -len(ending)]
    return ""


def repeat_names(text: str, spans: List[Span]) -> List[Span]:
    """Spans for the further mentions of people `spans` already hold; `spans` themselves are not returned."""
    known = _learn(spans)
    if not known.words:
        return []
    taken = sorted((s.start, s.end) for s in spans)  # the spans of one text do not overlap
    starts = [a for a, _ in taken]

    def free(start: int, end: int) -> bool:
        i = bisect_right(starts, start)
        return (i == 0 or taken[i - 1][1] <= start) and (i == len(taken) or end <= taken[i][0])

    # runs of name words that stand next to each other: [start, end, folded words, has a word that can stand alone]
    runs: List[Tuple[int, int, Set[str], bool]] = []
    for match in _WORD.finditer(text):
        stem = _stem(match.group(0), known.words)
        short = "" if stem else _stem(match.group(0), known.short)
        if not (stem or short) or not free(match.start(), match.end()):
            continue
        start, end = match.span()
        if runs:
            last_start, last_end, last_words, last_full = runs[-1]
            gap = text[last_end:start]
            if gap in (" ", ", ", ",") and known.same_person(last_words, {stem or short}):
                runs[-1] = (last_start, end, last_words | {stem or short}, last_full or bool(stem))
                continue
        runs.append((start, end, {stem or short}, bool(stem)))

    found: List[Span] = []
    for start, end, words, full in runs:
        if not full:
            continue  # "Le" on its own is an article, not a surname
        first = _stem(_WORD.match(text, start).group(0), known.words | known.short)
        head = text[max(0, start - 16) : start].casefold()
        with_particles = False
        for particles in sorted(known.particles.get(first, ()), key=len, reverse=True):
            if head.endswith(particles + " ") and free(start - len(particles) - 1, start):
                start -= len(particles) + 1
                with_particles = True
                break
        if len(words) == 1 and not with_particles:
            word = next(iter(words))
            if word in _CALENDAR or _BEFORE_A_NOUN.search(text, max(0, start - 8), start):
                continue
        initials = _INITIALS_BEFORE.search(text, max(0, start - 6), start)
        if initials and text[initials.start()].isupper() and free(initials.start(), start):
            if initials.start() == 0 or not text[initials.start() - 1].isalnum():
                start = initials.start()
        found.append(
            Span(start=start, end=end, text=text[start:end], kind=Kind.NAME, confidence=REPEAT_CONFIDENCE, source="repeat:name")
        )
    return found


def join_name_parts(text: str, spans: List[Span]) -> List[Span]:
    """Two name spans of one person with only a blank or ", " between them become one span: "Wöhrmann" and
    "Ilse" found by different detectors in "Wöhrmann, Ilse" are one name, and the comma belongs to it. They
    are joined only when a mention elsewhere in the text shows the words to be one person: two surnames side
    by side in a table stay two people, each with the placeholder it has everywhere else."""
    known = _learn(spans)
    joined: List[Span] = []
    for span in sorted(spans, key=lambda s: s.start):
        last = joined[-1] if joined else None
        if last is not None and _is_person(last) and _is_person(span) and last.end <= span.start:
            gap = text[last.end : span.start]
            words = [{fold(m.group(0)) for m in _WORD.finditer(s.text)} - _TITLES - _PARTICLES for s in (last, span)]
            if gap in (" ", ", ", ",") and all(words) and known.same_person(words[0], words[1]):
                best = last if last.confidence >= span.confidence else span
                joined[-1] = Span(
                    start=last.start,
                    end=span.end,
                    text=text[last.start : span.end],
                    kind=Kind.NAME,
                    confidence=best.confidence,
                    source=best.source,
                )
                continue
        joined.append(span)
    return joined
