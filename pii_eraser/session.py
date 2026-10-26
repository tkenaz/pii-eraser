"""Placeholder bookkeeping that outlives one text.

A session keeps one table for many calls: the diff, then every file an agent
reads, then the next file. "Jane Doe" is [NAME_1] in all of them, and once a
value is known it is replaced in later texts even where no detector fires.
"""

import re
from typing import Dict, List, Tuple

from pii_eraser.types import Kind, Span

# Kinds matched with letter boundaries so a short value doesn't fire inside a
# longer word ("Ana" in "Banana").
_WORDISH = {Kind.NAME, Kind.ADDRESS}


def canonical(text: str, kind: Kind) -> Tuple[Kind, str]:
    """Identity key, so trivially equivalent surface forms share one placeholder.
    Different placeholders for 'State of South Carolina' and 'South Carolina'
    made a model invent an inconsistency between identical jurisdictions."""
    t = " ".join(text.split())
    if t.lower().startswith("state of ") and kind in (Kind.ADDRESS, Kind.NAME):
        return Kind.ADDRESS, t[len("state of ") :].lower()
    return kind, t.lower()


class Session:
    def __init__(self):
        self._counters: Dict[Kind, int] = {}
        self._by_canon: Dict[Tuple[Kind, str], str] = {}
        self._by_surface: Dict[str, Tuple[str, Kind]] = {}  # surface form -> (placeholder, kind)
        self.mapping: Dict[str, str] = {}  # placeholder -> original

    def apply(self, text: str, spans: List[Span]) -> str:
        for span in sorted(spans, key=lambda s: s.start):
            self._register(span.text, span.kind)
        self._propagate_surnames()
        return self._replace_all(text)

    def restore(self, text: str) -> str:
        """Put originals back, e.g. into a model's answer shown to the owner."""
        if not self.mapping:
            return text
        pattern = re.compile("|".join(re.escape(p) for p in sorted(self.mapping, key=len, reverse=True)))
        return pattern.sub(lambda m: self.mapping[m.group(0)], text)

    def _register(self, surface: str, kind: Kind) -> None:
        if surface in self._by_surface:
            return
        key = canonical(surface, kind)
        placeholder = self._by_canon.get(key)
        if placeholder is None:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            placeholder = f"[{kind.value}_{self._counters[kind]}]"
            self._by_canon[key] = placeholder
            self.mapping[placeholder] = surface
        elif len(surface) > len(self.mapping[placeholder]):
            self.mapping[placeholder] = surface
        self._by_surface[surface] = (placeholder, kind)

    def _propagate_surnames(self) -> None:
        """A caught full name also covers its bare surname, unless the surname is
        shared by several caught people."""
        owners: Dict[str, set] = {}
        for surface, (placeholder, kind) in self._by_surface.items():
            words = surface.split()
            if kind is Kind.NAME and len(words) >= 2:
                last = words[-1].strip(".,")
                if len(last) >= 3 and last[0].isupper():
                    owners.setdefault(last.lower(), set()).add(placeholder)

        for surname, phs in owners.items():
            if len(phs) != 1:
                continue  # shared surname: ambiguous, leave it
            owner = next(iter(phs))
            existing = next((v for k, v in self._by_surface.items() if k.lower() == surname), None)
            if existing is None:
                self._by_surface[surname.capitalize()] = (owner, Kind.NAME)
            elif existing[0] != owner and existing[1] is Kind.NAME:
                # The bare surname was caught as its own entity: fold it in.
                orphan = existing[0]
                for k, (ph, kind) in list(self._by_surface.items()):
                    if ph == orphan:
                        self._by_surface[k] = (owner, kind)
                self.mapping.pop(orphan, None)

    def _replace_all(self, text: str) -> str:
        # Longest first, so 'John C. Eastham' is consumed before 'Eastham'.
        for surface in sorted(self._by_surface, key=len, reverse=True):
            placeholder, kind = self._by_surface[surface]
            pattern = re.escape(surface)
            if kind in _WORDISH:
                pattern = r"(?<![A-Za-z])" + pattern + r"(?![A-Za-z])"
            # Keep the line count: a multi-line private key becomes one
            # placeholder plus its newlines, so line numbers after it still hold.
            text = re.sub(
                pattern,
                lambda m, ph=placeholder: ph + "\n" * m.group(0).count("\n"),
                text,
                flags=re.IGNORECASE,
            )
        return text
