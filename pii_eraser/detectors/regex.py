"""Pattern-based detection: one engine, two rule tables (personal data, secrets).

A rule captures group 1 when it has one (the value after a label), otherwise
the whole match. Validators reject format matches that are not real values.
"""

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from pii_eraser.types import Kind, Span


@dataclass(frozen=True)
class Rule:
    name: str
    kind: Kind
    pattern: str
    confidence: float
    flags: int = re.MULTILINE
    # False: the rule fires on ordinary code (dates in changelogs, numbers that
    # look like phones, constants that look like IBANs) and is left out of the
    # code profile.
    code_safe: bool = False
    validate: Optional[Callable[[str], bool]] = None


class RegexDetector:
    def __init__(self, rules: Sequence[Rule], name: str = "regex"):
        self.name = name
        self._compiled = [(rule, re.compile(rule.pattern, rule.flags)) for rule in rules]

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for rule, regex in self._compiled:
            for match in regex.finditer(text):
                group = 1 if match.lastindex and match.group(1) else 0
                value = match.group(group)
                if rule.validate and not rule.validate(value):
                    continue
                spans.append(
                    Span(
                        start=match.start(group),
                        end=match.end(group),
                        text=value,
                        kind=rule.kind,
                        confidence=rule.confidence,
                        source=f"{self.name}:{rule.name}",
                    )
                )
        return spans
