"""Detectors in, one non-overlapping set of spans out, replaced through a session."""

from dataclasses import dataclass
from typing import List, Optional, Sequence

from pii_eraser.detectors.base import Detector
from pii_eraser.detectors.pii_rules import PII_RULES
from pii_eraser.detectors.regex import RegexDetector
from pii_eraser.detectors.secret_rules import SECRET_RULES
from pii_eraser.session import Session
from pii_eraser.types import EraseResult, Kind, Span


@dataclass(frozen=True)
class Stage:
    detector: Detector
    min_confidence: float = 0.5
    # False: report what the detector found, replace nothing. NER on source
    # code tags variable names as people; there it is a signal, not a verdict.
    replace: bool = True


class Eraser:
    def __init__(self, stages: Sequence[Stage]):
        self.stages = list(stages)

    @classmethod
    def for_prose(cls, ner: Optional[Detector] = None) -> "Eraser":
        """Documents, emails, MR descriptions: every rule, NER replaces."""
        stages = [Stage(RegexDetector(SECRET_RULES, "secret")), Stage(RegexDetector(PII_RULES, "pii"))]
        if ner is not None:
            stages.append(Stage(ner))
        return cls(stages)

    @classmethod
    def for_code(cls, ner: Optional[Detector] = None) -> "Eraser":
        """Source code and diffs: secrets plus the code-safe personal-data rules;
        NER, if given, only reports."""
        code_rules = [rule for rule in PII_RULES if rule.code_safe]
        stages = [Stage(RegexDetector(SECRET_RULES, "secret")), Stage(RegexDetector(code_rules, "pii"))]
        if ner is not None:
            stages.append(Stage(ner, replace=False))
        return cls(stages)

    def session(self) -> "ErasingSession":
        return ErasingSession(self)

    def erase(self, text: str) -> EraseResult:
        """One text, its own placeholder table."""
        return self.session().erase(text)

    def detect(self, text: str) -> tuple[List[Span], List[Span]]:
        """(spans to replace, signal-only spans)."""
        to_replace: List[Span] = []
        signals: List[Span] = []
        for stage in self.stages:
            for span in stage.detector.detect(text):
                if span.confidence >= stage.min_confidence:
                    (to_replace if stage.replace else signals).append(span)
        return resolve_overlaps(to_replace), signals


class ErasingSession:
    """An eraser bound to one placeholder table, for texts that belong together."""

    def __init__(self, eraser: Eraser):
        self._eraser = eraser
        self._session = Session()

    @property
    def mapping(self):
        return dict(self._session.mapping)

    def erase(self, text: str) -> EraseResult:
        found, signals = self._eraser.detect(text)
        clean = self._session.apply(text, found)
        return EraseResult(text=clean, found=found, signals=signals, mapping=self.mapping)

    def restore(self, text: str) -> str:
        return self._session.restore(text)


def resolve_overlaps(spans: List[Span]) -> List[Span]:
    """Keep the most confident span where spans overlap; on a tie a secret, then
    the longer span. In postgres://app:pass@db.internal the email rule sees
    'pass@db.internal' at the same confidence; the password must win."""
    kept: List[Span] = []
    for span in sorted(spans, key=lambda s: (-s.confidence, s.kind is not Kind.SECRET, -(s.end - s.start), s.start)):
        if all(span.end <= k.start or k.end <= span.start for k in kept):
            kept.append(span)
    return sorted(kept, key=lambda s: s.start)
