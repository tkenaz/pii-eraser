"""Detectors in, one non-overlapping set of spans out, replaced through a session."""

from dataclasses import dataclass
from typing import List, Optional, Sequence

from pii_eraser.detectors.base import Detector
from pii_eraser.detectors.pii_rules import PII_RULES
from pii_eraser.detectors.regex import RegexDetector
from pii_eraser.detectors.secret_rules import SECRET_RULES
from pii_eraser.repeats import join_name_parts, repeat_names
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
    def __init__(self, stages: Sequence[Stage], whole_text: bool = False):
        self.stages = list(stages)
        # True: after the detectors, read the text as a whole. A name found once is masked wherever it stands
        # again (repeats.py); name and address pieces found separately become one span.
        # Off for source code, where the same word is a class or a variable.
        self.whole_text = whole_text

    @classmethod
    def for_prose(cls, ner: Optional[Detector] = None) -> "Eraser":
        """Documents, emails, MR descriptions: every rule, NER replaces."""
        stages = [Stage(RegexDetector(SECRET_RULES, "secret")), Stage(RegexDetector(PII_RULES, "pii"))]
        if ner is not None:
            # A detector with its own per-label thresholds says how low its own bar goes.
            stages.append(Stage(ner, min_confidence=getattr(ner, "min_confidence", 0.5)))
        return cls(stages, whole_text=True)

    @classmethod
    def for_code(cls, ner: Optional[Detector] = None) -> "Eraser":
        """Source code and diffs: secrets plus the code-safe personal-data rules;
        NER, if given, only reports."""
        code_rules = [rule for rule in PII_RULES if rule.code_safe]
        secret_rules = [rule for rule in SECRET_RULES if rule.code_safe]  # prose password rules stay out
        stages = [Stage(RegexDetector(secret_rules, "secret")), Stage(RegexDetector(code_rules, "pii"))]
        if ner is not None:
            stages.append(Stage(ner, min_confidence=getattr(ner, "min_confidence", 0.5), replace=False))
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
        found = resolve_overlaps(to_replace)
        if self.whole_text:
            found = join_name_parts(text, found + repeat_names(text, found))
        return found, signals


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


# Kinds whose values have a fixed format a rule can delimit exactly. Names and addresses are not among them:
# their rules are context patterns with loose edges, and widening those only masks more of the sentence.
_FORMAT_KINDS = frozenset(
    {Kind.PHONE, Kind.FINANCIAL, Kind.NATIONAL_ID, Kind.SSN, Kind.IP, Kind.EMAIL, Kind.DOB, Kind.SECRET}
)


def _is_rule(span: Span) -> bool:
    return not span.source.startswith("gliner:") and span.kind in _FORMAT_KINDS


def merge_same_kind(spans: List[Span]) -> List[Span]:
    """Rule spans of the same kind that overlap become one span over their union, and an NER span that overlaps
    a rule span of the same kind gives way to it. Rules know where a phone number or an IBAN ends; two rules
    that agree on what a value is but not on its edges ("(0117) 496 0148" and "117) 496 0148") should mask
    all of it, and a model's fuzzy edges ("020 7946" of "020 7946 0040") should not cut a rule's match short."""
    rules = sorted((s for s in spans if _is_rule(s)), key=lambda s: (s.kind.value, s.start, -s.end))
    merged: List[Span] = []
    for span in rules:
        last = merged[-1] if merged else None
        if last is not None and last.kind is span.kind and span.start < last.end:
            if span.end > last.end:
                best = last if last.confidence >= span.confidence else span
                merged[-1] = Span(
                    start=last.start,
                    end=span.end,
                    text=last.text + span.text[last.end - span.start :],
                    kind=last.kind,
                    confidence=max(last.confidence, span.confidence),
                    source=best.source,
                )
            continue
        merged.append(span)
    rest = [
        s
        for s in spans
        if not _is_rule(s) and not any(r.kind is s.kind and r.start < s.end and s.start < r.end for r in merged)
    ]
    return merged + rest


def resolve_overlaps(spans: List[Span]) -> List[Span]:
    """Merge same-kind rule overlaps (see merge_same_kind), then keep the most
    confident span where spans overlap; on a tie a secret, then the longer span. In
    postgres://app:pass@db.internal the email rule sees 'pass@db.internal' at the
    same confidence; the password must win."""
    spans = merge_same_kind(spans)
    kept: List[Span] = []
    for span in sorted(spans, key=lambda s: (-s.confidence, s.kind is not Kind.SECRET, -(s.end - s.start), s.start)):
        if all(span.end <= k.start or k.end <= span.start for k in kept):
            kept.append(span)
    return sorted(kept, key=lambda s: s.start)
