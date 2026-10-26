"""Shared types: what a detector finds and what an erase call returns."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class Kind(str, Enum):
    """What a span is. The value is the placeholder prefix: [NAME_1], [SECRET_2]."""

    NAME = "NAME"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ADDRESS = "ADDRESS"
    SSN = "SSN"
    DOB = "DOB"
    FINANCIAL = "FINANCIAL"
    MRN = "MRN"  # medical record number
    HEALTH_PLAN_ID = "HEALTH_PLAN_ID"
    NATIONAL_ID = "NATIONAL_ID"
    SECRET = "SECRET"  # keys, tokens, passwords, private keys


@dataclass(frozen=True)
class Span:
    """A piece of text a detector believes is sensitive."""

    start: int
    end: int
    text: str
    kind: Kind
    confidence: float
    source: str  # detector and rule, e.g. "regex:email_standard", "gliner:person"


@dataclass
class EraseResult:
    """Result of one erase call.

    `found` are the spans that were replaced. `signals` are spans a signal-only
    detector reported (e.g. NER on source code) that were left in place.
    `mapping` is the session's full placeholder table at the end of the call.
    """

    text: str
    found: List[Span] = field(default_factory=list)
    signals: List[Span] = field(default_factory=list)
    mapping: Dict[str, str] = field(default_factory=dict)
