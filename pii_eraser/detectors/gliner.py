"""NER detection with GLiNER (zero-shot labels, runs locally, ~400 MB model).

Ported from the contract-analyzer scrubber. Install with `pip install
pii-eraser[gliner]`; the model downloads on first use.
"""

import logging
from typing import Dict, List, Optional, Sequence

from pii_eraser.types import Kind, Span

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "urchade/gliner_medium-v2.1"  # Apache-2.0

LABEL_TO_KIND: Dict[str, Kind] = {
    "person": Kind.NAME,
    "organization": Kind.NAME,
    "company": Kind.NAME,
    "corporation": Kind.NAME,
    "government": Kind.NAME,
    "county": Kind.NAME,
    "city": Kind.NAME,
    "municipality": Kind.NAME,
    "location": Kind.ADDRESS,
    "address": Kind.ADDRESS,
    "ssn": Kind.SSN,
    "tax_id": Kind.FINANCIAL,
    "passport_number": Kind.NATIONAL_ID,
    "drivers_license": Kind.NATIONAL_ID,
    "bank_account": Kind.FINANCIAL,
    "routing_number": Kind.FINANCIAL,
    "credit_card": Kind.FINANCIAL,
    "phone_number": Kind.PHONE,
    "email": Kind.EMAIL,
    "date_of_birth": Kind.DOB,
}

DEFAULT_LABELS = list(LABEL_TO_KIND)

# Role nouns, pronouns and bare titles that NER tags as person/organization but
# that never identify anyone. Scrubbing them corrupts quotes ("[NAME_5] owning
# 95% of the Shares") and a downstream model then reports the corruption.
GENERIC_TERMS = frozenset(
    {
        "client",
        "contractor",
        "vendor",
        "supplier",
        "customer",
        "employee",
        "employees",
        "employer",
        "party",
        "parties",
        "company",
        "corporation",
        "llc",
        "inc",
        "ltd",
        "agreement",
        "contract",
        "document",
        "plaintiff",
        "defendant",
        "attorney",
        "counsel",
        "licensor",
        "licensee",
        "lessor",
        "lessee",
        "buyer",
        "seller",
        "purchaser",
        "shareholder",
        "shareholders",
        "stockholder",
        "stockholders",
        "member",
        "members",
        "director",
        "directors",
        "officer",
        "officers",
        "authorized officer",
        "founder",
        "founders",
        "partner",
        "partners",
        "trustee",
        "beneficiary",
        "executor",
        "administrator",
        "guarantor",
        "borrower",
        "lender",
        "investor",
        "investors",
        "signatory",
        "signatories",
        "witness",
        "board",
        "board of directors",
        "the board",
        "person",
        "persons",
        "individual",
        "individuals",
        "entity",
        "entities",
        "the undersigned",
        "undersigned",
        "each party",
        "either party",
        "i",
        "we",
        "you",
        "he",
        "she",
        "they",
        "heirs",
        "successors",
        "assigns",
        "spouse",
        "affiliate",
        "affiliates",
        "cto",
        "ceo",
        "cfo",
        "coo",
        "cio",
        "president",
        "chairman",
        "chairperson",
        "secretary",
        "treasurer",
        "general counsel",
        "managing director",
        "email address",
        "e-mail address",
        "facsimile number",
        "fax number",
        "telephone number",
        "phone number",
        "mobile number",
        "capital account",
        "bank name",
        "financial institution",
        "account number",
        "registered address",
        "principal place of business",
        "transferee",
        "transferees",
        "transferor",
        "addressee",
        "recipient",
        "recipients",
        "someone",
        "anyone",
        "competitor",
        "competitors",
        "representative",
        "representatives",
        "court",
        "courts",
        "natural person",
        "human being",
        "personal representative",
        "personal representatives",
        "prevailing party",
        # software roles and words NER tags as people in code and commit messages
        "user",
        "users",
        "admin",
        "author",
        "maintainer",
        "owner",
        "reviewer",
        "developer",
        "service",
        "server",
        "client id",
    }
)

# Words that do not make a phrase a name: "New Shareholder", "Each party".
_STOP_MODIFIERS = frozenset(
    {
        "new",
        "each",
        "every",
        "any",
        "such",
        "said",
        "the",
        "a",
        "an",
        "all",
        "other",
        "proposed",
        "purported",
        "prevailing",
        "transferring",
        "natural",
        "personal",
        "authorized",
        "issuing",
        "federal",
        "state",
        "or",
        "and",
        "of",
        "to",
        "this",
        "that",
        "no",
        "non",
        "former",
        "future",
        "existing",
    }
)

_NOT_NAME_WORDS = GENERIC_TERMS | _STOP_MODIFIERS

_NAMEY_LABELS = frozenset(
    {
        "person",
        "organization",
        "company",
        "corporation",
        "government",
        "county",
        "city",
        "municipality",
    }
)

_LABEL_WORDS = {
    "ssn": {"ssn", "social security", "social security number"},
    "tax_id": {"tax id", "tax", "ein"},
    "passport_number": {"passport", "passport number"},
    "drivers_license": {"driver's license", "drivers license", "driver license", "dl"},
    "bank_account": {"bank account", "account", "bank"},
    "routing_number": {"routing", "routing number"},
    "phone_number": {"phone", "telephone", "tel", "mobile", "cell"},
    "email": {"email", "e-mail"},
    "address": {"address"},
    "date_of_birth": {"dob", "date of birth", "birthdate"},
}


def is_generic_name_phrase(text: str, label: str) -> bool:
    """True when a person/org hit holds no actual name: only role nouns, stop
    modifiers and lowercase words. 'transferring Shareholder' -> True,
    'Tunnel King Studios Inc.' -> False."""
    if label not in _NAMEY_LABELS:
        return False
    for token in text.split():
        bare = token.strip(".,;:()\"'’").rstrip(".")
        if bare and bare[0].isupper() and bare.lower() not in _NOT_NAME_WORDS:
            return False
    return True


def is_noise(text: str, label: str) -> bool:
    low = text.lower().strip().strip(".,;:")
    if low in GENERIC_TERMS:
        return True
    for article in ("the ", "a ", "an ", "such ", "said ", "any ", "each ", "every "):
        if low.startswith(article) and low[len(article) :] in GENERIC_TERMS:
            return True
    return is_generic_name_phrase(text, label) or low in _LABEL_WORDS.get(label, ())


class GlinerDetector:
    name = "gliner"

    def __init__(
        self,
        model_id: str = DEFAULT_MODEL,
        labels: Optional[Sequence[str]] = None,
        # 0.5: below it the model floods the table with generic phrases scored
        # as names; rare surnames it under-scores are left to the regex rules.
        threshold: float = 0.5,
        chunk_size: int = 1500,  # characters; the model truncates near 384 tokens
        overlap: int = 200,
        model=None,  # injected for tests
    ):
        self.model_id = model_id
        self.labels = list(labels or DEFAULT_LABELS)
        self.threshold = threshold
        self.chunk_size = chunk_size
        self.overlap = overlap
        self._model = model

    def _load(self):
        if self._model is None:
            try:
                from gliner import GLiNER
            except ImportError as e:
                raise ImportError("GLiNER is not installed: pip install 'pii-eraser[gliner]'") from e
            logger.info("loading GLiNER model %s", self.model_id)
            self._model = GLiNER.from_pretrained(self.model_id)
        return self._model

    def detect(self, text: str) -> List[Span]:
        model = self._load()
        spans: Dict[tuple, Span] = {}
        start = 0
        while start < len(text):
            end = min(start + self.chunk_size, len(text))
            chunk = text[start:end]
            for entity in model.predict_entities(chunk, self.labels, threshold=self.threshold):
                label, value = entity["label"], entity["text"]
                if is_noise(value, label):
                    continue
                local = entity.get("start")
                if local is None or chunk[local : local + len(value)] != value:
                    local = chunk.find(value)
                    if local == -1:
                        continue
                abs_start = start + local
                spans[(abs_start, value)] = Span(
                    start=abs_start,
                    end=abs_start + len(value),
                    text=value,
                    kind=LABEL_TO_KIND.get(label, Kind.NAME),
                    confidence=float(entity["score"]),
                    source=f"gliner:{label}",
                )
            if end >= len(text):
                break
            start = end - self.overlap
        return list(spans.values())
