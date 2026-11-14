"""NER detection with GLiNER (zero-shot labels, runs locally, ~400 MB model).

Ported from the contract-analyzer scrubber. Install with `pip install
pii-eraser[gliner]`; the model downloads on first use.
"""

import logging
import re
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
# Per-label thresholds over the default. GLiNER scores names it has seen rarely (most non-English names) low;
# at 0.5 a third of German names went unmasked. Below 0.5 the generic phrases it also scores are caught by
# the noise filter (role nouns, determiners, label words), not by the threshold.
DEFAULT_LABEL_THRESHOLDS: Dict[str, float] = {"person": 0.3}

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
        # German role nouns, departments and family roles: capitalised like names, never a name
        "kunde", "kundin", "kunden", "mitarbeiter", "mitarbeiterin", "mitarbeitende", "sachbearbeiter",
        "sachbearbeiterin", "geschäftsführer", "geschäftsführerin", "geschäftsführung", "ansprechpartner",
        "ansprechpartnerin", "vorgesetzter", "vorgesetzte", "kollege", "kollegin", "kollegen", "teamleiter",
        "teamleiterin", "abteilungsleiter", "abteilungsleiterin", "leiter", "leiterin", "inhaber", "inhaberin",
        "vermieter", "vermieterin", "mieter", "mieterin", "eigentümer", "eigentümerin", "auftraggeber",
        "auftragnehmer", "lieferant", "dienstleister", "arzt", "ärztin", "patient", "patientin", "versicherte",
        "versicherter", "antragsteller", "antragstellerin", "empfänger", "empfängerin", "absender", "verfasser",
        "bearbeiter", "bearbeiterin", "techniker", "technikerin", "entwickler", "entwicklerin", "administratorin",
        "buchhaltung", "personalabteilung", "vertrieb", "einkauf", "support", "kundenservice", "kundendienst",
        "hotline", "team", "herr", "frau", "herrn", "fahrer", "fahrerin", "nutzer", "nutzerin", "benutzer",
        "benutzerin", "teilnehmer", "teilnehmerin", "vorstand", "aufsichtsrat", "betriebsrat", "gesellschafter",
        "gesellschafterin", "steuerberater", "steuerberaterin", "rechtsanwalt", "rechtsanwältin", "notar",
        "notarin", "gutachter", "sachverständiger", "pflegekraft", "hausarzt", "hausärztin", "facharzt",
        "fachärztin", "ehegatte", "ehegattin", "ehefrau", "ehemann", "kind", "kinder", "tochter", "sohn",
        "mutter", "vater", "azubi", "auszubildende", "praktikant", "praktikantin", "werkstudent", "werkstudentin",
        "chef", "chefin", "projektleiter", "projektleiterin", "hausmeister", "hausverwaltung", "praxis",
        "praxisteam", "krankenkasse", "versicherung",
        # English roles and departments
        "manager", "engineer", "team lead", "procurement", "hr", "finance", "accounting", "helpdesk",
        "service desk", "colleague", "colleagues", "doctor", "nurse", "patient", "driver", "tenant", "landlord",
        "applicant", "claimant", "policyholder", "insured", "account holder", "cardholder", "sales", "marketing",
        "legal", "payroll", "wife", "husband", "spouse", "child", "daughter", "son", "mother", "father",
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


# Labels whose values are numbers: a hit without a digit is the field's name ("IBAN", "Steuer-ID",
# "Kreditkarte"), not its value.
_NUMERIC_LABELS = frozenset(
    {"ssn", "tax_id", "passport_number", "drivers_license", "bank_account", "routing_number", "credit_card",
     "phone_number", "date_of_birth"}
)
# German articles and determiners: standard written German puts none before a person's name, so
# "der Bäcker", "ein Schreiber", "den Dietrich" are the trade, the clerk, the lock pick.
_DE_DETERMINER = re.compile(
    r"(?:^|[\s(\[\"'„])(?:der|die|das|den|dem|des|ein|eine|einen|einem|einer|eines|kein|keine|keinen|keinem|jeder|jede"
    r"|jedes|jeden|dieser|diese|dieses|diesen|unser|unsere|unseren|unserem|beim|vom|zum|zur)\s+$",
    re.IGNORECASE,
)


def is_noise(text: str, label: str, before: str = "") -> bool:
    low = text.lower().strip().strip(".,;:")
    if low in GENERIC_TERMS:
        return True
    if label in _NUMERIC_LABELS and not any(c.isdigit() for c in text):
        return True
    if label == "email" and "@" not in text:
        return True
    if label == "person":
        words = text.split()
        if words and words[0].lower() in {"der", "die", "das", "den", "dem", "des", "ein", "eine", "einen", "einem"}:
            return True
        if len(words) == 1 and _DE_DETERMINER.search(before):
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
        label_thresholds: Optional[Dict[str, float]] = None,
    ):
        self.model_id = model_id
        self.labels = list(labels or DEFAULT_LABELS)
        self.threshold = threshold
        self.label_thresholds = dict(DEFAULT_LABEL_THRESHOLDS if label_thresholds is None else label_thresholds)
        # The lowest bar any label uses; the eraser's stage must not cut below it again.
        self.min_confidence = min([threshold, *self.label_thresholds.values()])
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
            for entity in model.predict_entities(chunk, self.labels, threshold=self.min_confidence):
                label, value = entity["label"], entity["text"]
                if entity["score"] < self.label_thresholds.get(label, self.threshold):
                    continue
                local = entity.get("start")
                if local is None or chunk[local : local + len(value)] != value:
                    local = chunk.find(value)
                    if local == -1:
                        continue
                abs_start = start + local
                if is_noise(value, label, text[max(0, abs_start - 12) : abs_start]):
                    continue
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
