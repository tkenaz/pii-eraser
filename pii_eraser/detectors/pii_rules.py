"""Personal-data rules. Ported from the contract-analyzer scrubber (37lab), where
they were tuned on real contracts, medical notes and business email in EN/DE/CH.

Confidence guide: 0.9+ near-certain format, 0.7-0.9 clear context, below 0.7
broad. `code_safe` marks rules precise enough to run over source code.
"""

import re

from pii_eraser.detectors.regex import Rule
from pii_eraser.detectors.validators import iban_ok, luhn_ok
from pii_eraser.types import Kind

_I = re.IGNORECASE | re.MULTILINE
_CS = re.MULTILINE  # names: capitalisation is the signal

# Address rules are case-insensitive overall, but US state abbreviations spell
# ordinary words (OR/IN/ME/HI/OK...), so those parts are scoped back to
# case-sensitive with (?-i:...).
_US_STATES = r"(?-i:(?:A[LKZR]|C[AOT]|DE|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY]|DC))"
_CITY = r"(?-i:[A-Z][a-z]+)"
_US_STATE_NAMES = r"(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\s+Hampshire|New\s+Jersey|New\s+Mexico|New\s+York|North\s+Carolina|North\s+Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\s+Island|South\s+Carolina|South\s+Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\s+Virginia|Wisconsin|Wyoming|District\s+of\s+Columbia)"
_NAME_WORD = r"[A-ZÀ-Ÿ][a-zà-ÿ]+"
# Id values must hold a digit: with IGNORECASE, [A-Z0-9]{6,} also matches the
# next word, and "Insurance: Member ID ABC123" replaced "Member", not the id.
# The value is captured alone so the label stays readable.
_HAS_DIGIT = r"(?=[A-Z0-9-]*\d)"

PII_RULES = [
    # ---- email
    Rule("email_standard", Kind.EMAIL, r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.95, _I, code_safe=True),
    # ---- phone
    Rule(
        "phone_intl",
        Kind.PHONE,
        r"\+\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d{2,4})?",
        0.85,
        _I,
    ),
    Rule("phone_us_parens", Kind.PHONE, r"\(?\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b", 0.80, _I),
    Rule("phone_us_dashed", Kind.PHONE, r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b", 0.80, _I),
    Rule("phone_swiss", Kind.PHONE, r"\b0\d{2}\s\d{3}\s\d{2}\s\d{2}\b", 0.85, _I),
    Rule("phone_de", Kind.PHONE, r"\b0\d{3,4}[-.\s/]\d{5,8}\b", 0.75, _I),
    Rule(
        "phone_labeled",
        Kind.PHONE,
        r"(?:phone|tel|telephone|mobile|cell|fax|telefon|handy)[:\s]+[\d\s\-\+\(\)]{7,20}(?=\s*[\n,]|$)",
        0.80,
        _I,
        code_safe=True,
    ),
    # ---- US SSN: strict formats only, never bare 9 digits
    Rule("ssn_dashed", Kind.SSN, r"\b\d{3}-\d{2}-\d{4}\b", 0.90, _I, code_safe=True),
    Rule(
        "ssn_labeled",
        Kind.SSN,
        r"(?:SSN|Social\s+Security)[:\s#]*\d{3}[-\s]?\d{2}[-\s]?\d{4}",
        0.85,
        _I,
        code_safe=True,
    ),
    # ---- financial
    Rule(
        "cc_visa",
        Kind.FINANCIAL,
        r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        0.90,
        _I,
        code_safe=True,
        validate=luhn_ok,
    ),
    Rule(
        "cc_mastercard",
        Kind.FINANCIAL,
        r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        0.90,
        _I,
        code_safe=True,
        validate=luhn_ok,
    ),
    Rule(
        "cc_amex", Kind.FINANCIAL, r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b", 0.90, _I, code_safe=True, validate=luhn_ok
    ),
    Rule("cc_partial", Kind.FINANCIAL, r"(?:ending\s+in|last\s+(?:4|four)\s*(?:digits)?)[:\s]*\d{4}\b", 0.85, _I),
    Rule("iban", Kind.FINANCIAL, r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", 0.75, _I, code_safe=True, validate=iban_ok),
    Rule("account_labeled", Kind.FINANCIAL, r"(?:account|acct|konto)[:\s#]*\d{8,17}", 0.70, _I),
    Rule(
        "tax_id_labeled", Kind.FINANCIAL, r"(?:Tax\s*ID|EIN|Employer\s+ID)[:\s#]*\d{2}-\d{7}", 0.90, _I, code_safe=True
    ),
    Rule("tax_id_bare", Kind.FINANCIAL, r"\b\d{2}-\d{7}\b", 0.70, _I),
    Rule("routing_labeled", Kind.FINANCIAL, r"(?:routing|ABA|RTN)[:\s#]*\d{9}\b", 0.85, _I, code_safe=True),
    Rule("routing_bare", Kind.FINANCIAL, r"\b0[0-9]\d{7}\b", 0.60, _I),
    Rule("account_number", Kind.FINANCIAL, r"(?:account\s*(?:number|#|no)?)[:\s#]*\d{6,17}", 0.80, _I),
    # ---- date of birth
    Rule("dob_iso", Kind.DOB, r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b", 0.80, _I),
    Rule("dob_us", Kind.DOB, r"\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b", 0.75, _I),
    Rule("dob_eu", Kind.DOB, r"\b(?:0[1-9]|[12]\d|3[01])[-./](?:0[1-9]|1[0-2])[-./](?:19|20)\d{2}\b", 0.75, _I),
    Rule(
        "dob_text_mdy",
        Kind.DOB,
        r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+(?:19|20)\d{2}\b",
        0.85,
        _I,
    ),
    Rule(
        "dob_text_dmy",
        Kind.DOB,
        r"\b\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+(?:19|20)\d{2}\b",
        0.85,
        _I,
    ),
    Rule(
        "dob_labeled_en", Kind.DOB, r"(?:DOB|date\s+of\s+birth|birthdate|born)[:\s]+[\d./-]+", 0.85, _I, code_safe=True
    ),
    Rule(
        "dob_labeled_text",
        Kind.DOB,
        r"(?:DOB|date\s+of\s+birth|birthdate|born)[:\s]+[A-Za-z]+\s+\d{1,2},?\s+\d{4}",
        0.90,
        _I,
        code_safe=True,
    ),
    Rule("dob_labeled_de", Kind.DOB, r"(?:Geburtsdatum|Geb\.?|geboren\s+am?)[:\s]+[\d./-]+", 0.85, _I, code_safe=True),
    # ---- address: conservative, require context
    Rule(
        "addr_us_street",
        Kind.ADDRESS,
        r"\b\d{1,5}\s+[A-Za-z]+(?:\s+[A-Za-z]+)?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir)\.?\b",
        0.80,
        _I,
    ),
    Rule("addr_unit", Kind.ADDRESS, r"(?:Apt|Apartment|Unit|Suite|Ste)\.?\s*#?\s*\d+\w?\b", 0.70, _I),
    Rule(
        "addr_city_state_zip",
        Kind.ADDRESS,
        r"\b" + _CITY + r"(?:\s+" + _CITY + r")*,\s*" + _US_STATES + r"\s+\d{5}(?:-\d{4})?",
        0.85,
        _I,
    ),
    Rule(
        "addr_city_state",
        Kind.ADDRESS,
        r"\b" + _CITY + r"(?:\s+" + _CITY + r")*,\s*" + _US_STATES + r"\b(?!\s+[a-z])",
        0.75,
        _I,
    ),
    Rule(
        "addr_city_state_full",
        Kind.ADDRESS,
        r"\b" + _CITY + r"(?:[ \t]+" + _CITY + r")*,[ \t]*" + _US_STATE_NAMES + r"\b",
        0.80,
        _I,
    ),
    Rule("zip_after_state", Kind.ADDRESS, r",\s*(?-i:[A-Z]{2})\s+\d{5}(?:-\d{4})?", 0.75, _I),
    Rule(
        "addr_jurisdiction_state",
        Kind.ADDRESS,
        r"(?:laws?\s+of\s+the\s+State\s+of|laws?\s+of\s+the\s+state\s+of|laws?\s+of)[ \t]+(" + _US_STATE_NAMES + r")\b",
        0.85,
        _I,
    ),
    Rule(
        "addr_jurisdiction_venue",
        Kind.ADDRESS,
        r"(?:courts?\s+(?:of|in|located\s+in)|venue\s+(?:in|of|shall\s+be))[ \t]+("
        + _CITY
        + r"(?:[ \t]+"
        + _CITY
        + r")*)\b(?![ \t]+(?:of|the|this|that|any|such|said|each))",
        0.75,
        _I,
    ),
    Rule(
        "addr_state_incorporation",
        Kind.ADDRESS,
        r"\b" + _US_STATE_NAMES + r"[ \t]+(?:Corporation|Corp\.?|LLC|LLP|Inc\.?|Company|Limited|Ltd\.?)\b",
        0.75,
        _I,
    ),
    Rule("addr_state_of", Kind.ADDRESS, r"\bState\s+of\s+(" + _US_STATE_NAMES + r")\b", 0.80, _I),
    Rule(
        "addr_country_context",
        Kind.ADDRESS,
        r"(?:Passport|Nationality|Citizenship|Country|citizen\s+of|resident\s+of)[:\s]+((?-i:[A-Z])[A-Za-z ]{2,20}?)(?=[ \t]*[\n,;.\)]|$)",
        0.75,
        _I,
    ),
    Rule("addr_country_us", Kind.ADDRESS, r"\b(?:USA|U\.S\.A\.|United\s+States(?:\s+of\s+America)?)\b", 0.70, _I),
    Rule("postcode_uk", Kind.ADDRESS, r"\b(?-i:[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2})\b", 0.75, _I),
    Rule(
        "addr_german",
        Kind.ADDRESS,
        r"\b[A-Za-zäöüÄÖÜß]+(?:straße|strasse|weg|platz|gasse|allee)\s+\d+[a-z]?\b",
        0.80,
        _I,
    ),
    Rule("addr_labeled", Kind.ADDRESS, r"(?:address|adresse|anschrift)[:\s]+[^\n]{10,60}", 0.65, _I),
    # ---- medical
    Rule("mrn_en", Kind.MRN, r"(?:MRN|Medical\s+Record|Patient\s+ID|Chart)[:\s#]+\d{5,12}", 0.85, _I, code_safe=True),
    Rule(
        "mrn_de",
        Kind.MRN,
        r"(?:Patientennummer|Pat\.?\s*-?\s*Nr\.?|Fallnummer)[:\s#]+\d{5,12}",
        0.85,
        _I,
        code_safe=True,
    ),
    Rule(
        "health_en",
        Kind.HEALTH_PLAN_ID,
        r"(?:Member|Subscriber|Policy|Insurance|Plan)\s*(?:ID|Number|#|No)?[:\s#]+" + _HAS_DIGIT + r"([A-Z0-9]{6,15})",
        0.80,
        _I,
    ),
    Rule("rx_bin", Kind.HEALTH_PLAN_ID, r"(?:Group|Rx\s*Bin|BIN)[:\s#]+\d{5,10}", 0.75, _I),
    Rule(
        "health_de",
        Kind.HEALTH_PLAN_ID,
        r"(?:Versicherungsnummer|Versicherungs-Nr|Krankenkasse)[:\s]+" + _HAS_DIGIT + r"([A-Z0-9-]{6,20})",
        0.80,
        _I,
        code_safe=True,
    ),
    # ---- national ids
    Rule(
        "dl_labeled", Kind.NATIONAL_ID, r"(?:Driver'?s?\s*License|DL|License\s*#?)[:\s]*([A-Z]{2}\s*\d{6,10})", 0.90, _I
    ),
    Rule("dl_state_number", Kind.NATIONAL_ID, r"\b([A-Z]{2}\s+\d{7,9})\b", 0.65, _I),
    Rule(
        "passport_labeled", Kind.NATIONAL_ID, r"(?:Passport\s*(?:Number|#|No)?)[:\s]*(\d{9})", 0.90, _I, code_safe=True
    ),
    Rule(
        "passport_alphanumeric",
        Kind.NATIONAL_ID,
        r"(?:Passport\s*(?:Number|#|No)?)[:\s]*([A-Z]?\d{8,9})",
        0.85,
        _I,
        code_safe=True,
    ),
    Rule(
        "id_labeled_en", Kind.NATIONAL_ID, r"\b(?:ID|License)\s*[:#]\s*" + _HAS_DIGIT + r"([A-Z0-9]{6,12})\b", 0.70, _I
    ),
    Rule(
        "id_labeled_de",
        Kind.NATIONAL_ID,
        r"(?:Ausweis|Führerschein|Personalausweis)[:\s#]+" + _HAS_DIGIT + r"([A-Z0-9]{6,12})",
        0.75,
        _I,
        code_safe=True,
    ),
    Rule("ni_uk", Kind.NATIONAL_ID, r"\b[A-Z]{2}\d{6}[A-Z]\b", 0.80, _I),
    Rule("ahv_swiss", Kind.NATIONAL_ID, r"\b756\.\d{4}\.\d{4}\.\d{2}\b", 0.95, _I, code_safe=True),
    Rule("ahv_labeled", Kind.NATIONAL_ID, r"(?:AHV|AVS)[:\s-]*756\d{10}", 0.90, _I, code_safe=True),
    Rule("nie_spanish", Kind.NATIONAL_ID, r"\b[XYZ]\d{7}[A-Z]\b", 0.95, _I, code_safe=True),
    Rule("nie_labeled", Kind.NATIONAL_ID, r"(?:NIE)[:\s#]*[XYZ]\d{7}[A-Z]", 0.95, _I, code_safe=True),
    Rule("dni_spanish", Kind.NATIONAL_ID, r"\b\d{8}[A-Z]\b", 0.80, _I),
    Rule("dni_labeled", Kind.NATIONAL_ID, r"(?:DNI|NIF)[:\s#]*\d{8}[A-Z]", 0.95, _I, code_safe=True),
    # ---- names: the hardest category, context required, same line only
    Rule(
        "name_label",
        Kind.NAME,
        r"(?:Name)[:\s]+(" + _NAME_WORD + r"\s+" + _NAME_WORD + r")(?=\s*[\n,]|$)",
        0.85,
        _CS,
        code_safe=True,
    ),
    Rule(
        "name_titled",
        Kind.NAME,
        r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Herr|Frau)\.?\s+("
        + _NAME_WORD
        + r"(?:\s+"
        + _NAME_WORD
        + r"){0,1})(?=[\s,.\n]|$)",
        0.85,
        _CS,
        code_safe=True,
    ),
    Rule(
        "name_role",
        Kind.NAME,
        r"(?:Patient|Client|Customer|Kunde)(?:\s+Name)?[:\s]+(" + _NAME_WORD + r"\s+" + _NAME_WORD + r")(?=\s*[\n,]|$)",
        0.80,
        _CS,
    ),
    Rule(
        "name_email_header",
        Kind.NAME,
        r"(?:From|To|Von|An)[:\s]+(" + _NAME_WORD + r"\s+" + _NAME_WORD + r")(?=\s*[\n<]|$)",
        0.75,
        _CS,
    ),
    Rule(
        "name_dear",
        Kind.NAME,
        r"Dear\s+(?!Sir|Madam|Team|All|Customer|Support)(" + _NAME_WORD + r"(?:\s+" + _NAME_WORD + r")?)(?=\s*[,\n])",
        0.75,
        _CS,
    ),
    Rule(
        "name_signature",
        Kind.NAME,
        r"(?:regards|sincerely|cheers|thanks|best)[,\s]*\n\s*("
        + _NAME_WORD
        + r"(?:\s+"
        + _NAME_WORD
        + r")?)(?=\s*[\n]|$)",
        0.75,
        _CS,
    ),
    # Signature blocks: party names NER is most likely to miss (rare surnames).
    Rule(
        "name_signature_by",
        Kind.NAME,
        r"\bBy:\s*\n?\s*([A-ZÀ-Ÿ][A-Za-zà-ÿÀ-Ÿ'’.-]*(?:\s+[A-ZÀ-Ÿ][A-Za-zà-ÿÀ-Ÿ'’.-]*){1,3})(?=\s*[\n,(]|$)",
        0.90,
        _CS,
    ),
    Rule(
        "name_signed_label",
        Kind.NAME,
        r"\b(?:Signed|Witness|Signature)[:\s]+([A-ZÀ-Ÿ][a-zà-ÿ'’.-]+(?:\s+[A-ZÀ-Ÿ][A-Za-zà-ÿ'’.-]*){1,3})(?=\s*[\n,(]|$)",
        0.85,
        _CS,
    ),
    Rule(
        "name_party_preamble",
        Kind.NAME,
        r"(?i:by\s+and\s+(?:between|among)|\bbetween)\s+(?-i:([A-ZÀ-Ÿ][a-zà-ÿ'’.-]+(?:\s+[A-ZÀ-Ÿ][A-Za-zà-ÿ'’.-]*){1,3}))(?=\s*[,(\n])",
        0.80,
        _CS,
    ),
]
