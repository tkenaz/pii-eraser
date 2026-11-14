"""Personal-data rules. Ported from the contract-analyzer scrubber (37lab), where
they were tuned on real contracts, medical notes and business email in EN/DE/CH.

Confidence guide: 0.9+ near-certain format, 0.7-0.9 clear context, below 0.7
broad. `code_safe` marks rules precise enough to run over source code.
"""

import re

from pii_eraser.detectors.regex import Rule
from pii_eraser.detectors.validators import (
    card_span,
    digits_between,
    iban_labeled_span,
    iban_printed_span,
    iban_span,
    ip_ok,
    nino_ok,
    printed_as_one,
    steuer_id_ok,
    sv_nummer_ok,
    uk_postcode_area_ok,
)
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

# Names beyond ASCII: Latin-1, Latin Extended-A (Łukasz, Şahin) and Extended Additional (Phạm, Nguyễn).
_UP = "A-ZÀ-ÖØ-Þ\u0100-\u017F\u1E00-\u1EFF"
_LO = "a-zß-öø-ÿ\u0100-\u017F\u1E00-\u1EFF"
# One name word: O'Connor, El-Amrani, Schmidt-Rottluff, Tanner's.
_NW = rf"[{_UP}](?:['’][{_UP}])?[{_LO}]+(?:-[{_UP}][{_LO}]+)*"
_NWS = rf"{_NW}(?:['’]s)?"  # street words: Tanner's Yard
_PARTICLE = r"(?:van|von|de|der|den|du|da|di|del|della|dos|das|zu|ter|ten|al|el|bin|ibn|le|la)"
_SURNAME = rf"(?:{_PARTICLE}\s+){{0,2}}{_NW}"
_FULL = rf"{_NW}(?:[ \t]+{_SURNAME}){{0,2}}"
_INITIAL_SURNAME = rf"[{_UP}]\.[ \t]?{_SURNAME}"
# Last, First — as name lists and forms write it.
_INVERTED = rf"{_SURNAME},[ \t]*{_NW}(?:[ \t]+{_NW})?"
_NAME_END = r"(?=[ \t]*(?:[\n,;:()<|\"']|[ \t][-–—+][ \t]|$)|[ \t]{2,})"
# A name written in capitals, as banks and forms print it: GISELA KÖNIG, MINH ĐỨC TRẦN.
_FULL_UPPER = rf"[{_UP}]{{2,}}(?:-[{_UP}]{{2,}})*(?:[ \t]+[{_UP}]{{2,}}(?:-[{_UP}]{{2,}})*){{1,3}}"

_MONTHS_EN = r"(?:January|February|March|April|May|June|July|August|September|October|November|December)"
_MONTHS_DE = r"(?:Januar|Jänner|Februar|Feber|März|April|Mai|Juni|Juli|August|September|Oktober|November|Dezember)"
_DATE_VALUE = (
    r"(?:\d{1,2}[./-]\d{1,2}[./-](?:19|20)?\d{2}|(?:19|20)\d{2}-\d{2}-\d{2}"
    rf"|\d{{1,2}}\.?[ \t]+(?:{_MONTHS_EN}|{_MONTHS_DE})[ \t]+(?:19|20)\d{{2}}"
    rf"|{_MONTHS_EN}[ \t]+\d{{1,2}},?[ \t]+(?:19|20)\d{{2}})"
)

# German, Austrian and Swiss street names: compound (Lindenstraße), separate (Mariahilfer Straße),
# hyphenated (Friedrich-Ebert-Allee, Bgm.-Smidt-Str.) and prepositional (Am Alten Markt, Im Rosengarten).
_DE_SUFFIX = (
    r"(?:straße|strasse|str\.|gasse|weg|allee|platz|ring|damm|ufer|chaussee|steig|stieg|pfad|markt|graben|kai"
    r"|zeile|promenade|anger|hof|park|feld|berg|brücke|wall|deich|kamp|redder|twiete|höhe|grund|aue|bogen|winkel|gärten|garten)"
)
_DE_STREET = (
    rf"(?:[{_UP}][{_LO}]*\.?-(?:[{_UP}{_LO}][{_LO}]*\.?-)*(?-i:Straße|Strasse|Str\.|Gasse|Weg|Allee|Platz|Ring|Damm|Ufer|Chaussee|Steig|Pfad|Markt|Graben|Kai|Zeile|Promenade|Anger|Hof|Park|Brücke)"
    # the type first, with a genitive or a place after it: Straße des Friedens, Platz der Republik
    rf"|(?-i:Straße|Strasse|Platz|Allee|Weg|Gasse|Ring|Damm|Ufer)[ \t]+(?:des|der|dem|den|am|im|zum|zur|vom)[ \t]+[{_UP}][{_LO}]+(?:[ \t]+[{_UP}][{_LO}]+)?"
    # Swiss streets in French and Italian: Rue du Marché, Via alla Chiesa
    rf"|(?-i:Via|Viale|Vicolo|Piazza|Corso|Rue|Chemin|Avenue|Route|Place|Quai|Boulevard|Impasse)"
    rf"(?:[ \t]+(?:[{_UP}][{_LO}]+|de|du|des|la|le|les|della|del|dello|dei|di|alla|al|ai)|[ \t]+(?:d|l)['’][{_UP}][{_LO}]+){{1,4}}"
    rf"|(?:(?-i:Alte|Neue|Obere|Untere|Große|Grosse|Kleine|Hintere|Vordere|Lange|Kurze|Breite|Hohe|Innere|Äußere)[rn]?[ \t]+)?"
    rf"(?:[{_UP}][{_LO}]*\.?-)*[{_UP}][{_LO}]*?{_DE_SUFFIX}"
    rf"|[{_UP}][{_LO}]+[ \t]+(?-i:Straße|Strasse|Str\.|Gasse|Weg|Allee|Platz|Ring|Damm|Ufer|Chaussee|Steig|Pfad|Markt|Graben|Kai|Zeile|Promenade|Anger|Hof|Park|Brücke)"
    rf"|(?:Am|An[ \t]+der|An[ \t]+den|An[ \t]+dem|Auf[ \t]+der|Auf[ \t]+dem|Auf[ \t]+den|Im|In[ \t]+der|In[ \t]+den|Zum|Zur|Unter[ \t]+den|Hinter[ \t]+der|Hinter[ \t]+dem|Vor[ \t]+dem|Bei[ \t]+der)"
    rf"(?:[ \t]+[{_UP}][{_LO}]+){{1,3}})"
)
_HOUSE_NO = r"\d{1,4}(?:[ \t]?[a-zA-Z])?(?:[ \t]?[-–/][ \t]?\d{1,4}[a-zA-Z]?)?"
_CITY_NAME = (
    rf"[{_UP}][{_LO}]+(?:[- ][{_UP}][{_LO}]+)*"
    rf"(?:[ \t]+(?:im|am|an[ \t]+der|in[ \t]+der|ob[ \t]+der|bei|upon|on)[ \t]+[{_UP}][{_LO}]+)?(?:[ \t]*\([^)\n]{{1,12}}\))?"
)
# Words that follow a five-digit number without being a town.
_NOT_TOWN = r"(?!(?:Euro|Stück|Stk|Mitarbeiter|Mitarbeitende|Kunden|Nutzer|Zeilen|Einträge|Datensätze|Punkte|Tage|Jahre|Stunden|Minuten|Sekunden|Anfragen|Fehler|Dateien|Seiten|Wörter|Zeichen|Euro|Franken|Pfund|Requests|Users|Rows|Records|Items|Files|Pages|Words|Bytes|Points|Days|Years)\b)"
_UK_STREET_TYPE = (
    r"(?:Road|Rd|Street|St|Lane|Ln|Avenue|Ave|Close|Crescent|Cres|Drive|Dr|Gardens|Gdns|Grove|Place|Pl|Square|Sq"
    r"|Terrace|Tce|Way|Yard|Mews|Row|Court|Ct|Hill|Park|Rise|Walk|View|Green|Parade|Wharf|Quay|Lodge|Gate)"
)
_UK_POSTCODE = r"[A-Z]{1,2}[0-9lIO][0-9A-Zl]?[ \t]?[0-9lIO][A-Z]{2}"

# What is printed between the groups of one value: a blank, a hyphen, a dot, a slash. No-break and narrow
# spaces arrive here as blanks (see RegexDetector). A tab divides table columns and is never part of a value.
_GAP = r"[ .\-/]?"
# Blank, hyphen or dot, or one line break: account and card numbers wrap, ids do not.
_GAP_WRAP = r"(?:[ .\-]?|[ \t]*\n[ \t]*)"
# IBAN-shaped run of letters and digits; the refine function cuts it at the country's registry length.
_IBAN_RUN = rf"[A-Za-z0-9]{{2}}[0-9OISlB]{{2}}(?:{_GAP_WRAP}[A-Za-z0-9]){{11,30}}"
# Not inside a token, and not after "x-" or "x.": the third group of a UUID is not where an IBAN starts.
_IBAN_START = r"(?<![A-Za-z0-9])(?<![A-Za-z0-9][-.])"

PII_RULES = [
    # ---- email (letters beyond ASCII in the mailbox and in the domain: gärtnerei-beispiel.de)
    Rule("email_standard", Kind.EMAIL, r"(?<![\w.%+-])[\w.%+-]+@[\w.-]+\.[^\W\d_]{2,}\b", 0.95, _I, code_safe=True),
    # ---- phone
    # +49 / 0049, optional (0), area in brackets or not, groups split by blanks, dashes or a slash.
    Rule(
        "phone_intl",
        Kind.PHONE,
        r"(?<![\w+])(?:\+|00)[1-9]\d{0,2}[ \t./-]?(?:\(0\)[ \t]?)?\(?\d{1,12}\)?(?:(?:[ \t]*/[ \t]*|[ \t-])\d{1,8}){0,4}(?!\w|[.,]\d)",
        0.85,
        _I,
        validate=digits_between(8, 16),
    ),
    # National numbers with a trunk 0 (DE, AT, CH, UK): 030 23125057, (069) 90009-311, 0172 / 9973185,
    # (0117) 496 0823, 020 7946 0958. Seven digits at least, so 01/2026 is not a phone.
    Rule(
        "phone_national",
        Kind.PHONE,
        r"(?<![\w+/.,-])\(?0[1-9]\d{0,4}\)?(?:[ \t]*/[ \t]*|[ \t]*-[ \t]*|[ \t]+)\d{2,8}(?:[ \t-]\d{1,6}){0,2}(?![\w/-]|[.,]\d)",
        0.75,
        _I,
        validate=digits_between(7, 13),
    ),
    # German mobile numbers written without spaces: 0172..., 015x, 016x.
    Rule("phone_mobile_de", Kind.PHONE, r"(?<![\w+])01[5-7]\d{8,9}(?!\w)", 0.80, _I),
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
    # A run of digits read from every position where a number can start (the look-ahead lets candidates
    # overlap, so a phone number standing before a card in a table row does not hide it). The run is taken
    # one digit longer than the longest card, so card_span can see that a number goes on. It cuts the run at
    # a length the scheme issues and accepts it only in a card's print layout and on the Luhn digit.
    Rule(
        "card",
        Kind.FINANCIAL,
        rf"(?<![\w.+-])(?=(\d(?:{_GAP_WRAP}\d){{12,19}}))",
        0.97,
        re.MULTILINE,
        code_safe=True,
        refine=card_span,
    ),
    Rule("cc_partial", Kind.FINANCIAL, r"(?:ending\s+in|last\s+(?:4|four)\s*(?:digits)?)[:\s]*\d{4}\b", 0.85, _I),
    # An IBAN in any grouping and with any separator; iban_span cuts the run at the country's registry length
    # and accepts it only on mod-97, after reading OCR confusions back. Checksum-proven, so it outranks an
    # NER guess on the same characters.
    Rule(
        "iban",
        Kind.FINANCIAL,
        rf"{_IBAN_START}(?=({_IBAN_RUN}))",
        0.98,
        re.MULTILINE,
        code_safe=True,
        refine=iban_span,
    ),
    # Check digits that do not hold (typing or OCR error): still an IBAN when it is printed as one, in groups
    # of four at the registry length, or when it stands after the word IBAN.
    Rule("iban_printed", Kind.FINANCIAL, rf"{_IBAN_START}(?=({_IBAN_RUN}))", 0.80, re.MULTILINE, refine=iban_printed_span),
    Rule(
        "iban_labeled",
        Kind.FINANCIAL,
        rf"(?i:\bI[ ]?BAN\b)[\s:#=\"']{{0,4}}({_IBAN_RUN})",
        0.85,
        re.MULTILINE,
        refine=iban_labeled_span,
    ),
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
        "dob_labeled_en",
        Kind.DOB,
        r"(?:\bDOB|D\.O\.B\.|date\s+of\s+birth|birth\s*date|\bborn(?:\s+on)?)[:\s]+(" + _DATE_VALUE + r")",
        0.90,
        _I,
        code_safe=True,
    ),
    Rule(
        "dob_labeled_text",
        Kind.DOB,
        r"(?:DOB|date\s+of\s+birth|birthdate|born)[:\s]+[A-Za-z]+\s+\d{1,2},?\s+\d{4}",
        0.90,
        _I,
        code_safe=True,
    ),
    Rule(
        "dob_labeled_de",
        Kind.DOB,
        r"(?:Geburtsdatum|Geb\.\s*-?\s*Datum|\bgeb\.|\bgeboren(?:\s+am)?)[:\s]+(" + _DATE_VALUE + r")",
        0.90,
        _I,
        code_safe=True,
    ),
    # ---- address: conservative, require context
    Rule(
        "addr_us_street",
        Kind.ADDRESS,
        r"\b\d{1,5}\s+[A-Za-z]+(?:\s+[A-Za-z]+)?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir)\.?\b",
        0.80,
        _I,
    ),
    Rule("addr_unit", Kind.ADDRESS, r"(?:Apt|Apartment|Flat|Unit|Suite|Ste|Room)\.?\s*#?\s*\d+\w?\b", 0.70, _I),
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
    # Typed in lower case in chats and exports; without capitals the postcode area has to exist.
    Rule(
        "postcode_uk_lower",
        Kind.ADDRESS,
        r"(?<![\w-])[a-z]{1,2}\d{1,2}[a-z]?[ ]?\d[a-z]{2}(?![\w-])",
        0.70,
        re.MULTILINE,
        validate=uk_postcode_area_ok,
    ),
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
        r"\b(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof|Sir|Herr|Herrn|Frau|Hr|Fr)\.?[ \t]+(?:(?:Dr|Prof)\.[ \t]+)?("
        + rf"(?:{_PARTICLE}[ \t]+){{0,2}}"
        + _FULL
        + r")(?=[\s,.;:!?)\n'’]|$)",
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
        "name_greeting",
        Kind.NAME,
        r"(?:^|(?<=[>\n]))[ \t]*(?i:hello|hi|hey|hallo|liebe|lieber|moin|servus|guten\s+(?:tag|morgen))[ \t]+"
        r"(?!(?i:all|both|team|everyone|everybody|zusammen|there|folks|guys|leute|alle)\b)(" + _FULL + r")(?=[ \t]*[,!\n])",
        0.80,
        _CS,
    ),
    Rule(
        "name_closing_inline",
        Kind.NAME,
        r"(?i:best|regards|thanks|cheers|grüße|gruß|mfg|lg|vg|danke)[,!.][ \t]+(" + _FULL + r"|" + _INITIAL_SURNAME + r")(?=[ \t]*(?:\n|$))",
        0.80,
        _CS,
    ),
    Rule(
        "name_dear",
        Kind.NAME,
        r"Dear\s+(?!Sir|Madam|Team|All|Customer|Support)(" + _NAME_WORD + r"(?:\s+" + _NAME_WORD + r")?)(?=\s*[,\n])",
        0.75,
        _CS,
    ),
    # The line under a closing: "Thanks,\nGiorgos", "Danke\nShirin", "Mit freundlichen Grüßen\nH. Lindner".
    Rule(
        "name_signature",
        Kind.NAME,
        r"(?i:regards|sincerely|cheers|thanks|thank\s+you|best(?:\s+wishes)?|danke(?:\s+schön)?|vielen\s+dank"
        r"|gr[üu](?:ß|ss)e?n?|mfg|lg|vg|servus|ciao)[,!.]?[ \t]*\n[ \t]*(?:(?:i\.\s?A\.|i\.\s?V\.|gez\.)[ \t]*)?"
        r"(?!(?:Ihr|Ihre|Euer|Eure|Dein|Deine|Your|The|Das|Die|Der|Team)\b)(?![^\n]*(?:[Tt]eam|Support|Service|Abteilung)\b)("
        + _FULL
        + r"|"
        + _INITIAL_SURNAME
        + r")(?=[ \t]*(?:\n|$|,))",
        0.80,
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

    # ---- additions from the 2026-11 evaluation (DACH and UK formats)
    # German tax id (IdNr): 11 digits, check digit and digit-repetition rule.
    Rule(
        "steuer_id",
        Kind.NATIONAL_ID,
        rf"(?<![\w.,/+-])(?<!\d )(?=([1-9](?:{_GAP}\d){{10}}(?!{_GAP}\d|,\d)))",
        0.90,
        _I,
        validate=printed_as_one(steuer_id_ok),
    ),
    # German tax number (Steuernummer), state formats 2-3/3-4/4-5 digits with slashes.
    Rule("steuernummer", Kind.NATIONAL_ID, r"(?<![\d/.])\d{2,3}/\d{3,4}/\d{4,5}(?![\d/]|\.\d)", 0.80, _I),
    # German pension insurance number with its check digit, in any grouping: 43 191171 V 67 2, 43-191171-V-672.
    Rule(
        "sv_nummer",
        Kind.NATIONAL_ID,
        rf"(?<![\w/.-])(?=(\d(?:{_GAP}\d){{7}}{_GAP}[A-Za-z](?:{_GAP}\d){{3}}(?!\w)))",
        0.95,
        re.MULTILINE,
        code_safe=True,
        validate=printed_as_one(sv_nummer_ok),
    ),
    # UK National Insurance number written in pairs: JG 37 28 59 A.
    Rule(
        "ni_uk_spaced",
        Kind.NATIONAL_ID,
        r"(?<![\w-])[A-Z]{2}(?:[ .\-]?\d{2}){3}[ .\-]?[A-D](?![\w])",
        0.90,
        re.MULTILINE,
        validate=printed_as_one(nino_ok),
    ),
    # IP addresses. Version strings are kept out by what precedes them (v1.2.3.4, "version 1.2.3.4").
    Rule(
        "ip_v4",
        Kind.IP,
        r"(?<![\w.:/-])(?<!version )(?<!Version )(?<!VERSION )(?<!ver )(?<!v=)(?<!==)(?:\d{1,3}\.){3}\d{1,3}(?![\w-]|\.\d)",
        0.85,
        _I,
        validate=ip_ok,
    ),
    Rule(
        "ip_v6",
        Kind.IP,
        r"(?<![\w:.])[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])",
        0.85,
        re.MULTILINE,
        validate=ip_ok,
    ),
    # ---- names in forms, lists and sign-offs
    Rule(
        "name_field",
        Kind.NAME,
        r"(?i:\b(?:name|vorname|nachname|empfänger(?:in)?|kontoinhaber(?:in)?|inhaber(?:in)?|patient(?:in)?|versicherte[rn]?"
        r"|mitarbeiter(?:in)?|antragsteller(?:in)?|fahrer(?:in)?|ansprechpartner(?:in)?|kontakt|contact|bearbeiter(?:in)?"
        r"|sachbearbeiter(?:in)?|absender(?:in)?|raised\s+by|requested\s+by|reported\s+by|submitted\s+by|approved\s+by"
        r"|created\s+by|assigned\s+to|assignee|reporter|employee|customer|kunde|kundin|client|recipient|beneficiary"
        r"|account\s+holder|card\s*holder|forename\(s\)|surname|full\s+name|policyholder|tenant|mieter(?:in)?"
        r"|vermieter(?:in)?|teilnehmer(?:in)?|attendees?|verfasser(?:in)?|author)[\"']?[ \t]*:[ \t]*[\"']?"
        r"|(?:raised|requested|reported|submitted|approved|created|signed|taken)\s+by[ \t]*:?[ \t]*)("
        + _INVERTED
        + r"|"
        + _FULL_UPPER
        + r"|"
        + _FULL
        + r"|"
        + _INITIAL_SURNAME
        + r")"
        + _NAME_END,
        0.85,
        _CS,
    ),
    # Initial and surname after a signature mark or a separator: "gez. H. Lindner", "– G. Benedetti",
    # "(A. Fernández)".
    Rule(
        "name_initial",
        Kind.NAME,
        r"(?:\bgez\.|\bi\.\s?A\.|\bi\.\s?V\.|[–—(/:|,]|\b(?:von|by|cc|mit|with|und|and|durch|für|for|an|to|update|mfg|gruß|best|regards)"
        r"|\d{1,2}:\d{2}|^)[ \t]*(" + _INITIAL_SURNAME + r")" + _NAME_END,
        0.80,
        _CS,
    ),
    # "Last, First" items of a semicolon list (distribution lists, attendee lists).
    Rule("name_list_inverted", Kind.NAME, r"(?:(?<=;)|(?<=:))[ \t]*(" + _INVERTED + r")(?=[ \t]*(?:;|\n|$))", 0.75, _CS),
    Rule("name_list_inverted_first", Kind.NAME, r"(?<![\w,])(" + _INVERTED + r")(?=[ \t]*;)", 0.70, _CS),
    # ---- addresses: DACH street + number, optionally with postcode and town; UK street lines and postcodes
    Rule(
        "addr_dach",
        Kind.ADDRESS,
        r"(?<![\w-])"
        + _DE_STREET
        + r"[ \t]+"
        + _HOUSE_NO
        + r"(?:(?:[ \t]*[,·|][ \t]*|[ \t]*\n[ \t]*|[ \t]+)(?:(?:D|A|CH)-)?\d{4,5}[ \t]+"
        + _CITY_NAME
        + r")?(?![\w])",
        0.85,
        _CS,
    ),
    # Postcode and town on their own, as an address line: at a line start or after a field separator, and the
    # town ends the line or the field. German nouns are capitalised, so "24816 Tokens" mid-sentence must not count.
    Rule(
        "addr_postcode_town_de",
        Kind.ADDRESS,
        r"(?:(?<=^)|(?<=[,·|:]))[ \t]*((?:D-)?\d{5}[ \t]+" + _NOT_TOWN + _CITY_NAME + r")(?=[ \t]*(?:$|[,·|;)]))",
        0.75,
        _CS,
    ),
    Rule(
        "addr_uk",
        Kind.ADDRESS,
        r"(?<![\w-])\d{1,4}[A-Z]?[ \t]+(?:" + _NWS + r"[ \t]+){1,3}" + _UK_STREET_TYPE + r"\b\.?"
        r"(?:,[ \t]*" + _CITY_NAME + r")?(?:,?[ \t]+" + _UK_POSTCODE + r")?(?![\w])",
        0.85,
        _CS,
    ),
    Rule(
        "postcode_uk_ocr",
        Kind.ADDRESS,
        r"(?:(?<![\w])|(?<=\\n))" + _UK_POSTCODE + r"(?![\w])",
        0.70,
        _CS,
        validate=digits_between(1, 4),
    ),
    # Address parts in labelled fields and JSON keys (vendor master data, OCR'd invoices):
    # PLZ: 70173, "postal_code": "5020", Ort: Münster, "town": "Leipzig", Street: Friedrich-Ebert-Allee 9c.
    Rule(
        "addr_field_postcode",
        Kind.ADDRESS,
        r"(?i:\b(?:plz|postleitzahl|post\s*code|postcode|postal[\s_]*code|zip(?:[\s_]*code)?)[\"']?)[ \t]*[:=][ \t]*[\"']?"
        r"((?:(?:D|A|CH)-)?\d{4,5}|" + _UK_POSTCODE + r")(?![\w])",
        0.85,
        _CS,
    ),
    Rule(
        "addr_field_town",
        Kind.ADDRESS,
        r"(?i:\b(?:ort|wohnort|stadt|town|city)[\"']?)[ \t]*[:=][ \t]*[\"']?(" + _CITY_NAME + r")(?=[\"']|[ \t]*(?:$|[,;\n]))",
        0.80,
        _CS,
    ),
    Rule(
        "addr_field_street",
        Kind.ADDRESS,
        r"(?i:\b(?:straße|strasse|street|anschrift|adresse|address(?:\s*line\s*\d)?|zeile\s*\d|line\s*\d)[\"']?)[ \t]*[:=][ \t]*[\"']?"
        r"(" + _DE_STREET + r"[ \t]+" + _HOUSE_NO + r"|\d{1,4}[A-Z]?[ \t]+(?:" + _NWS + r"[ \t]+){1,3}" + _UK_STREET_TYPE + r"\b\.?)(?![\w])",
        0.85,
        _CS,
    ),
]
