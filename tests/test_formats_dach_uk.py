"""German, Austrian, Swiss and UK formats, prose passwords, IP addresses, and how overlapping spans are
resolved. Fixture values are invented here; ids carry valid check digits, phone numbers use ranges reserved
for drama or invented area codes."""

import pytest

from pii_eraser import Eraser, Kind
from pii_eraser.detectors.gliner import GlinerDetector
from pii_eraser.detectors.validators import iban_span, ip_ok, nino_ok, steuer_id_ok, sv_nummer_ok


def found(text, eraser=None):
    eraser = eraser or Eraser.for_prose()
    return [(s.kind, text[s.start : s.end]) for s in eraser.detect(text)[0]]


def kinds(text):
    return {k for k, _ in found(text)}


# ---------------- validators


def test_steuer_id_check_digit_and_repetition_rule():
    assert steuer_id_ok("86095742719") and steuer_id_ok("86 095 742 719")
    assert not steuer_id_ok("86095742718")  # check digit
    assert not steuer_id_ok("06095742719")  # leading zero
    assert not steuer_id_ok("12345678903")  # no repeated digit


def test_sv_nummer_check_digit():
    assert sv_nummer_ok("15 070649 C 103") and sv_nummer_ok("15070649C103")
    assert not sv_nummer_ok("15 070649 C 104")
    assert not sv_nummer_ok("15 330649 C 103")  # no 33rd day


def test_nino_prefix_rules():
    assert nino_ok("AB 12 34 56 C") and nino_ok("AB123456C")
    assert not nino_ok("QQ123456C") and not nino_ok("GB123456A") and not nino_ok("AB123456E")


def test_ip_ok_skips_loopback_and_unspecified():
    assert ip_ok("192.0.2.17") and ip_ok("2001:db8:4f2a::17")
    assert not ip_ok("127.0.0.1") and not ip_ok("0.0.0.0") and not ip_ok("::1") and not ip_ok("300.1.1.1")


# ---------------- IBAN


IBAN_DE = "DE89 3704 0044 0532 0130 00"


def test_iban_printed_in_groups():
    assert found(f"IBAN: {IBAN_DE}, BIC COBADEFFXXX") == [(Kind.FINANCIAL, IBAN_DE)]


def test_iban_across_a_line_break():
    text = "IBAN DE89 3704 0044\n0532 0130 00 bitte"
    assert found(text) == [(Kind.FINANCIAL, "DE89 3704 0044\n0532 0130 00")]


def test_iban_registry_length_stops_before_a_following_number():
    text = f"{IBAN_DE} 2026"
    assert found(text) == [(Kind.FINANCIAL, IBAN_DE)]


def test_iban_with_ocr_confusions_is_read_back():
    assert iban_span("DE89 37O4 0044 O532 0l30 00") is not None
    assert iban_span("DE89 3704 0044 0532 0130 01") is None  # wrong check digits stay rejected


def test_iban_outranks_an_ner_guess_on_the_same_characters():
    ner = GlinerDetector(model=_Fake([{"text": IBAN_DE, "label": "bank_account", "score": 0.93, "start": 6}]))
    assert found(f"IBAN: {IBAN_DE}", Eraser.for_prose(ner)) == [(Kind.FINANCIAL, IBAN_DE)]


# ---------------- phone numbers


@pytest.mark.parametrize(
    "phone",
    ["030 23125057", "(069) 90009-311", "0172 / 9973185", "+49 (0)40 66969 559", "0049 69 90009311",
     "01729925904", "020 7946 0958", "(0117) 496 0823", "+44 20 7946 0958"],
)
def test_phone_formats(phone):
    assert found(f"Rückruf unter {phone}.") == [(Kind.PHONE, phone)]


@pytest.mark.parametrize("text", ["Abrechnung 01/2026 folgt", "Version 2.3.4", "Rechnung 4711 vom 3.5."])
def test_not_phones(text):
    assert Kind.PHONE not in kinds(text)


# ---------------- national ids


def test_german_ids():
    assert found("Steuer-ID 86 095 742 719, SV-Nr. 15 070649 C 103.") == [
        (Kind.NATIONAL_ID, "86 095 742 719"),
        (Kind.NATIONAL_ID, "15 070649 C 103"),
    ]
    assert found("Steuernummer 21/815/08150") == [(Kind.NATIONAL_ID, "21/815/08150")]


def test_eleven_digits_without_a_valid_check_digit_are_left():
    assert Kind.NATIONAL_ID not in kinds("Auftrag 86095742718 erledigt")


def test_nino_in_pairs():
    assert found("NI number AB 12 34 56 C") == [(Kind.NATIONAL_ID, "AB 12 34 56 C")]


# ---------------- IP addresses


def test_ip_addresses():
    assert found("Login von 192.0.2.17 und 2001:db8:4f2a::17.") == [
        (Kind.IP, "192.0.2.17"),
        (Kind.IP, "2001:db8:4f2a::17"),
    ]


@pytest.mark.parametrize("text", ["release v1.2.3.4", "version 1.2.3.4", "localhost 127.0.0.1", "um 12:30:45"])
def test_not_ip_addresses(text):
    assert Kind.IP not in kinds(text)


# ---------------- dates of birth


def test_dob_with_a_month_name_and_the_label_stays_readable():
    assert found("geb. 3. Juni 1970, Fahrer") == [(Kind.DOB, "3. Juni 1970")]
    assert found("Date of birth:      11 December 1983\n") == [(Kind.DOB, "11 December 1983")]
    assert found("birth date 7.5.2005 is accepted") == [(Kind.DOB, "7.5.2005")]


# ---------------- addresses


@pytest.mark.parametrize(
    "address",
    ["Lindenstraße 14, 93047 Regensburg", "Mariahilfer Straße 45\n1060 Wien", "Am Alten Markt 9c, 01067 Dresden",
     "Friedrich-Ebert-Allee 3 b · 18055 Rostock", "Bgm.-Smidt-Str. 17/2, 28195 Bremen",
     "Im Rosengarten 28 · 24103 Kiel", "Kleine Gasse 112-114 · 18055 Rostock"],
)
def test_dach_addresses(address):
    assert found(f"Anlieferung: {address}\n") == [(Kind.ADDRESS, address)]


def test_uk_address_line():
    text = "Send it to 37 Larch Gardens, Oxford OX1 1DP."
    assert found(text) == [(Kind.ADDRESS, "37 Larch Gardens, Oxford OX1 1DP")]


def test_address_fields_in_json_and_forms():
    assert found('{"plz": "99084", "town": "Erfurt"}') == [(Kind.ADDRESS, "99084"), (Kind.ADDRESS, "Erfurt")]
    assert found("PLZ:   70173\nOrt:   Münster\n") == [(Kind.ADDRESS, "70173"), (Kind.ADDRESS, "Münster")]


def test_number_and_noun_mid_sentence_is_not_an_address():
    assert Kind.ADDRESS not in kinds("Der Lauf verbrauchte 24816 Tokens und 1184 Pakete.")


# ---------------- names


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("Rückruf an Herrn Phạm erfolgt", "Phạm"),
        ("Sehr geehrte Frau Dr. Öztürk-Schneider,", "Öztürk-Schneider"),
        ("If Mr van den Berg no longer lives there", "van den Berg"),
        ("Einmalkennwort durchgegeben. – G. Benedetti\n", "G. Benedetti"),
        ("gez. H. Lindner\n", "H. Lindner"),
        ("Hello Priya, thanks for raising it", "Priya"),
        ("Danke\nShirin\n", "Shirin"),
        ("Raised by: Kovalenko, Dmytro (HR)", "Kovalenko, Dmytro"),
        ("Kontoinhaber: GISELA KÖNIG\n", "GISELA KÖNIG"),
        ("Verteiler: Papadopoulou, Eleni; de Vries, Pieter; Okafor, Ngozi\n", "Papadopoulou, Eleni"),
    ],
)
def test_names_in_context(text, name):
    assert (Kind.NAME, name) in found(text)


def test_team_signature_is_not_a_name():
    assert Kind.NAME not in kinds("Viele Grüße\nIhr Praxisteam\n")


def test_greeting_to_a_group_is_not_a_name():
    assert Kind.NAME not in kinds("Hi all, quick one.")


# ---------------- NER noise


class _Fake:
    def __init__(self, entities):
        self.entities = entities

    def predict_entities(self, text, labels, threshold):
        return [e for e in self.entities if e["text"] in text]


def _ner(*entities):
    return GlinerDetector(model=_Fake(list(entities)))


def test_ner_trade_after_an_article_is_not_a_person():
    text = "Morgen kommt der Bäcker, und Frau Bäcker zahlt."
    det = _ner({"text": "Bäcker", "label": "person", "score": 0.8, "start": 17})
    assert det.detect(text) == []


def test_ner_field_name_without_a_digit_is_not_a_value():
    text = "Bitte IBAN und Steuer-ID nachreichen"
    det = _ner(
        {"text": "IBAN", "label": "bank_account", "score": 0.9, "start": 6},
        {"text": "Steuer-ID", "label": "tax_id", "score": 0.9, "start": 15},
    )
    assert det.detect(text) == []


def test_ner_german_role_noun_is_not_a_person():
    det = _ner({"text": "Sachbearbeiterin", "label": "person", "score": 0.9, "start": 4})
    assert det.detect("Die Sachbearbeiterin meldet sich") == []


# ---------------- passwords in prose


def test_password_typed_into_a_ticket():
    assert found("Login mit Benutzer svc-deploy und Passwort Blau1827&nOn an.") == [(Kind.SECRET, "Blau1827&nOn")]
    assert found("my previous one was Winter7103?XN2 in case") == [(Kind.SECRET, "Winter7103?XN2")]


def test_password_rules_stay_out_of_the_code_profile():
    assert Eraser.for_code().erase('log("Passwort Blau1827&nOn")').found == []


def test_query_string_is_not_a_password():
    assert Kind.SECRET not in kinds("see https://example.org/a?b=C1d&e=F9x")


# ---------------- overlaps


def test_rules_that_agree_on_a_phone_mask_all_of_it():
    # phone_us_parens sees "117) 496 0823", phone_national the whole number
    assert found("call (0117) 496 0823 today") == [(Kind.PHONE, "(0117) 496 0823")]


def test_ner_edges_do_not_cut_a_rule_match_short():
    det = _ner({"text": "020 7946", "label": "phone_number", "score": 0.95, "start": 5})
    assert found("Tel. 020 7946 0040", Eraser.for_prose(det)) == [(Kind.PHONE, "020 7946 0040")]
