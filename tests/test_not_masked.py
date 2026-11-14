"""What stays readable, as listed in docs/not-masked.md. Rules only, no NER model. Values are invented;
the IBAN is the published example number.

A failure in `test_not_covered_today` is good news: a gap was closed. Take the row out of section 2 of
docs/not-masked.md and move the case to the tests of the rule that now finds it."""

import pytest

from pii_eraser import Eraser

CONNECTION = "DATABASE_URL=postgresql://svc_report:Xk9mQ2vLp8Zt@db-prod.intern.example:5432/billing"


def readable(text, value, eraser=None):
    """No character of `value` is masked."""
    eraser = eraser or Eraser.for_prose()
    start = text.index(value)
    end = start + len(value)
    return not any(s.start < end and start < s.end for s in eraser.detect(text)[0])


def masked(text, value, eraser=None):
    """Every character of `value` is masked."""
    eraser = eraser or Eraser.for_prose()
    start = text.index(value)
    covered = set()
    for span in eraser.detect(text)[0]:
        covered.update(range(span.start, span.end))
    return all(i in covered for i in range(start, start + len(value)))


# ---------------- section 1: left readable on purpose


@pytest.mark.parametrize(
    "text, value",
    [
        ("Die Frist endet am 15. Januar 2099.", "15. Januar 2099"),
        ("Liefertermin 03.02.2099 bestätigt.", "03.02.2099"),
        ("Der Vertrag läuft seit März 2021.", "März 2021"),
        ("Sie ist seit 1998 Kundin.", "1998"),
        ("Der Patient ist 47 Jahre alt.", "47"),
        ("Rückruf um 14:30 Uhr.", "14:30"),
        ("Offener Betrag 1.284,50 EUR.", "1.284,50"),
        (CONNECTION, "db-prod.intern.example:5432/billing"),
        (CONNECTION, "svc_report"),
        ("Der Schlüssel steht in STRIPE_SECRET_KEY.", "STRIPE_SECRET_KEY"),
        ("password = ${DB_PASSWORD}", "${DB_PASSWORD}"),
        ("token = os.environ['SECRET']", "os.environ['SECRET']"),
        ("Fehler in Anfrage req_011CSHoEeqs5C35K2UUqR7Fy.", "req_011CSHoEeqs5C35K2UUqR7Fy"),
        ("Vorgang 3f2b8c1e-9a4d-4e7f-b2a1-6c5d4e3f2a1b angelegt.", "3f2b8c1e-9a4d-4e7f-b2a1-6c5d4e3f2a1b"),
        ("Deploy von Commit 9fceb02d0ae598e95dc970b74767f19372d61af8.", "9fceb02d0ae598e95dc970b74767f19372d61af8"),
        ("Update auf Version 2.14.3.1 eingespielt.", "2.14.3.1"),
        ("Siehe https://portal.example.org/kunden/4711/akte", "https://portal.example.org/kunden/4711/akte"),
        ("Gerät 00:1A:2B:3C:4D:5E meldet sich nicht.", "00:1A:2B:3C:4D:5E"),
        ("Dienst lauscht auf 127.0.0.1 und 0.0.0.0.", "127.0.0.1 und 0.0.0.0"),
        ("Der Kunde hat sich beschwert.", "Kunde"),
        ("The contractor has not replied.", "contractor"),
        ("Die Leiterin Einkauf hat freigegeben.", "Leiterin Einkauf"),
        ("Der Lieferant sitzt in Portugal.", "Portugal"),
    ],
)
def test_left_readable_on_purpose(text, value):
    assert readable(text, value)


@pytest.mark.parametrize(
    "text, value",
    [
        ("Rechnung vom 12.03.2024 ist offen.", "12.03.2024"),  # a past date is masked without a label
        ("Geburtsdatum: 15.01.2099", "15.01.2099"),  # a birth label decides, whatever the year
        (CONNECTION, "Xk9mQ2vLp8Zt"),
        ("Client 10.42.7.19 getrennt.", "10.42.7.19"),  # private ranges are masked, only loopback is not
        ("Personalausweis: L01X00T471", "L01X00T471"),
        ("Sort code 20-45-77, account 43120987.", "43120987"),
    ],
)
def test_the_other_side_of_each_line_is_masked(text, value):
    assert masked(text, value)


# ---------------- section 2: not covered


@pytest.mark.parametrize(
    "text, value",
    [
        ("Diagnose: Diabetes mellitus Typ 2.", "Diabetes mellitus Typ 2"),
        ("Konfession: römisch-katholisch.", "römisch-katholisch"),
        ("Staatsangehörigkeit: ungarisch.", "ungarisch"),
        ("Geschlecht: weiblich.", "weiblich"),
        ("Rechnung RE-2024-00417 ist bezahlt.", "RE-2024-00417"),
        ("Bestellung 4500128834 wurde storniert.", "4500128834"),
        ("Ticket INC0048213 geschlossen.", "INC0048213"),
        ("Kundennummer 20481377 bitte angeben.", "20481377"),
        ("Personalnummer 004512 gesperrt.", "004512"),
        ("Das Fahrzeug M-AB 1234 steht im Hof.", "M-AB 1234"),
        ("USt-IdNr. DE123456789 der Firma.", "DE123456789"),
        ("Eingetragen unter HRB 123456 beim Amtsgericht.", "HRB 123456"),
        ("BIC COBADEFFXXX der Bank.", "COBADEFFXXX"),
        ("Benutzername: mkeller92", "mkeller92"),
        ("Sort code 20-45-77, account 43120987.", "20-45-77"),
        ("Versichertennummer A123456780 liegt vor.", "A123456780"),
        ("Reisepass-Nr.: C01X00T47", "C01X00T47"),
        ("Termin war am 12.03.24.", "12.03.24"),
        ("Kennzahl 12031984 im Feld.", "12031984"),
        ("Durchwahl 4412 wählen.", "4412"),
        ("Karte 5018123456784 belastet.", "5018123456784"),
        ("Er wohnt in der Lindenstraße.", "Lindenstraße"),
        ("Wir liefern nach 93047 Regensburg aus.", "93047 Regensburg"),
        ("Gestern hat Okafor die Liste geschickt.", "Okafor"),
        ("frag mal tamsin wegen dem export", "tamsin"),
        ("Die Nordlicht Logistik GmbH liefert morgen.", "Nordlicht Logistik GmbH"),
    ],
)
def test_not_covered_today(text, value):
    assert readable(text, value)


# ---------------- section 4: the code profile masks less


@pytest.mark.parametrize(
    "text, value",
    [
        ('HOST = "10.42.7.19"', "10.42.7.19"),
        ("# Rückruf unter 089 4412 9907", "089 4412 9907"),
        ("# Rechnung vom 12.03.2024", "12.03.2024"),
        ("# Lager: Tulpenweg 14, 54321 Beispielstadt", "Tulpenweg 14, 54321 Beispielstadt"),
        ("# Viele Grüße\n# Tamsin Ekwuazi", "Tamsin Ekwuazi"),
        ("# das Passwort lautet Xk9mQ2vLp8Zt", "Xk9mQ2vLp8Zt"),
    ],
)
def test_code_profile_leaves_readable_what_the_prose_profile_masks(text, value):
    assert readable(text, value, Eraser.for_code())
    assert masked(text.replace("# ", ""), value, Eraser.for_prose())


@pytest.mark.parametrize(
    "text, value",
    [
        ('MAIL = "t.ekwuazi@example.org"', "t.ekwuazi@example.org"),
        (f'URL = "{CONNECTION}"', "Xk9mQ2vLp8Zt"),
        ("# author: Frau Ekwuazi-Brandt", "Ekwuazi-Brandt"),
        ("# Geburtsdatum: 12.03.1984", "12.03.1984"),
        ('IBAN = "DE89370400440532013000"', "DE89370400440532013000"),
    ],
)
def test_code_profile_still_masks(text, value):
    assert masked(text, value, Eraser.for_code())
