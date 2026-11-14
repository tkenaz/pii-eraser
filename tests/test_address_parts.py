"""An address found in pieces is masked as one address, with what is printed between its pieces. Street and
town names are invented; postcodes are in ranges of the towns' countries."""

import pytest

from pii_eraser import Eraser, Kind
from pii_eraser.address_parts import join_address_parts
from pii_eraser.types import Span


def addresses(text):
    return [text[s.start : s.end] for s in Eraser.for_prose().detect(text)[0] if s.kind is Kind.ADDRESS]


def piece(text, value, kind=Kind.ADDRESS, confidence=0.8):
    start = text.index(value)
    return Span(start=start, end=start + len(value), text=value, kind=kind, confidence=confidence, source="test:piece")


def joined(text, *values):
    return [s.text for s in join_address_parts(text, [piece(text, v) for v in values])]


@pytest.mark.parametrize(
    "between",
    [", ", " – ", " | ", " in ", "\n", ", D-", " Hs. 2, ", " Hs. 2 – ", "/2/9 in ", " HH, ", " a\n", " Top 4, A-"],
)
def test_street_and_town_with_filling_between_them_are_one_address(between):
    text = f"Anschrift: Tulpenweg 14{between}54321 Beispielstadt gilt ab Mai."
    assert joined(text, "Tulpenweg 14", "54321 Beispielstadt") == [f"Tulpenweg 14{between}54321 Beispielstadt"]


@pytest.mark.parametrize("between", [
        " und ",
        ". Neu: ",
        "; ",
        " (alt), jetzt ",
        " oder im Büro, ",
        "\n\n\n",
        ", 1, 2, 3, 4, 5, 6, 7, ",  # filling, but more of it than stands inside one address
        ", Donaudampfschifffahrtsgesellschaft Kapitänsmützenfabrik, ",  # capitalised words, too many letters
    ],
)
def test_two_addresses_with_words_between_them_stay_two(between):
    text = f"Tulpenweg 14{between}54321 Beispielstadt"
    assert joined(text, "Tulpenweg 14", "54321 Beispielstadt") == ["Tulpenweg 14", "54321 Beispielstadt"]


def test_town_line_between_street_and_postcode():
    text = "12 Fernbank Lane\nMarlowick\nMK1 4ZZ\n\nDear customer"
    assert joined(text, "12 Fernbank Lane", "MK1 4ZZ") == ["12 Fernbank Lane\nMarlowick\nMK1 4ZZ"]


def test_named_part_between_two_pieces_on_one_line():
    text = "Rosebank, Fernbank Lane, MARLOWICK, MK1 4ZZ"
    assert joined(text, "Rosebank", "MARLOWICK", "MK1 4ZZ") == [text]


def test_a_sentence_between_two_pieces_is_not_a_named_part():
    text = "12 Fernbank Lane, please note the change, MK1 4ZZ"
    assert joined(text, "12 Fernbank Lane", "MK1 4ZZ") == ["12 Fernbank Lane", "MK1 4ZZ"]


def test_other_kinds_are_not_joined_and_not_run_over():
    text = "Tulpenweg 14, 030 1234567, 54321 Beispielstadt"
    spans = [piece(text, "Tulpenweg 14"), piece(text, "030 1234567", Kind.PHONE), piece(text, "54321 Beispielstadt")]
    assert [s.text for s in join_address_parts(text, spans)] == ["Tulpenweg 14", "030 1234567", "54321 Beispielstadt"]


@pytest.mark.parametrize(
    "found, rest",
    [
        ("9000 St", ". Gallen"),
        ("61348 Bad Homburg", " v. d. Höhe"),
        ("54321 Beispielstadt", ", Deutschland"),
        ("MK1 4ZZ", ", United Kingdom"),
        ("6900 Lugano", ", Schweiz"),
    ],
)
def test_address_runs_on_over_the_rest_of_the_town_and_the_country(found, rest):
    text = f"Sitz: {found}{rest}\nTelefon folgt"
    assert joined(text, found) == [found + rest]


def test_address_does_not_run_on_into_the_sentence():
    text = "Wir sind in 54321 Beispielstadt, Deutschlandweit bekannt, und a. D. Meier grüßt."
    assert joined(text, "54321 Beispielstadt") == ["54321 Beispielstadt"]


# ---------------- through the prose profile


@pytest.mark.parametrize(
    "value",
    [
        "Tulpenweg 14 Hs. 2 – 54321 Beispielstadt",
        "Tulpenweg 14 in 54321 Beispielstadt",
        "Tulpenweg 14 | 54321 Beispielstadt",
        "Tulpenweg 14, 54321 Beispielstadt, Deutschland",
        "Untere Tulpengasse 3, 54321 Beispielstadt",
        "Karl-von-Muster-Allee 41a\n54321 Beispielstadt",
        "Straße des Aufbruchs 11c, 54321 Beispielstadt",
        "Via alla Fontana 6, 6900 Lugano",
        "Rue du Vieux Moulin 7\n1204 Genève",
    ],
)
def test_whole_address_is_masked(value):
    assert addresses(f"Neue Anschrift:\n{value}\n\nBitte bestätigen.") == [value]


def test_flat_number_before_a_uk_street_belongs_to_the_address():
    value = "Flat 24, 12 Fernbank Lane, Marlowick, MK1 4ZZ"
    assert addresses(f"Send it to {value} please.") == [value]


@pytest.mark.parametrize("value", ["mk1 4zz", "le2 7qq", "ab10 1xg"])
def test_uk_postcode_in_lower_case(value):
    assert addresses(f"postcode;{value};ok") == [value]


def test_lower_case_words_that_look_like_a_postcode_are_not_one():
    assert addresses("meet at pm2 5am or fx1 2go, id zz9 9zz") == []


def test_street_takes_the_postcode_and_town_after_it():
    text = "wohnhaft Tulpenweg 14 Hs. 2 – 54321 Beispielstadt, Fahrzeug folgt"
    assert joined(text, "Tulpenweg 14") == ["Tulpenweg 14 Hs. 2 – 54321 Beispielstadt"]


def test_street_does_not_take_an_amount_or_a_year_for_a_town():
    for text in ("Tulpenweg 14, 5000 Euro Kaution", "Tulpenweg 14 und 2024 Anträge", "Tulpenweg 14. 54321 Beispielstadt"):
        assert joined(text, "Tulpenweg 14") == ["Tulpenweg 14"]


def test_only_a_span_that_ends_in_a_house_number_takes_a_town():
    text = "Postfach Musterhof, 54321 Beispielstadt"
    assert joined(text, "Musterhof") == ["Musterhof"]


def test_address_tail_stops_at_the_next_span():
    text = "Sitz: 54321 Beispielstadt, Deutschland GmbH"
    spans = [piece(text, "54321 Beispielstadt"), piece(text, "Deutschland GmbH", Kind.NAME)]
    assert [s.text for s in join_address_parts(text, spans)] == ["54321 Beispielstadt", "Deutschland GmbH"]
