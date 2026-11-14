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


# ---------------- second review: a list of addresses is a list


@pytest.mark.parametrize("between", ["\n", ", ", " | ", ", Berlin Mitte, "])
def test_two_streets_are_two_addresses(between):
    text = f"Kunden: Tulpenweg 14{between}Nelkenweg 4{between}Asternring 3"
    assert joined(text, "Tulpenweg 14", "Nelkenweg 4", "Asternring 3") == ["Tulpenweg 14", "Nelkenweg 4", "Asternring 3"]
    assert len(addresses(text)) == 3


def test_what_follows_a_postcode_is_the_next_address():
    text = "Tulpenweg 14, 54321 Beispielstadt\nNelkenweg 4, 54322 Anderstadt\n"
    assert addresses(text) == ["Tulpenweg 14, 54321 Beispielstadt", "Nelkenweg 4, 54322 Anderstadt"]
    assert joined("54321 Beispielstadt, 54322 Anderstadt", "54321 Beispielstadt", "54322 Anderstadt") == [
        "54321 Beispielstadt",
        "54322 Anderstadt",
    ]


def test_address_over_two_lines_restores_to_itself():
    text = "Neue Anschrift:\nTulpenweg 14\n54321 Beispielstadt\n\nEnde"
    session = Eraser.for_prose().session()
    erased = session.erase(text).text
    assert "Tulpenweg" not in erased and session.restore(erased) == text


def test_a_year_after_in_is_not_an_austrian_postcode():
    text = "Gartenweg 3 in 2019 Neubau"
    assert joined(text, "Gartenweg 3") == ["Gartenweg 3"]
    text = "Gartenweg 3 in 2340 Musterdorf"
    assert joined(text, "Gartenweg 3") == [text]


def test_town_after_a_street_is_not_followed_by_a_sentence():
    text = "Tulpenweg 14, 54321 Beispielstadt liegt am Fluss"
    assert joined(text, "Tulpenweg 14") == ["Tulpenweg 14"]


def test_street_takes_a_town_on_the_next_line_but_not_two_lines_down():
    assert joined("Tulpenweg 14\n54321 Beispielstadt", "Tulpenweg 14") == ["Tulpenweg 14\n54321 Beispielstadt"]
    assert joined("Tulpenweg 14\n\n54321 Beispielstadt", "Tulpenweg 14") == ["Tulpenweg 14"]


def test_town_after_filling_longer_than_an_address_has_is_not_taken():
    text = "Tulpenweg 14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 54321 Beispielstadt"
    assert joined(text, "Tulpenweg 14") == ["Tulpenweg 14"]


def test_named_part_of_more_than_four_words_is_a_sentence():
    text = "Rosebank, Old Mill Lane North Side Upper, MK1 4ZZ"
    assert joined(text, "Rosebank", "MK1 4ZZ") == ["Rosebank", "MK1 4ZZ"]


def test_joined_address_keeps_the_source_of_its_surer_piece():
    text = "Tulpenweg 14, 54321 Beispielstadt"
    spans = [piece(text, "Tulpenweg 14", confidence=0.6), piece(text, "54321 Beispielstadt", confidence=0.9)]
    spans[0] = Span(spans[0].start, spans[0].end, spans[0].text, Kind.ADDRESS, 0.6, "test:weak")
    (one,) = join_address_parts(text, spans)
    assert (one.confidence, one.source) == (0.9, "test:piece")


def test_town_tail_needs_its_dot():
    assert joined("Sitz: 9000 St Gallenstein AG", "9000 St") == ["9000 St"]
