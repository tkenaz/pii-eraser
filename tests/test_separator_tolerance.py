"""A value with a check digit is the same value however it is printed: with blanks, no-break spaces, hyphens,
dots or slashes between its groups, in any grouping, in lower case. The check digit proves it, so the rules
do not list print layouts. The values are invented here and carry valid check digits. Several layouts were first
seen among the misses on evaluation corpus v2 (hyphens and no-break spaces in IBANs and cards, ids with dots),
which is why v2 is a development set from here on and proves nothing about this code."""

import pytest

from pii_eraser import Eraser, Kind
from pii_eraser.detectors.validators import card_span, iban_printed_span, iban_span, luhn_ok, single_separator

NBSP = " "


def found(text, eraser=None):
    eraser = eraser or Eraser.for_prose()
    return [(s.kind, text[s.start : s.end]) for s in eraser.detect(text)[0]]


def regroup(compact, sizes, sep):
    out, i = [], 0
    for n in sizes:
        out.append(compact[i : i + n])
        i += n
    assert i == len(compact)
    return sep.join(out)


# ---------------- IBAN

IBAN_DE = "DE17138978270736206986"
IBAN_NO = "NO1764337289353"
IBAN_AT = "AT656741295276291321"
IBAN_NL = "NL34ABNA5825274226"
FOURS_DE = (4, 4, 4, 4, 4, 2)


@pytest.mark.parametrize("sep", [" ", NBSP, "-", ".", " "])
def test_iban_in_groups_of_four_with_any_separator(sep):
    value = regroup(IBAN_DE, FOURS_DE, sep)
    assert found(f"Bankverbindung {value} bitte merken") == [(Kind.FINANCIAL, value)]


@pytest.mark.parametrize("sizes", [(4, 8, 10), (22,), (4, 4, 4, 4, 6), (4, 2, 4, 4, 4, 4)])
def test_iban_in_any_grouping(sizes):
    value = regroup(IBAN_DE, sizes, " ")
    assert found(f"auf {value} überweisen") == [(Kind.FINANCIAL, value)]


def test_iban_in_lower_case():
    value = regroup(IBAN_DE.lower(), FOURS_DE, " ")
    assert found(f"konto: {value}") == [(Kind.FINANCIAL, value)]


def test_iban_with_a_short_last_group_and_letters_in_the_account():
    no = regroup(IBAN_NO, (4, 4, 4, 3), "-")
    nl = regroup(IBAN_NL, (4, 4, 4, 4, 2), NBSP)
    assert found(f"{no} oder {nl}") == [(Kind.FINANCIAL, no), (Kind.FINANCIAL, nl)]


def test_iban_does_not_swallow_the_number_after_it():
    value = regroup(IBAN_AT, (4, 4, 4, 4, 4), " ")
    assert found(f"{value} 4711 Stück") == [(Kind.FINANCIAL, value)]


def test_iban_between_table_columns():
    value = regroup(IBAN_DE, FOURS_DE, "-")
    assert (Kind.FINANCIAL, value) in found(f"K-1\t{value}\t12,50\n")
    assert (Kind.FINANCIAL, value) in found(f'"K-1","{value}","12,50"\n')


def test_iban_with_a_wrong_check_digit_is_still_masked_when_printed_as_an_iban():
    wrong = regroup(IBAN_DE[:-1] + "7", FOURS_DE, " ")
    assert found(f"Empfänger siehe {wrong} laut Vertrag") == [(Kind.FINANCIAL, wrong)]


def test_iban_with_a_wrong_check_digit_is_masked_after_its_label():
    wrong = IBAN_DE[:-1] + "7"
    assert (Kind.FINANCIAL, wrong) in found(f"IBAN: {wrong}")


def test_a_wrong_check_digit_without_groups_or_label_is_not_an_iban():
    wrong = IBAN_DE[:-1] + "7"
    assert found(f"Referenz {wrong} im Protokoll") == []


def test_words_after_a_country_code_are_not_an_iban():
    assert found("NO12 people came, IT19 was the room, DE22 of them left") == []


# ---------------- payment cards

CARDS = {
    "mastercard 2-series": ("2221595837725710", (4, 4, 4, 4)),
    "jcb": ("3528873785439974", (4, 4, 4, 4)),
    "diners": ("36793065366286", (4, 6, 4)),
    "discover": ("6011485520162766", (4, 4, 4, 4)),
    "unionpay 19": ("6211372832894471005", (4, 4, 4, 4, 3)),
    "visa": ("4451752024017743", (4, 4, 4, 4)),
    "amex": ("377489163545049", (4, 6, 5)),
    "maestro": ("5893809844222623", (4, 4, 4, 4)),
}


@pytest.mark.parametrize("scheme", sorted(CARDS))
@pytest.mark.parametrize("sep", ["", " ", NBSP, "-"])
def test_card_of_any_scheme_with_any_separator(scheme, sep):
    compact, sizes = CARDS[scheme]
    value = regroup(compact, sizes, sep)
    assert found(f"bezahlt mit {value}, Beleg folgt") == [(Kind.FINANCIAL, value)]


def test_card_across_a_line_break():
    value = "6011 4855\n2016 2766"
    assert found(f"Karte {value}\nDanke") == [(Kind.FINANCIAL, value)]


def test_card_next_to_other_numbers_in_a_table_row():
    card = regroup(CARDS["jcb"][0], (4, 4, 4, 4), " ")
    assert (Kind.FINANCIAL, card) in found(f"| 12 | {card} | 29.99 |")
    assert (Kind.FINANCIAL, card) in found(f"({card})")


def test_card_followed_by_a_number_is_cut_at_its_length():
    card = regroup(CARDS["visa"][0], (4, 4, 4, 4), " ")
    assert card_span(card + " 12") == len(card)


def test_digits_that_fail_luhn_are_not_a_card():
    compact = CARDS["discover"][0]
    wrong = compact[:-1] + str((int(compact[-1]) + 1) % 10)
    assert not luhn_ok(wrong)
    assert found(f"Vorgang {wrong} abgeschlossen") == []


def test_luhn_valid_digits_outside_every_card_range_are_not_a_card():
    body = "1794635675500" + "12"  # 15 digits starting with 1: no scheme issues these
    check = next(c for c in "0123456789" if luhn_ok(body + c))
    assert found(f"trace {body + check} done") == []


def test_card_separators_must_agree():
    compact = CARDS["jcb"][0]
    mixed = f"{compact[:4]} {compact[4:8]}-{compact[8:12]}.{compact[12:]}"
    assert card_span(mixed) is None


def test_single_separator():
    assert single_separator("12 34 56") and single_separator("12-34-56") and single_separator("123456")
    assert single_separator("12 34\n56")  # a line break is white space
    assert not single_separator("12 34-56") and not single_separator("12.34/56")


# ---------------- German tax id and pension insurance number, UK NI number

STEUER_ID = "25763191046"
SV_NUMMER = "05271059P433"


@pytest.mark.parametrize(
    "value",
    [
        regroup(STEUER_ID, (2, 3, 3, 3), NBSP),
        regroup(STEUER_ID, (2, 3, 3, 3), "-"),
        regroup(STEUER_ID, (2, 3, 3, 3), "."),
        regroup(STEUER_ID, (2, 3, 6), "/"),
        regroup(STEUER_ID, (3, 3, 3, 2), " "),
        " ".join(STEUER_ID),
        STEUER_ID,
    ],
)
def test_steuer_id_in_any_print_layout(value):
    assert found(f"IdNr;{value};gültig") == [(Kind.NATIONAL_ID, value)]


def test_steuer_id_with_a_wrong_check_digit_is_not_found():
    wrong = regroup(STEUER_ID[:-1] + "7", (2, 3, 3, 3), "-")
    assert found(f"Wert;{wrong};ok") == []


def test_steuer_id_is_not_cut_out_of_a_longer_number():
    assert found(f"Zähler {STEUER_ID}7 abgelesen") == []
    assert found(f"Zähler 9 {' '.join(STEUER_ID)} abgelesen") == []


@pytest.mark.parametrize(
    "value",
    [
        "05-271059-P-433",
        "05/271059/P/433",
        "05 27 10 59 P 433",
        f"05{NBSP}271059{NBSP}P{NBSP}433",
        "05271059p433",
    ],
)
def test_sv_nummer_in_any_print_layout(value):
    assert found(f"RV-Nr;{value};ok") == [(Kind.NATIONAL_ID, value)]


def test_sv_nummer_with_a_wrong_check_digit_is_not_found():
    assert found("RV-Nr;05-271059-P-434;ok") == []


@pytest.mark.parametrize("value", ["AB-12-34-56-C", "AB.12.34.56.C", f"AB{NBSP}12{NBSP}34{NBSP}56{NBSP}C"])
def test_ni_number_with_any_separator(value):
    assert found(f"NI no;{value};ok") == [(Kind.NATIONAL_ID, value)]


# ---------------- white space and e-mail


@pytest.mark.parametrize(
    "text",
    [
        "Rückruf unter +49 (0)30 23125 778 erbeten",
        "IBAN: DE17 1389 7827 0736 2069 86",
        "geboren am 3. Mai 1961 in Kassel",
        "Musterweg 12, 34117 Kassel",
    ],
)
def test_no_break_spaces_are_read_as_spaces(text):
    plain = Eraser.for_prose().detect(text)[0]
    assert plain, "the sample must be detected with ordinary spaces"
    nbsp = Eraser.for_prose().detect(text.replace(" ", NBSP))[0]
    assert [(s.kind, s.start, s.end) for s in nbsp] == [(s.kind, s.start, s.end) for s in plain]
    assert all(NBSP in s.text or " " not in text[s.start : s.end] for s in nbsp)  # the span carries the original


@pytest.mark.parametrize(
    "value",
    ["petra.muster@bücherei-beispiel.de", "jörg_meier+rechnung@bäckerei-süd.example", "łukasz@żółw.example"],
)
def test_email_with_letters_beyond_ascii(value):
    assert found(f"Mail an {value}.") == [(Kind.EMAIL, value)]


# ---------------- what a check digit does not prove (counter-examples from review)


@pytest.mark.parametrize(
    "text",
    [
        "[[2 5 7 4 5 0 5 6 3 6 3 7 3 3 9 1 5 0 8 6]]",
        "Antworten: 5 1 2 1 4 2 2 1 1 3 4 3 1 1 2 5 1 5 4 2",
        "639 273 446 319\n615 213 224 421\n723 462 239 617",
        "\n".join("4512345678901234"),
        "31 45 62 18 27 53 44 61 29 35 47 52",
    ],
)
def test_rows_and_columns_of_small_numbers_are_not_cards(text):
    assert found(text) == [] and found(text, Eraser.for_code()) == []


def test_every_card_layout_passes_and_no_other():
    compact = CARDS["visa"][0]
    assert card_span(regroup(compact, (4, 4, 4, 4), " ")) and card_span(regroup(compact, (4, 4, 4, 4), "-"))
    for sizes in [(1,) * 16, (2,) * 8, (3, 3, 3, 3, 4), (8, 8), (4, 4, 8), (5, 5, 6)]:
        assert card_span(regroup(compact, sizes, " ")) is None, sizes


def test_a_longer_number_is_not_cut_down_to_a_card():
    body = CARDS["visa"][0] + "47"  # 18 digits: Visa issues 13, 16 and 19
    assert found(f"Sendungsnummer {body}7 unterwegs") == []
    assert found(f"Sendungsnummer {body + '12345'} unterwegs") == []
    assert card_span(CARDS["unionpay 19"][0] + "4") is None


def test_card_before_a_quantity_is_the_card_alone():
    card = regroup(CARDS["visa"][0], (4, 4, 4, 4), " ")
    assert found(f"Karte {card} 1224 Stück") == [(Kind.FINANCIAL, card)]


@pytest.mark.parametrize("line", ["1,{c},12.50", "1;{c};12.50", "Visa/{c}", '"{c}"'])
def test_card_in_a_csv_field(line):
    compact = CARDS["visa"][0]
    for value in (compact, regroup(compact, (4, 4, 4, 4), "-")):
        assert (Kind.FINANCIAL, value) in found("id,card,amount\n" + line.format(c=value))


@pytest.mark.parametrize(
    "uuid",
    ["c7b0c07a-e253-49da-be86-839bde82f0e5", "be427dbc-677e-42e6-a553-083cae9dedf2", "0f8fad5b-d9cb-469f-a165-70867728950e"],
)
def test_uuid_is_not_an_iban(uuid):
    text = f'request_id = "{uuid}"'
    assert found(text) == [] and found(text, Eraser.for_code()) == []


def test_iban_cut_where_its_own_separator_goes_on_is_not_an_iban():
    value = regroup(IBAN_DE, FOURS_DE, "-")
    assert iban_span(value) == len(value)
    assert iban_span(value + "-4a7f") is None
    assert iban_span(regroup(IBAN_DE, FOURS_DE, "-") + " 4a7f") == len(value)


def test_iban_groups_must_be_divided_the_same_way():
    assert iban_span(f"{IBAN_DE[:4]} {IBAN_DE[4:8]}-{IBAN_DE[8:12]}.{IBAN_DE[12:]}") is None


@pytest.mark.parametrize("text", ["Bestellung 5112 3456 7890 1234 567", "Ref 8E12 3456 7890 1234", "Los SI12 abcd efgh ijkl mno"])
def test_without_check_digits_a_number_or_a_word_run_is_not_an_iban(text):
    assert found(text) == []
    assert iban_printed_span(text.split(" ", 1)[1]) is None
