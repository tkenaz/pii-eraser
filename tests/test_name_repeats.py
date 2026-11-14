"""A name found once in a text is the same name everywhere in that text: the first name on its own three
paragraphs later, the surname in capitals in a table, "Surname, Given" in a list. All names are invented."""

from pii_eraser import Eraser, Kind
from pii_eraser.repeats import join_name_parts, repeat_names
from pii_eraser.types import Span


def names(text, eraser=None):
    eraser = eraser or Eraser.for_prose()
    return [text[s.start : s.end] for s in eraser.detect(text)[0] if s.kind is Kind.NAME]


def seed(text, value, confidence=0.9, kind=Kind.NAME):
    start = text.index(value)
    return Span(start=start, end=start + len(value), text=value, kind=kind, confidence=confidence, source="test:seed")


def repeats(text, *seeds):
    return [text[s.start : s.end] for s in repeat_names(text, list(seeds))]


def test_first_name_alone_after_the_full_name():
    text = "Teilnehmer: Frau Tamsin Ekwuazi-Brandt\n\nTamsin schickt die Liste bis Freitag. Danach prüft Tamsin die Zahlen."
    assert repeats(text, seed(text, "Tamsin Ekwuazi-Brandt")) == ["Tamsin", "Tamsin"]


def test_surname_alone_and_in_capitals():
    text = "Mr Ferran Quistgaard called. Quistgaard wants a refund.\nHOLDER: QUISTGAARD"
    assert repeats(text, seed(text, "Ferran Quistgaard")) == ["Quistgaard", "QUISTGAARD"]


def test_inverted_name_in_a_table_is_one_span():
    text = "Ansprechpartnerin Ilse Wöhrmann\n4711\tWöhrmann, Ilse\t12,50"
    assert repeats(text, seed(text, "Ilse Wöhrmann")) == ["Wöhrmann, Ilse"]


def test_genitive_and_possessive():
    text = "Herr Ludger Pfannenstiel fehlt. Pfannenstiels Vertretung und Ludger's notes."
    assert repeats(text, seed(text, "Ludger Pfannenstiel")) == ["Pfannenstiels", "Ludger's"]


def test_accents_are_folded():
    text = "Kontakt Zdeněk Hrubý, später nur noch Zdenek oder HRUBY."
    assert repeats(text, seed(text, "Zdeněk Hrubý")) == ["Zdenek", "HRUBY"]


def test_particles_and_titles_are_not_names():
    text = "Frau Dr. Wilhelmina van der Heyden kam. Der Bus von Frau Roth fuhr, und Dr. Roth wartete."
    assert repeats(text, seed(text, "Frau Dr. Wilhelmina van der Heyden")) == []


def test_particle_before_a_repeated_surname_is_taken_along():
    text = "Wilhelmina van der Heyden kam. Später rief van der Heyden an."
    assert repeats(text, seed(text, "Wilhelmina van der Heyden")) == ["van der Heyden"]


def test_lower_case_word_is_not_a_repeat():
    text = "Ms Rose Hartwell sat down. A rose stood on the table; Hartwell smiled."
    assert repeats(text, seed(text, "Rose Hartwell")) == ["Hartwell"]


def test_part_of_a_longer_word_is_not_a_repeat():
    text = "Herr Bernd Stein grüßt. Der Steinbruch und die Bernsteinkette bleiben."
    assert repeats(text, seed(text, "Bernd Stein")) == []


def test_what_is_already_masked_is_left_alone():
    text = "Tamsin Ekwuazi schrieb an tamsin.okonkwo@example.org, Tamsin wartet."
    mail = seed(text, "tamsin.okonkwo@example.org", kind=Kind.EMAIL)
    assert repeats(text, seed(text, "Tamsin Ekwuazi"), mail) == ["Tamsin"]


def test_a_weak_guess_is_not_spread():
    text = "Der Maler kommt morgen. Maler und Lackierer gesucht."
    assert repeats(text, seed(text, "Maler", confidence=0.35)) == []


def test_short_words_are_not_spread():
    text = "Li Wu kam. Li ist da."
    assert repeats(text, seed(text, "Li Wu")) == []


def test_only_names_are_spread():
    text = "Wohnhaft Lindenweg 4 in Lindenweg."
    assert repeats(text, seed(text, "Lindenweg 4", kind=Kind.ADDRESS)) == []


def test_prose_profile_spreads_names_found_by_rules():
    text = "Sehr geehrte Frau Ekwuazi-Brandt,\n\nwie besprochen.\n\nNotiz: Ekwuazi-Brandt ruft Dienstag zurück."
    found = names(text)
    assert found.count("Ekwuazi-Brandt") == 2


def test_code_profile_does_not_spread_names():
    text = "# author: Frau Ekwuazi-Brandt\nclass EkwuaziBrandt:\n    Ekwuazi = 1\n"
    spans = Eraser.for_code().detect(text)[0]
    assert not any(s.source.startswith("repeat:") for s in spans)


def test_surname_that_is_a_noun_is_not_taken_after_an_article():
    text = "Herr Anselm Becker kam. Der Brief ging an den Becker, der Becker schwieg. Dann rief Becker an."
    assert repeats(text, seed(text, "Anselm Becker")) == ["Becker"]


def test_surname_that_is_a_season_or_a_month():
    text = "Herr Jonas Winter kommt im Winter. Der Winter wird kalt. Winter bestätigt den Termin."
    assert repeats(text, seed(text, "Jonas Winter")) == ["Winter"]
    text = "Ms April Hartwell joins in April 2026. April is busy, says Hartwell."
    assert repeats(text, seed(text, "April Hartwell")) == ["Hartwell"]


def test_names_read_from_fields_and_signature_blocks_are_not_spread():
    text = "Kontakt: Stadtwerke Musterhausen\nDie Stadtwerke liefern nach Musterhausen."
    start = text.index("Stadtwerke Musterhausen")
    for source in ("pii:name_field", "pii:name_signature_by", "pii:name_party_preamble", "pii:name_dear", "pii:name_label"):
        field = Span(start=start, end=start + 23, text="Stadtwerke Musterhausen", kind=Kind.NAME, confidence=0.9, source=source)
        assert repeats(text, field) == []


def test_a_title_before_the_name_proves_a_person():
    text = "Frau Tamsin Ekwuazi schrieb.\nTamsin wartet."
    start = text.index("Tamsin Ekwuazi")
    titled = Span(start=start, end=start + 14, text="Tamsin Ekwuazi", kind=Kind.NAME, confidence=0.9, source="pii:name_titled")
    assert repeats(text, titled) == ["Tamsin"]


def test_seed_at_the_confidence_bar_counts():
    text = "Tamsin Ekwuazi schrieb. Tamsin wartet."
    assert repeats(text, seed(text, "Tamsin Ekwuazi", confidence=0.5)) == ["Tamsin"]
    assert repeats(text, seed(text, "Tamsin Ekwuazi", confidence=0.49)) == []


def test_lower_case_letter_and_dot_is_not_an_initial():
    text = "Ms Oksana Lysenkova chairs. See p. Lysenkova and vs. Lysenkova."
    assert repeats(text, seed(text, "Oksana Lysenkova")) == ["Lysenkova", "Lysenkova"]


def test_particle_in_capitals_is_a_name_word():
    text = "ANTRAGSTELLERIN: DE LUCA MARTINELLI\nFrau Martinelli und Herr Luca warten."
    assert repeats(text, seed(text, "DE LUCA MARTINELLI")) == ["Martinelli", "Luca"]
    text = "Herr Bruno De Luca-Martinelli kam. Später de Luca-Martinelli allein."
    assert repeats(text, seed(text, "Bruno De Luca-Martinelli")) == ["de Luca-Martinelli"]


def test_two_surnames_side_by_side_keep_their_placeholders():
    text = "Herr Anselm Becker und Frau Tamsin Ekwuazi.\n| Becker Ekwuazi | 3 |\n| Ekwuazi | 3 |"
    assert repeats(text, seed(text, "Anselm Becker"), seed(text, "Tamsin Ekwuazi")) == ["Becker", "Ekwuazi", "Ekwuazi"]
    result = Eraser.for_prose().erase(text)
    assert len([p for p in result.mapping if p.startswith("[NAME_")]) == 2


def test_initial_before_a_repeated_surname_is_taken_along():
    text = "Ms Oksana Lysenkova chairs. Minutes: O. Lysenkova opens, then I.O. Lysenkova closes."
    assert repeats(text, seed(text, "Oksana Lysenkova")) == ["O. Lysenkova", "I.O. Lysenkova"]


def test_short_name_word_counts_only_next_to_a_longer_one():
    text = "Mme Maëlys Le Bihan schreibt. Le Bihan ist dagegen. Le Monde berichtet."
    assert repeats(text, seed(text, "Maëlys Le Bihan")) == ["Le Bihan"]


def test_a_list_of_people_is_not_joined_by_its_commas():
    text = "Herr Anselm Becker und Frau Tamsin Ekwuazi. Anwesend: Becker, Ekwuazi"
    assert repeats(text, seed(text, "Anselm Becker"), seed(text, "Tamsin Ekwuazi")) == ["Becker", "Ekwuazi"]


def test_organisations_and_places_found_by_the_model_are_not_spread():
    text = "Our German entity pays. The German payroll continues."
    org = Span(start=4, end=17, text="German entity", kind=Kind.NAME, confidence=0.9, source="gliner:organization")
    assert repeats(text, org) == []


def test_name_parts_found_separately_become_one_span():
    text = "Kontakt: Ilse Wöhrmann\n4711\tWöhrmann, Ilse\t12,50"
    row = text.index("Wöhrmann, Ilse")
    parts = [
        seed(text, "Ilse Wöhrmann"),
        Span(start=row, end=row + 8, text="Wöhrmann", kind=Kind.NAME, confidence=0.6, source="gliner:person"),
        Span(start=row + 10, end=row + 14, text="Ilse", kind=Kind.NAME, confidence=0.8, source="test:rule"),
    ]
    assert [s.text for s in join_name_parts(text, parts)] == ["Ilse Wöhrmann", "Wöhrmann, Ilse"]


def test_two_people_separated_by_a_comma_stay_two_spans():
    text = "Anselm Becker\nTamsin Ekwuazi\nBecker, Ekwuazi"
    row = text.index("Becker, Ekwuazi")
    parts = [
        seed(text, "Anselm Becker"),
        seed(text, "Tamsin Ekwuazi"),
        Span(start=row, end=row + 6, text="Becker", kind=Kind.NAME, confidence=0.7, source="repeat:name"),
        Span(start=row + 8, end=row + 15, text="Ekwuazi", kind=Kind.NAME, confidence=0.7, source="repeat:name"),
    ]
    assert [s.text for s in join_name_parts(text, parts)][2:] == ["Becker", "Ekwuazi"]


def test_a_repeat_never_runs_into_a_span_that_starts_inside_the_word():
    text = "Frau Ekwuazi-Brandt schrieb. Lieferung an Ekwuazi-Brandt 5."
    street = text.index("Brandt 5")
    spans = [
        seed(text, "Ekwuazi-Brandt"),
        Span(start=street, end=street + 8, text="Brandt 5", kind=Kind.ADDRESS, confidence=0.8, source="test:other"),
    ]
    assert [s.text for s in repeat_names(text, spans)] == []


def test_german_prepositions_before_a_name_do_not_hide_it():
    text = "Herr Anselm Becker fehlt. Mail an Becker, Anruf bei Becker, Grüße von Becker in Kassel."
    assert repeats(text, seed(text, "Anselm Becker")) == ["Becker", "Becker", "Becker"]
