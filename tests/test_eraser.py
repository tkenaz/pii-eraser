import io
import json
import sys

import pytest

from pii_eraser import Eraser, Kind
from pii_eraser.cli import main
from pii_eraser.detectors.gliner import GlinerDetector
from pii_eraser.detectors.validators import iban_ok, luhn_ok, shannon_entropy

# Credential-shaped fixtures are assembled at runtime so secret scanners on the
# repository host don't flag the test file itself.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
RANDOM_B64 = "q8Zr3" + "Kx9Lm2Vb7Tn4Yw1Pc6Hs5Jd0Fg"
SHORT_RANDOM = "Zq81kLm0" + "9xPw7Rt3Yv"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\nAAAA\nBBBB\n-----END RSA " + "PRIVATE KEY-----"


# ---------------- session: one table for many texts


def test_session_keeps_placeholders_across_texts():
    s = Eraser.for_prose().session()
    a = s.erase("Contact: jane.doe@example.org")
    b = s.erase("cc jane.doe@example.org and bob@example.org")
    assert a.text == "Contact: [EMAIL_1]"
    assert b.text == "cc [EMAIL_1] and [EMAIL_2]"


def test_value_learned_in_one_text_is_erased_in_the_next_without_context():
    s = Eraser.for_prose().session()
    s.erase("Name: Jane Doe\n")
    later = s.erase("approved by Jane Doe yesterday")
    assert "Jane" not in later.text
    assert later.text == "approved by [NAME_1] yesterday"


def test_bare_surname_follows_the_full_name():
    result = Eraser.for_prose().erase("Name: Jane Doe\nLater Doe signed.")
    assert result.text == "Name: [NAME_1]\nLater [NAME_1] signed."


def test_name_does_not_fire_inside_a_longer_word():
    s = Eraser.for_prose().session()
    s.erase("Dr. Ana\n")
    assert s.erase("Banana and Ana").text == "Banana and [NAME_1]"


def test_restore_round_trips():
    s = Eraser.for_prose().session()
    original = "Mail jane.doe@example.org, key " + AWS_KEY
    erased = s.erase(original).text
    assert "example.org" not in erased and AWS_KEY not in erased
    assert s.restore(erased) == original


# ---------------- secrets


def test_known_token_shapes():
    text = f'aws = {AWS_KEY}\ngh = "{GH_TOKEN}"\n'
    result = Eraser.for_code().erase(text)
    assert AWS_KEY not in result.text and GH_TOKEN not in result.text
    assert {s.kind for s in result.found} == {Kind.SECRET}


def test_private_key_keeps_the_line_count():
    text = f"line1\n{PEM}\nline7\n"
    result = Eraser.for_code().erase(text)
    assert "MIIEow" not in result.text
    assert result.text.count("\n") == text.count("\n")
    assert result.text.splitlines()[-1] == "line7"


def test_secret_assignment_replaces_the_value_only():
    result = Eraser.for_code().erase(f'api_key = "{RANDOM_B64}"')
    assert result.text == 'api_key = "[SECRET_1]"'


@pytest.mark.parametrize(
    "line",
    [
        'password = "${DB_PASSWORD}"',
        'token: "<your-token-here>"',
        'API_KEY = "changeme-please"',
        "secret = os.environ['SECRET']",
    ],
)
def test_references_to_secrets_are_left_alone(line):
    assert Eraser.for_code().erase(line).text == line


def test_url_password_only():
    result = Eraser.for_code().erase("postgres://app:hunter2pass@db.internal:5432/main")
    assert result.text == "postgres://app:[SECRET_1]@db.internal:5432/main"


def test_env_style_assignment():
    result = Eraser.for_code().erase(f"export SERVICE_TOKEN={RANDOM_B64}\n")
    assert RANDOM_B64 not in result.text


@pytest.mark.parametrize("prefix", ["+", "-", " "])
@pytest.mark.parametrize("line", [f"API_KEY={SHORT_RANDOM}", f"  password: {SHORT_RANDOM}"])
def test_bare_assignment_is_caught_as_a_diff_line(prefix, line):
    # .env and YAML hunks: the unquoted rule was anchored before the diff prefix.
    result = Eraser.for_code().erase(prefix + line)
    assert SHORT_RANDOM not in result.text


def test_short_random_value_behind_a_secret_key_is_caught():
    # 18 random chars top out below the 4.2 entropy bar of long strings.
    assert Eraser.for_code().erase(f"DB_PASSWORD={SHORT_RANDOM}").found


@pytest.mark.parametrize(
    "line",
    [
        "+  api_key_env: GATEWAY_API_KEY_V2",
        "+  credentials_file: /etc/app/creds_v2.json",
        "+SECRET_VERSION=v20261029build7",
        "+TOKEN_AUDIENCE=api2production",
        "+TOKEN_CLASS=OAuth2BearerToken",
        "+PASSWORD_HASHER=Argon2idHasher",
        "+PASSWORD_POLICY=min12chars_upper",
    ],
)
def test_names_behind_a_secret_key_are_not_secrets(line):
    assert Eraser.for_code().erase(line).found == []


def test_hex_hash_is_not_a_secret_but_random_base64_is():
    sha = '"' + "3f786850e387550fdab836ed7e6dc881de23001b" + '"'
    assert Eraser.for_code().erase(f"expected = {sha}").found == []
    assert Eraser.for_code().erase(f'seed = "{RANDOM_B64}"').found


def test_secret_wins_over_an_email_inside_it():
    result = Eraser.for_code().erase("smtp://mailer:pa55word99@smtp.example.org")
    assert "pa55word99" not in result.text


# ---------------- code profile vs prose profile


def test_code_profile_leaves_changelog_dates_and_numbers():
    text = "## [0.3.0] - 2026-10-14\ntimeout = 555-123-4567\n"
    assert Eraser.for_code().erase(text).text.startswith("## [0.3.0] - 2026-10-14")
    assert "2026-10-14" not in Eraser.for_prose().erase(text).text


def test_card_numbers_need_a_valid_check_digit():
    valid, invalid = "4111 1111 1111 1111", "4111 1111 1111 1112"
    assert Eraser.for_code().erase(f"card {valid}").text == "card [FINANCIAL_1]"
    assert Eraser.for_code().erase(f"build {invalid}").text == f"build {invalid}"


def test_iban_needs_a_valid_checksum():
    assert Eraser.for_code().erase("iban DE89370400440532013000").text == "iban [FINANCIAL_1]"
    assert Eraser.for_code().erase("ENUM DE89370400440532013001").found == []


# ---------------- NER stage


class FakeModel:
    def __init__(self, entities):
        self.entities = entities

    def predict_entities(self, text, labels, threshold):
        return [e for e in self.entities if e["text"] in text]


def _ner(*entities):
    return GlinerDetector(model=FakeModel(list(entities)))


def test_ner_uses_model_offsets_not_first_occurrence():
    text = "Maria wrote; Maria Garcia reviewed"
    det = _ner({"text": "Maria Garcia", "label": "person", "score": 0.9, "start": 13, "end": 25})
    [span] = det.detect(text)
    assert (span.start, span.end) == (13, 25)


def test_ner_drops_role_nouns():
    det = _ner({"text": "the Shareholder", "label": "person", "score": 0.9, "start": 0, "end": 15})
    assert det.detect("the Shareholder agrees") == []


def test_ner_replaces_in_prose_but_only_signals_in_code():
    entity = {"text": "Maria Garcia", "label": "person", "score": 0.9, "start": 3, "end": 15}
    text = "by Maria Garcia"
    prose = Eraser.for_prose(_ner(entity)).erase(text)
    code = Eraser.for_code(_ner(entity)).erase(text)
    assert prose.text == "by [NAME_1]"
    assert code.text == text and [s.text for s in code.signals] == ["Maria Garcia"]


def test_ner_below_threshold_is_ignored():
    entity = {"text": "Maria Garcia", "label": "person", "score": 0.3, "start": 3, "end": 15}
    assert Eraser.for_prose(_ner(entity)).erase("by Maria Garcia").found == []


# ---------------- validators


def test_validators():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert iban_ok("GB82 WEST 1234 5698 7654 32") and not iban_ok("GB82WEST12345698765433")
    assert shannon_entropy("aaaa") == 0.0 and shannon_entropy("0123456789abcdef") == 4.0


# ---------------- CLI


def _run(monkeypatch, capsys, stdin, *args):
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    code = main(["-", *args])
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_fails_on_secret_and_never_prints_the_value(monkeypatch, capsys):
    code, out, err = _run(monkeypatch, capsys, f"k = {AWS_KEY}\n", "--profile", "code", "--report", "--fail-on-secret")
    assert code == 1
    assert AWS_KEY not in out and AWS_KEY not in err
    report = json.loads(err[: err.rindex("}") + 1])
    assert report["secrets"] == 1 and report["found"][0]["line"] == 1


def test_cli_passes_clean_input(monkeypatch, capsys):
    code, out, _ = _run(monkeypatch, capsys, "nothing here\n", "--fail-on-secret")
    assert code == 0 and out == "nothing here\n"


@pytest.mark.parametrize(
    "line",
    [
        'MAX_TOKENS = "max_tokens"',
        "patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'})",
        '"SEMANTIC_DIFF_API_KEY": "gateway-key",',
    ],
)
def test_enum_values_and_test_fixtures_are_not_secrets(line):
    # Both fired on the semantic-diff history before the identifier/test filters.
    assert Eraser.for_code().erase(line).found == []


def test_labelled_id_value_must_hold_a_digit():
    # The ported rule took the word "Member" for the id and left the id in place.
    result = Eraser.for_prose().erase("Insurance: Member ID ABC123456789")
    assert "ABC123456789" not in result.text
    assert "Member" in result.text
