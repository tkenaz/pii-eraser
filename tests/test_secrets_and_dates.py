"""Credentials inside connection strings and behind provider prefixes; calendar dates in the layouts people
write them in. All values are invented here."""

import pytest

from pii_eraser import Eraser, Kind

PASSWORD = "hT7kQ2mVx9pL4wQ"
KEY = "k98xpqIvbeIuuSHpiaO3rslb+5Qe/2UGzqjIVtYI04ArpA+4DZKNMM1VmLErRo2Rhni/zXvng0KLNqt8tf3kgE=="


def found(text, eraser=None):
    eraser = eraser or Eraser.for_prose()
    return [(s.kind, text[s.start : s.end]) for s in eraser.detect(text)[0]]


@pytest.mark.parametrize(
    "text",
    [
        f"redis://:{PASSWORD}@cache.beispiel.example:6379/0",
        f"Server=db.beispiel.example;Database=billing;User Id=report_ro;Password={PASSWORD};",
        f"Server=db.beispiel.example;Database=billing;Uid=report_ro;Pwd={PASSWORD}",
        f"jdbc:postgresql://db.beispiel.example:5432/hr?user=app_user&password={PASSWORD}",
        f"https://api.beispiel.example/v1/export?format=csv&api_key={PASSWORD}&page=2",
    ],
)
def test_password_inside_a_connection_string_is_masked_and_the_host_stays(text):
    for eraser in (Eraser.for_prose(), Eraser.for_code()):
        assert (Kind.SECRET, PASSWORD) in found(text, eraser)
        assert "beispiel.example" in eraser.erase(text).text


def test_storage_account_key_is_masked():
    text = f"DefaultEndpointsProtocol=https;AccountName=billingstore;AccountKey={KEY};EndpointSuffix=core.windows.net"
    assert found(text) == [(Kind.SECRET, KEY)]


def test_placeholders_in_connection_strings_are_left_alone():
    assert found("Server=db;Database=x;Password=${DB_PASSWORD};") == []
    assert found("https://api.beispiel.example/v1?token=<your-token>&page=2") == []


@pytest.mark.parametrize("token", ["Rk3vTT7QWdqdsGmofTwGDKBsyW4TB5vG289GHnq1", "https://hooks.beispiel.example/services/T01ABCD/B02EFGH/a8Kq2mZx9pL4wQ7r"])
def test_what_follows_bearer_is_a_credential(token):
    text = f'curl -H "Authorization: Bearer {token}" https://api.beispiel.example'
    assert (Kind.SECRET, token) in found(text) and (Kind.SECRET, token) in found(text, Eraser.for_code())


def test_bearer_in_prose_is_not_a_credential():
    assert found("The bearer of this letter, and Bearer authentication in general, is fine.") == []


@pytest.mark.parametrize(
    "token",
    [
        "qz_DQ1PChTHUO07FrkeYE7zrPd2hs3oInFffB",
        "abc_v1_a625799e31e0afddb275caf95ed5444ca99f29c2bb47f40f0bc8b94120bbbcd0",
        "tokn-AgEIcHlwaS5vcmceHAOVJAkLSnWiRA9mHjFyKcL27jn8hrlZLQFoLjLrpWz",
        "whk_hIkF4yTqATAVHuMS4Lc8wmagaaE8LIfn",
    ],
)
def test_provider_prefix_with_a_random_tail_is_a_token(token):
    assert found(f"key we are using: {token}\n") == [(Kind.SECRET, token)]
    assert found(f"token\t{token}\tactive", Eraser.for_code()) == [(Kind.SECRET, token)]


@pytest.mark.parametrize(
    "text",
    [
        "feature_flag_enable_new_checkout_flow_2024_v2",
        "req-550e8400-e29b-41d4-a716-446655440000",
        "sha512-Zq7hBC5FKfyxMSdA2DNvgU6Hs23pCtu43XJFs8zIDvVUgZ332H82R1k98opoIvbe",
        "commit-3f2a9c1d8e7b6a5f4c3d2e1f0a9b8c7d6e5f4a3b",
        "integration_test_customer_export_handler",
        "my-very-long-kebab-case-component-name-2",
        "arn_QuarterlyRevenueForecastWorkbookFinalVersion",  # letters only: a name, however long
        "tmp_aaaaaaaaaaaaaaaaaaaaaaaa111111111111",  # letters and digits, nothing random about them
    ],
)
def test_names_digests_and_ids_are_not_tokens(text):
    assert found(text) == [] and found(text, Eraser.for_code()) == []


# ---------------- dates


@pytest.mark.parametrize(
    "value",
    [
        "26 FEB 1974", "15th of November 1974", "5th of May 1986", "15th July 1944", "8.September 1973", "11. Feb. 1948",
        "25. Mai 1939", "22.Februar 1965", "8.Jänner 1941", "11-Aug-1941", "16 Sep 1991", "4 Nov 1999", "10. März 1938",
        "September 28th, 1984", "January 1st, 1982", "Feb 12, 1979", "Oct 1, 2005",
        "23. 12. 1988", "11.4.1942", "25/1/1987", "3.9.1969", "1994/01/01",
    ],
)  # fmt: skip
def test_written_date_in_any_layout(value):
    assert found(f"Meier;Jo;{value};aktiv") == [(Kind.DOB, value)]


@pytest.mark.parametrize("value", ["17061981", "19810617", "16.01.01", "8/1/68"])
def test_ambiguous_date_forms_only_after_a_birth_label(value):
    for label in ("geb.", "DOB", "Geburtsdatum:", "born"):
        assert (Kind.DOB, value) in found(f"Jo Meier, {label} {value}, wohnhaft")
    assert (Kind.DOB, value) not in found(f"Vorgang {value} erledigt")


@pytest.mark.parametrize(
    "text",
    ["geb. 99998877", "Kapitel 3.9.1969a", "Version 11.4.19422", "32. Mai 1939", "Mai 1939", "Feb 31st 12", "v2024.13.01", "12.13.1988"],
)
def test_what_is_not_a_date(text):
    assert not any(kind is Kind.DOB for kind, _ in found(text))


@pytest.mark.parametrize("value", ["ow 82 01 06 d", "ow820106d", "OW-82-01-06-D"])
def test_ni_number_in_lower_case_after_its_label(value):
    for label in ("NI number:", "NINO", "National Insurance no."):
        assert (Kind.NATIONAL_ID, value) in found(f"{label} {value}\n")
    assert found("ow 82 01 06 d") == []
