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
        # public object ids: an agent has to pass them on
        "toolu_01QVjYRCNKMPTjxuBZmqD9pS",
        "req_011CSHoEeqs5C35K2UUqR7Fy",
        "pi_3MtwBwLkdIwHu7ix28a3tqPa",
        "chatcmpl-8V1pXaNYKz2X4mPqRtUv9WbCdEfGh",
        "run_abc123DEF456ghi789JKL012",
        "batch_0123456789abcdef0123456789abcdef",
        "session_01Gca5DYfTJT4gvQR7BFpqEP",
        "sg-0a1b2c3d4e5f6a7b8c9d0e1f",
        "cache-v1-linux-node-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "chunk-vendors-2f8a9c3d1e5b7f4a.js",
        "abc_v1_a625799e31e0afddb275caf95ed5444ca99f29c2bb47f40f0bc8b94120bbbcd0",  # hex: a digest unless the format is known
        "tmp_AaAaAaAaAaAaAaAaAaAaAaAaAaAa111111",  # both cases and digits, nothing random
        "tmp_" + "aB3dE6gH" * 4,  # eight symbols repeated: 3.0 bits per character, a pattern
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


# ---------------- second review


@pytest.mark.parametrize(
    "token",
    ["dop_v1_" + "a625799e31e0afdd" * 4, "shpat_" + "f7d195769a5363ce" * 2, "dapi" + "e49744904dbeaa28" * 2],
)
def test_provider_formats_with_a_hex_tail(token):
    assert found(f"key: {token} ok") == [(Kind.SECRET, token)]


@pytest.mark.parametrize(
    "query",
    [
        "&client_secret=Zx9Kq2mN8pQ4rS7tV1wX",
        "&refresh_token=1//0gAbCd3fGh1JkLmN0pQrStUv",
        "?auth_token=Zx9Kq2mN8pQ4rS7tV1wX",
        "?secret_key=Zx9Kq2mN8pQ4rS7tV1wX",
        "&X-Amz-Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
    ],
)
def test_any_key_that_ends_in_a_credential_word(query):
    value = query.split("=", 1)[1]
    text = f"https://api.beispiel.example/v1/items{'?a=1' if query[0] == '&' else ''}{query}&page=2"
    assert (Kind.SECRET, value) in found(text) and (Kind.SECRET, value) in found(text, Eraser.for_code())


@pytest.mark.parametrize(
    "text",
    [
        "https://api.beispiel.example/v1?token=page2cursor&limit=50",
        "https://api.beispiel.example/v1?a=1&page_token=Zx9Kq2mN8pQ4rS7tV1wX",
        "https://api.beispiel.example/v1?a=1&sort_key=created2024desc&token_type=bearer",
        "Endpoint=sb://bus.beispiel.example/;SharedAccessKeyName=RootManageSharedAccessKey1",
        "Server=db;Database=x;Pwd=abc12;",
        "https://api.beispiel.example/v1?a=1&api_key=shortkey123",
        'curl -H "Authorization: Bearer YOUR_TOKEN" https://api.beispiel.example',
        'curl -H "Authorization: Bearer ${TOKEN}" https://api.beispiel.example',
        "Authorization: Bearer abc123def456ghi7",
        "Authorization: Bearer your_access_token_goes_here",
        "https://api.beispiel.example/v1?a=1&token=aaaaaaaaaaaa1111",
    ],
)
def test_parameters_and_placeholders_that_are_not_credentials(text):
    assert not any(kind is Kind.SECRET for kind, _ in found(text))


def test_dates_in_a_coming_year_are_not_dates_of_birth():
    for value in ("10. September 2099", "21 August 2099", "March 3, 2099", "12.05.2099", "2099-05-12", "2099/05/12", "05/12/2099"):
        assert found(f"Frist: {value}\n") == [], value
    assert found("geb. 12.05.2099") != []  # a label says what it is, whatever the year


@pytest.mark.parametrize(
    "text",
    ["3.9.1969-A", "12/3/2015-alpha", "1.2.2000/24", "10.1.2024.5", "git tag 2024.01.15", "v3.9.1969", "192.3.9.1969", "1994/01/01/x", "x/1994/01/01"],
)
def test_date_is_not_cut_out_of_a_longer_token(text):
    assert not any(kind is Kind.DOB for kind, _ in found(text))


def test_month_day_year_without_a_comma():
    assert found("Meier;Jo;Mar 3 2004;aktiv") == [(Kind.DOB, "Mar 3 2004")]


def test_compact_date_after_a_label_needs_a_year_people_are_born_in():
    assert found("geb. 17061881") == [] and found("geb. 31122040") == []
    assert found("geb. 170619812") == []


def test_ordinals_are_not_postcodes():
    assert found("Meeting in room b1 2nd floor, queue rm3 3rd slot") == []
