# pii-eraser

Find personal data and secrets in text and code. Replace them with stable
placeholders. Do it locally, before the text goes to a model, a log or a vendor.

```
Contact Jane Doe <jane.doe@example.org>, key AKIA…      →   Contact [NAME_1] <[EMAIL_1]>, key [SECRET_1]
```

- **Local.** Regex rules and an optional NER model run on your machine. No network.
- **Stable.** A session keeps one placeholder table across many texts:
  `Jane Doe` is `[NAME_1]` in the diff, in every file an agent reads afterwards,
  and in the next file, even where no rule fires again.
- **Code-aware.** The code profile drops rules that misfire on source (dates in
  changelogs, numbers that look like phones) and checks card numbers (Luhn) and
  IBANs (mod-97). Line counts never change, so line numbers in a review still hold.
- **Reversible for the owner.** `session.restore(text)` puts the originals back
  into a model's answer, on your side.

## Install

```bash
pip install pii-eraser              # regex rules only, no dependencies
pip install 'pii-eraser[gliner]'    # + GLiNER NER for names and organisations (~400 MB model)
```

## Use

```python
from pii_eraser import Eraser

eraser = Eraser.for_prose()  # documents, emails, MR descriptions
result = eraser.erase("Name: Jane Doe, jane.doe@example.org")
result.text  # 'Name: [NAME_1], [EMAIL_1]'
result.mapping  # {'[NAME_1]': 'Jane Doe', '[EMAIL_1]': 'jane.doe@example.org'}

session = Eraser.for_code().session()  # many texts, one table
session.erase(diff_text)
session.erase(file_the_agent_read)
answer = session.restore(model_answer)
```

With NER:

```python
from pii_eraser.detectors.gliner import GlinerDetector

Eraser.for_prose(GlinerDetector())  # NER hits are replaced
Eraser.for_code(GlinerDetector())  # NER hits are only reported in result.signals
```

On source code an NER model tags variable names and authors as people. In the
code profile its hits are signals for a human, not replacements.

NER names count from a score of 0.3, other labels from 0.5 (`GlinerDetector(label_thresholds=…)`):
the model scores names it has rarely seen low. What it also tags at low scores — role nouns
(EN/DE), a trade after a German article ("der Bäcker"), a field name without a digit ("IBAN") —
is filtered. Where a rule and the model disagree on the edges of a phone number, IBAN or id, the
rule's span is kept.

## CLI

```bash
pii-eraser contract.txt > contract.clean.txt
git diff origin/main | pii-eraser --profile code --report --fail-on-secret > /dev/null
```

The report on stderr lists kind, line and rule, never the original value, so it
is safe for CI logs. `--fail-on-secret` exits 1 when a secret is found.
Diff lines are read as they come: added, removed and context lines are all
checked, since a removed secret still sits in history.

## What it finds

| Kind | Examples |
|---|---|
| `SECRET` | private key blocks, AWS / GitHub / GitLab / Slack / Anthropic / OpenAI / Google / Stripe keys, JWTs, passwords in URLs, `password = "…"` / `API_KEY=…` assignments, long random quoted strings; in prose also passwords typed into a sentence ("Passwort …", "my password is …") |
| `EMAIL`, `PHONE` | emails; international (`+49 (0)…`, `0049 …`), national DE/AT/CH/UK (`030 …`, `(069) …-…`, `0172 / …`, `020 7946 …`), US formats |
| `NAME` | labelled names (also `Last, First` and in capitals), titles (Herr/Frau/Mr/Dr, particles like van den), greetings, sign-offs (EN/DE), initials (`gez. H. Lindner`), name lists, contract parties; with NER: any person or organisation |
| `ADDRESS` | German, Austrian and Swiss streets with postcode and town, UK street lines and postcodes, address fields (`PLZ:`, `"town":`), US street / city / state / ZIP, labelled addresses |
| `FINANCIAL` | payment cards (Luhn), IBAN (mod-97; printed in groups, across a line break, OCR confusions read back), account, routing, tax ids |
| `IP` | IPv4 and IPv6 addresses (not loopback; version strings left alone) |
| `SSN`, `NATIONAL_ID`, `DOB`, `MRN`, `HEALTH_PLAN_ID` | German Steuer-ID and SV-Nummer (check digits), Steuernummer, UK NI, US SSN, Swiss AHV, Spanish NIE/DNI, passports, licences, dates of birth (also with month names), medical record and insurance numbers (EN/DE) |

References to secrets are left alone: `${DB_PASSWORD}`, `<your-token>`,
`os.environ['SECRET']`, `changeme`.

## Limits

Detection is heuristic. Rules miss formats they don't know; NER misses rare
names and catches some non-names. Treat the output as reduced exposure, not as
anonymisation in the legal sense, and keep a secret scanner such as gitleaks in
your pipeline: a leaked key must be rotated, not just masked.

## Origin

The personal-data rules and NER filters come from the scrubber of
37lab's contract analyzer, tuned on real contracts, medical notes and business
email. The secret rules, sessions and the code profile were added for agentic
code review in [semantic-diff](https://github.com/tkenaz/semantic_diff).

## License

MIT — [37lab](https://37lab.ai). The default NER model
`urchade/gliner_medium-v2.1` is Apache-2.0.
