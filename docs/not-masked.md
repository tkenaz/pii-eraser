# What pii-eraser does not mask

Masking reduces exposure; it is not anonymisation. This page lists what stays readable after
`Eraser.for_prose()` and `Eraser.for_code()`, so that nobody has to find out from an incident. Every row
was checked against the build `0.1.2.dev2`; the rows of sections 1, 2 and 4 are pinned by
`tests/test_not_masked.py`, so the page cannot drift from the code unnoticed.

Read it as three different statements: left readable **on purpose** (section 1), **not covered** by any
rule (section 2), and found **only by the optional NER model**, which is a likelihood and not a guarantee
(section 3).

## 1. Left readable on purpose

| What | Example | Why |
|---|---|---|
| A date in a coming year, without a birth label | `Frist: 15. Januar 2027` | It cannot be a date of birth, and a reader needs deadlines. Dates of the current year and earlier **are** masked. With a birth label a date is masked whatever its year. The line between the two is the calendar year at the time of the run. |
| Month and year, a year alone, an age, a clock time | `seit März 2021`, `seit 1998`, `47 Jahre alt`, `14:30 Uhr` | Too coarse to be a date of birth. |
| Amounts of money | `1.284,50 EUR` | Not personal data on their own. |
| Host, port, user and database in a connection string | `postgresql://svc_report:[SECRET_1]@db-prod.intern.example:5432/billing` | Only the secret value is masked; the rest is what makes the string debuggable. A user name in the string stays readable. |
| Names of secrets | `STRIPE_SECRET_KEY`, `${DB_PASSWORD}`, `os.environ['SECRET']` | A reference to a secret is not the secret. |
| Public object ids, UUIDs, commit hashes, version strings | `req_011CSHoE…`, `3f2b8c1e-9a4d-…`, `9fceb02d0ae5…`, `2.14.3.1` | Tools downstream have to pass them on. If such an id points to a person in your system, it is personal data for you and it is **not** masked. |
| URLs, MAC addresses | `https://portal.example.org/kunden/4711/akte`, `00:1A:2B:3C:4D:5E` | No rule; a URL path or query can carry an id or a name. |
| Loopback and unspecified IP addresses | `127.0.0.1`, `0.0.0.0` | They identify no one. Every other IPv4 / IPv6 address is masked, private ranges included. |
| Role nouns and job titles | `der Kunde`, `the contractor`, `Leiterin Einkauf` | They name a role, not a person; masking them corrupts the sentence. In a small team a job title identifies its holder all the same. |
| Countries | `Portugal` | |

## 2. Not covered: no rule finds these

| What | Example | Note |
|---|---|---|
| Special categories written as free text (GDPR Art. 9) | a diagnosis, a religion, a nationality, a gender | pii-eraser finds identifiers, not sensitive statements. A text stays as sensitive as it was once the name is gone if the rest still points to one person. |
| Business numbers | invoice, order, ticket, customer and employee numbers | A customer or employee number is personal data where it resolves to a person. |
| Licence plates | `M-AB 1234` | |
| Company identifiers | VAT id `DE123456789`, register number `HRB 123456`, BIC | For a sole trader these identify a person. |
| Login names | `Benutzername: mkeller92` | E-mail addresses are masked; a bare login name is not. |
| UK sort codes | `20-45-77` | The labelled account number next to it is masked. |
| German health-insurance numbers after `Versichertennummer` | `A123456780` | The rule knows `Versicherungsnummer` and `Krankenkasse` only. |
| Passport numbers that are not eight or nine digits | `C01X00T47` | The passport rules know the US shape. A German `Personalausweis` number after its label is masked. |
| Ambiguous date forms without a birth label | `12.03.24`, `12031984` | Read as a date only after a birth label. |
| Phone extensions and numbers under seven digits | `Durchwahl 4412` | |
| Payment cards under 16 digits | 13-digit Maestro | |
| A street without a house number, a postcode and town in the middle of a sentence | `in der Lindenstraße`, `nach 93047 Regensburg` | An address is recognised by street with number, or by where the postcode line stands. |
| A name that stands only once, with no title, greeting, label or signature around it | `Gestern hat Okafor die Liste geschickt.` | Rules need a context; see section 3. A name found once by any means is then masked everywhere in the text. |
| Images, scans, attachments, file names | | Text only. |

## 3. Found only with the NER extra (`pii-eraser[gliner]`), and then not always

Without the extra these are readable. With it the model usually masks them, at its own error rate: on the
development corpus about a third of the organisation names were found.

- names of people without any context around them, in running text
- company and organisation names
- towns and streets outside a full address
- passport and insurance numbers in shapes the rules do not know
- handles such as `@mkeller_92`, geographic coordinates

A first name alone in lower case (`frag mal tamsin`) is not found by the model either, unless the name
was found somewhere else in the same text.

## 4. The code profile masks less, on purpose

`Eraser.for_code()` is for source code and diffs, where a loose rule destroys the code. It runs the secret
rules and only those personal-data rules that are safe in code: e-mail addresses, cards, IBANs, SV-Nummer,
AHV and NIE numbers, values after an explicit label (phone, date of birth, SSN, passport, medical record
number), names after a title or a name label. It does **not** mask, even though the prose profile does:

- IP addresses
- phone numbers without a label
- dates without a birth label
- addresses
- names in greetings, signatures and lists; repeated mentions of a name
- passwords typed into a sentence

The NER model, if given, only reports in this profile and replaces nothing.
