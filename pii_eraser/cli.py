"""pii-eraser FILE|-  →  erased text on stdout, a report on stderr.

The report names kind, line and rule, never the original value: it is meant
for CI logs.
"""

import argparse
import json
import sys

from pii_eraser.eraser import Eraser
from pii_eraser.types import EraseResult, Kind


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _report(original: str, result: EraseResult) -> dict:
    def row(span):
        return {"kind": span.kind.value, "line": _line_of(original, span.start), "rule": span.source}

    return {
        "found": [row(s) for s in result.found],
        "signals": [row(s) for s in result.signals],
        "secrets": sum(1 for s in result.found if s.kind is Kind.SECRET),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pii-eraser", description=__doc__.split("\n")[0])
    parser.add_argument("path", nargs="?", default="-", help="file to read, '-' for stdin")
    parser.add_argument("--profile", choices=("prose", "code"), default="prose")
    parser.add_argument("--ner", action="store_true", help="add GLiNER (pip install 'pii-eraser[gliner]')")
    parser.add_argument("--report", action="store_true", help="JSON report on stderr")
    parser.add_argument("--fail-on-secret", action="store_true", help="exit 1 when a secret is found")
    args = parser.parse_args(argv)

    text = sys.stdin.read() if args.path == "-" else open(args.path, encoding="utf-8").read()

    ner = None
    if args.ner:
        from pii_eraser.detectors.gliner import GlinerDetector

        ner = GlinerDetector()
    eraser = Eraser.for_code(ner) if args.profile == "code" else Eraser.for_prose(ner)
    result = eraser.erase(text)

    sys.stdout.write(result.text)
    report = _report(text, result)
    if args.report:
        print(json.dumps(report, indent=2), file=sys.stderr)
    if args.fail_on_secret and report["secrets"]:
        print(f"pii-eraser: {report['secrets']} secret(s) found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
