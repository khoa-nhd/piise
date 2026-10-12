"""
Importer tests. Run:  PYTHONPATH=src python tests/test_importers.py
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ttf.importers import parse_sarif_obj, detect_and_parse

SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "python.sql.injection",
             "shortDescription": {"text": "Possible SQL injection"},
             "properties": {"tags": ["security", "sql"], "security-severity": "8.5"}},
            {"id": "generic.hardcoded-secret",
             "shortDescription": {"text": "Hardcoded secret"},
             "properties": {"tags": ["secret"]}},
        ]}},
        "results": [
            {"ruleId": "python.sql.injection", "level": "error",
             "message": {"text": "User input in SQL string"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "app/db.py"},
                 "region": {"startLine": 42}}}]},
            {"ruleId": "generic.hardcoded-secret", "level": "warning",
             "message": {"text": "API key in source"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "app/config.py"},
                 "region": {"startLine": 7}}}]},
        ],
    }],
}


def check(name, cond):
    if not cond:
        raise AssertionError(f"FAILED: {name}")
    print(f"  ok  {name}")


def test_sarif_mapping():
    fs = parse_sarif_obj(SARIF)
    check("two findings", len(fs) == 2)
    by_class = {f.vuln_class for f in fs}
    check("sql classified", "Injection (SQL)" in by_class)
    check("secret classified", "Secrets exposure" in by_class)
    sqlf = [f for f in fs if f.vuln_class == "Injection (SQL)"][0]
    check("cvss 8.5 -> HIGH", sqlf.severity.value == "HIGH")
    check("line in entry_point", sqlf.entry_point == "app/db.py:42")
    check("all POTENTIAL", all(f.exploitability.value == "POTENTIAL" for f in fs))
    check("tagged sarif", all("sarif" in f.tags for f in fs))
    check("stable unique ids", len({f.id for f in fs}) == 2)


def test_autodetect_and_ttf_format():
    with tempfile.TemporaryDirectory() as d:
        sp = Path(d) / "x.sarif"
        sp.write_text(json.dumps(SARIF), encoding="utf-8")
        check("auto-detect sarif", len(detect_and_parse(str(sp), "auto")) == 2)

        tp = Path(d) / "ttf.json"
        tp.write_text(json.dumps([{
            "id": "L-001", "title": "logic bug", "vuln_class": "Broken access control",
            "severity": "HIGH", "exploitability": "PLAUSIBLE", "tags": ["llm-scan"],
        }]), encoding="utf-8")
        fs = detect_and_parse(str(tp), "auto")
        check("ttf-shaped parsed", len(fs) == 1 and fs[0].id == "L-001")
        check("ttf-shaped keeps exploitability", fs[0].exploitability.value == "PLAUSIBLE")


def main():
    for fn in [test_sarif_mapping, test_autodetect_and_ttf_format]:
        print(fn.__name__)
        fn()
    print("\nALL IMPORTER TESTS PASSED")


if __name__ == "__main__":
    main()
