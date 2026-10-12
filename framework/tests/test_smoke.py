"""
Dependency-free smoke tests. Run:  PYTHONPATH=src python tests/test_smoke.py
Exits non-zero on first failed assertion.
"""
from __future__ import annotations

import json
from pathlib import Path

from ttf.models import (
    Assessment, Finding, Severity, Exploitability, AttackerProfile,
    AssetExposure, AttackPath, AttackStep,
)
from ttf.metrics import (
    reach_level, attack_reach, attack_depth, blast_radius,
    finding_risk, security_improvement,
)
from ttf.report import render_report, render_diff

ROOT = Path(__file__).resolve().parents[1]


def check(name: str, cond: bool) -> None:
    if not cond:
        raise AssertionError(f"FAILED: {name}")
    print(f"  ok  {name}")


def test_reach_level():
    check("reach 0 -> level 0", reach_level(0.0) == 0)
    check("reach 0.024 -> level 3", reach_level(0.024) == 3)
    check("reach 0.0001 -> level 2", reach_level(0.0001) == 2)
    check("reach 0.6 -> level 5", reach_level(0.6) == 5)
    check("privileged bumps to >=4", reach_level(0.01, has_privileged=True) == 4)


def test_attack_reach_fraction():
    exp = [
        AssetExposure("user_profile", 24, 1000),
        AssetExposure("order", 51, 2125),
        AssetExposure("email", 37, None, sensitive=True),
    ]
    r = attack_reach(exp)
    check("fraction = 75/3125 = 0.024", abs(r["fraction"] - 0.024) < 1e-9)
    check("level 3", r["level"] == 3)


def test_blast_and_depth():
    exp = [AssetExposure("message", 63, 4200, sensitive=True),
           AssetExposure("email", 14, None, sensitive=True)]
    b = blast_radius(exp)
    check("blast records 77", b["records"] == 77)
    check("blast sensitive 77", b["sensitive_records"] == 77)
    path = AttackPath("AP", "GET /x", [AttackStep("entry", "a"),
                                       AttackStep("weakness", "b"),
                                       AttackStep("asset", "c")])
    check("attack depth = 3", attack_depth(path) == 3)
    check("no path -> depth 0", attack_depth(None) == 0)


def test_risk_and_blocked():
    confirmed = Finding(
        id="X", title="t", vuln_class="IDOR",
        severity=Severity.HIGH, exploitability=Exploitability.CONFIRMED,
        exposure=[AssetExposure("message", 63, 4200, sensitive=True)],
    )
    r1 = finding_risk(confirmed)
    check("confirmed HIGH risk > 0", r1 > 0)
    confirmed.exploitability = Exploitability.BLOCKED
    check("blocked risk == 0", finding_risk(confirmed) == 0.0)


def test_improvement():
    check("80->15 ~ 81.25%", security_improvement(80, 15) == 81.25)
    check("pre 0 -> 0", security_improvement(0, 5) == 0.0)


def test_example_roundtrip():
    data = json.loads((ROOT / "examples/ecommerce-idor/assessment.json").read_text("utf-8"))
    a = Assessment.from_dict(data)
    # round-trips through dict without loss of finding count
    check("2 findings loaded", len(a.findings) == 2)
    a2 = Assessment.from_dict(a.to_dict())
    check("roundtrip stable", len(a2.findings) == 2)
    state = a.current_state()
    check("1 open vuln (one RESOLVED)", state.vulnerabilities == 1)
    check("report renders", "THREAT THINKING REPORT" in render_report(a))
    # improvement shows up vs previous_state (28.5 -> ~5.04)
    check("improvement positive", security_improvement(28.5, state.risk) > 50)


def test_schema_files_parse():
    for name in ["finding", "assessment", "security-state"]:
        p = ROOT / "schema" / f"{name}.schema.json"
        json.loads(p.read_text("utf-8"))
        check(f"{name}.schema.json parses", True)


def main():
    for fn in [
        test_reach_level, test_attack_reach_fraction, test_blast_and_depth,
        test_risk_and_blocked, test_improvement, test_example_roundtrip,
        test_schema_files_parse,
    ]:
        print(fn.__name__)
        fn()
    print("\nALL SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
