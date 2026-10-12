"""
TTF command-line interface — stdlib only.

    python -m ttf init <app-name>        scaffold an empty assessment JSON
    python -m ttf report <assessment>    render the Threat Report to stdout
    python -m ttf state  <assessment>    print the current security state (JSON)
    python -m ttf diff   <a> <b>         diff two assessments' states
    python -m ttf validate <assessment>  check the file loads and is consistent

Run from the repo root with  src/  on the path, e.g.:

    PYTHONPATH=src python -m ttf report examples/ecommerce-idor/assessment.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import Assessment, Severity, Exploitability, AttackerProfile, Finding
from .report import render_report, render_diff
from .metrics import finding_risk
from .detectors import scan_path, DETECTORS
from .prober import run_probe, load_config, ScopeError
from .importers import detect_and_parse, run_semgrep, run_gitleaks


def _load(path: str) -> Assessment:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Assessment.from_dict(data)


def _merge_findings(target: str | None, app: str, new: list[Finding],
                    merge: bool) -> tuple[Assessment, int]:
    """Load (or create) an assessment and add non-duplicate findings by id."""
    p = Path(target) if target else None
    if p and p.exists() and merge:
        assessment = _load(str(p))
    else:
        assessment = Assessment(
            app=app,
            scope="Authorized self-assessment of an application I own/develop.",
        )
    existing = {f.id for f in assessment.findings}
    added = 0
    for f in new:
        if f.id in existing:
            continue
        assessment.findings.append(f)
        existing.add(f.id)
        added += 1
    return assessment, added


def _write(assessment: Assessment, out: str) -> None:
    Path(out).write_text(
        json.dumps(assessment.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def cmd_init(args: argparse.Namespace) -> int:
    sample = Assessment(
        app=args.app,
        cycle=1,
        scope="Authorized self-assessment of an application I own/develop.",
        findings=[
            Finding(
                id="F-001",
                title="(describe the weakness)",
                vuln_class="(e.g. Broken Object Level Authorization)",
                severity=Severity.MEDIUM,
                exploitability=Exploitability.POTENTIAL,
                attacker=AttackerProfile.AUTHENTICATED,
                entry_point="(e.g. GET /api/orders/{id})",
                hypothesis="If I were an attacker I would try ...",
            )
        ],
    )
    out = Path(args.out or f"{args.app}-assessment.json")
    out.write_text(
        json.dumps(sample.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"wrote {out}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    assessment = _load(args.file)
    text = render_report(assessment)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    assessment = _load(args.file)
    print(json.dumps(assessment.current_state().to_dict(), indent=2, ensure_ascii=False))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    before = _load(args.before).current_state()
    after = _load(args.after).current_state()
    print(render_diff(before, after))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    assessment = _load(args.file)
    problems: list[str] = []
    ids = set()
    for f in assessment.findings:
        if f.id in ids:
            problems.append(f"duplicate finding id: {f.id}")
        ids.add(f.id)
        if f.exploitability == Exploitability.CONFIRMED and not f.evidence:
            problems.append(f"{f.id}: CONFIRMED but no evidence recorded")
        if f.status == "RESOLVED" and f.reattack.original_blocked is not True:
            problems.append(f"{f.id}: RESOLVED but re-attack not verified blocked")
        if f.severity in (Severity.HIGH, Severity.CRITICAL) and not f.root_cause:
            problems.append(f"{f.id}: {f.severity.value} but no root cause analysis")
    if problems:
        print("VALIDATION PROBLEMS:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK — {len(assessment.findings)} finding(s), "
          f"residual risk {assessment.current_state().risk}")
    return 0


def _summarize(findings, path_label, out, added) -> None:
    by_class: dict[str, int] = {}
    for f in findings:
        by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
    print(f"Scanned {path_label}")
    print(f"  {len(findings)} candidate finding(s); {added} new written to {out}")
    for k, v in sorted(by_class.items(), key=lambda kv: -kv[1]):
        print(f"    {v:>3}  {k}")


def cmd_scan(args: argparse.Namespace) -> int:
    engine = args.engine
    findings = []
    notes: list[str] = []
    if engine in ("builtin", "all"):
        findings += scan_path(args.path)
    if engine in ("semgrep", "all"):
        fs, note = run_semgrep(args.path)
        findings += fs
        notes.append(f"semgrep: {note}")
    if engine in ("gitleaks", "all"):
        fs, note = run_gitleaks(args.path)
        findings += fs
        notes.append(f"gitleaks: {note}")
    out = args.out or "assessment.json"
    assessment, added = _merge_findings(out, args.app, findings, args.merge)
    _write(assessment, out)
    _summarize(findings, args.path, out, added)
    for n in notes:
        print(f"  [{n}]")
    print("\nAll scanner findings are POTENTIAL (static only).")
    print("Next: confirm with  'ttf probe',  or add engines:  --engine all  (needs semgrep/gitleaks).")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    findings = detect_and_parse(args.file, fmt=args.format, tool_hint=args.tool or "")
    out = args.out or "assessment.json"
    assessment, added = _merge_findings(out, args.app, findings, args.merge)
    _write(assessment, out)
    _summarize(findings, args.file, out, added)
    print("\nImported findings keep their source exploitability "
          "(SARIF -> POTENTIAL; TTF-shaped kept as-is).")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        findings = run_probe(config, reattack=args.reattack)
    except ScopeError as e:
        print(f"SCOPE: {e}")
        return 2
    out = args.out or "assessment.json"
    app = config.get("app", args.app or "My App")
    assessment, added = _merge_findings(out, app, findings, args.merge)
    # on re-probe, update existing finding ids in place
    if args.merge and Path(out).exists():
        by_id = {f.id: f for f in findings}
        for i, f in enumerate(assessment.findings):
            if f.id in by_id:
                assessment.findings[i] = by_id[f.id]
    _write(assessment, out)
    confirmed = sum(1 for f in findings if f.exploitability.value == "CONFIRMED")
    blocked = sum(1 for f in findings if f.exploitability.value == "BLOCKED")
    print(f"Probed {config.get('base_url')}  ({'re-attack' if args.reattack else 'initial'})")
    for f in findings:
        acc = f.exposure[0].accessible if f.exposure else 0
        tot = f.exposure[0].total if f.exposure else 0
        print(f"    {f.exploitability.value:<10} {f.id:<16} {acc}/{tot} reachable")
    print(f"\n  {confirmed} CONFIRMED, {blocked} BLOCKED; written to {out}")
    print("Next: 'ttf report " + out + " --out report.md'")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ttf", description="Threat Thinking Framework")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="scaffold an empty assessment")
    pi.add_argument("app")
    pi.add_argument("--out")
    pi.set_defaults(func=cmd_init)

    pr = sub.add_parser("report", help="render the Threat Report")
    pr.add_argument("file")
    pr.add_argument("--out")
    pr.set_defaults(func=cmd_report)

    ps = sub.add_parser("state", help="print current security state as JSON")
    ps.add_argument("file")
    ps.set_defaults(func=cmd_state)

    pd = sub.add_parser("diff", help="diff two assessments' security states")
    pd.add_argument("before")
    pd.add_argument("after")
    pd.set_defaults(func=cmd_diff)

    pv = sub.add_parser("validate", help="sanity-check an assessment file")
    pv.add_argument("file")
    pv.set_defaults(func=cmd_validate)

    psc = sub.add_parser("scan", help="① static scan source -> candidate findings")
    psc.add_argument("path")
    psc.add_argument("--app", default="My App")
    psc.add_argument("--engine", choices=["builtin", "semgrep", "gitleaks", "all"],
                     default="builtin",
                     help="builtin regex (default), or shell out to semgrep/gitleaks, or all")
    psc.add_argument("--out", help="assessment file to write/merge (default assessment.json)")
    psc.add_argument("--merge", action="store_true",
                     help="merge into --out if it exists instead of overwriting")
    psc.set_defaults(func=cmd_scan)

    pim = sub.add_parser("import", help="H1 — import SARIF (semgrep/codeql/gitleaks/…) or TTF JSON")
    pim.add_argument("file")
    pim.add_argument("--format", choices=["auto", "sarif", "ttf"], default="auto")
    pim.add_argument("--tool", help="label for the source tool (optional)")
    pim.add_argument("--app", default="My App")
    pim.add_argument("--out", help="assessment file to write/merge (default assessment.json)")
    pim.add_argument("--merge", action="store_true")
    pim.set_defaults(func=cmd_import)

    pp = sub.add_parser("probe", help="② active IDOR probe against your local app")
    pp.add_argument("config", help="probe config JSON (see examples/demo-app/probe.config.json)")
    pp.add_argument("--app", default=None)
    pp.add_argument("--out", help="assessment file to write/merge (default assessment.json)")
    pp.add_argument("--merge", action="store_true",
                    help="merge into --out if it exists instead of overwriting")
    pp.add_argument("--reattack", action="store_true",
                    help="re-run after a fix; records original_blocked / BLOCKED status")
    pp.set_defaults(func=cmd_probe)

    return p


def _force_utf8_stdout() -> None:
    """Windows consoles default to cp1252 and choke on the report's box/arrow
    glyphs. Reconfigure stdout/stderr to UTF-8 so printing never crashes.
    Best-effort: ignored on streams that cannot be reconfigured.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
