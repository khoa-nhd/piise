"""
Render a Threat Report (Markdown) from an Assessment, and diff two states.

Output is plain Markdown with ASCII boxes/arrows so it reads well in a terminal,
a PR description, or a rendered Markdown viewer.
"""

from __future__ import annotations

from .models import Assessment, Finding, SecurityState, Exploitability
from .metrics import (
    attack_reach,
    attack_depth,
    blast_radius,
    finding_risk,
    assessment_risk,
    security_improvement,
)

_RULE = "━" * 52
_THIN = "─" * 52


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _attack_path_block(finding: Finding) -> list[str]:
    path = finding.attack_path
    if not path:
        return ["  (no attack path recorded)"]
    out: list[str] = [f"  Entry: {path.entry_point}"]
    rendered = [s.label for s in path.steps] if path.steps else []
    for i, label in enumerate(rendered):
        prefix = "   " if i == 0 else "    ↓\n   "
        out.append(f"{prefix} {label}")
    if path.impact:
        out.append(f"    ↓\n    Impact: {path.impact}")
    return out


def _reattack_lines(finding: Finding) -> list[str]:
    ra = finding.reattack
    lines: list[str] = []

    def mark(blocked) -> str:
        if blocked is True:
            return "BLOCKED ✓"
        if blocked is False:
            return "STILL VULNERABLE ✗"
        return "not tested"

    lines.append(f"Original exploit:    {mark(ra.original_blocked)}")
    if ra.variants:
        n_ok = sum(1 for v in ra.variants if v.get("blocked"))
        lines.append(f"Variant attacks:     {n_ok}/{len(ra.variants)} blocked")
        for v in ra.variants:
            lines.append(f"  - {v.get('label', '?'):<28} {mark(v.get('blocked'))}")
    if ra.regressions:
        n_ok = sum(1 for r in ra.regressions if r.get("blocked"))
        lines.append(f"Regression attacks:  {n_ok}/{len(ra.regressions)} blocked")
        for r in ra.regressions:
            lines.append(f"  - {r.get('label', '?'):<28} {mark(r.get('blocked'))}")
    return lines


# --------------------------------------------------------------------------- #
# finding section
# --------------------------------------------------------------------------- #
def render_finding(finding: Finding, index: int) -> str:
    reach = attack_reach(finding.exposure)
    blast = blast_radius(finding.exposure)
    depth = attack_depth(finding.attack_path)
    risk = finding_risk(finding)

    lines: list[str] = []
    lines.append(_THIN)
    lines.append(f"VULNERABILITY #{index:02d} — {finding.title}")
    lines.append(_THIN)
    lines.append("")
    lines.append(f"Type:            {finding.vuln_class}")
    lines.append(f"Severity:        {finding.severity.value}")
    lines.append(f"Exploitability:  {finding.exploitability.value}")
    lines.append(f"Attacker:        {finding.attacker.label}")
    lines.append(f"Entry Point:     {finding.entry_point or '—'}")
    lines.append(f"Risk score:      {risk}")
    lines.append(f"Status:          {finding.status}")
    lines.append("")

    if finding.hypothesis:
        lines.append("HYPOTHESIS")
        lines.append(f"  {finding.hypothesis}")
        lines.append("")

    if finding.evidence:
        lines.append("EVIDENCE (sanitized)")
        for ln in finding.evidence.splitlines():
            lines.append(f"  {ln}")
        lines.append("")

    lines.append("ATTACK PATH")
    lines.extend(_attack_path_block(finding))
    lines.append("")
    lines.append(f"  Attack depth: {depth}")
    lines.append("")

    lines.append("IMPACT / EXPOSURE")
    if finding.exposure:
        for e in finding.exposure:
            tot = f"/{e.total}" if e.total is not None else ""
            flag = "  [sensitive]" if e.sensitive else ""
            lines.append(f"  {e.asset_type:<18} {e.accessible}{tot}{flag}")
    else:
        lines.append("  (none recorded)")
    lines.append("")
    lines.append(f"  Attack Reach:  {reach['fraction'] * 100:.4f}%  (level {reach['level']}/5)")
    lines.append(f"  Blast Radius:  {blast['records']} records "
                 f"({blast['sensitive_records']} sensitive)")
    lines.append("")

    if finding.root_cause:
        lines.append("ROOT CAUSE")
        for ln in finding.root_cause.splitlines():
            lines.append(f"  {ln}")
        lines.append("")

    if finding.invariant:
        lines.append("SECURITY INVARIANT TO RESTORE")
        lines.append(f"  {finding.invariant}")
        lines.append("")

    if finding.remediation:
        lines.append("REMEDIATION (root-cause fix)")
        for ln in finding.remediation.splitlines():
            lines.append(f"  {ln}")
        lines.append("")

    ra_lines = _reattack_lines(finding)
    if any("not tested" not in l for l in ra_lines[:1]) or finding.reattack.variants:
        lines.append("RE-ATTACK")
        lines.extend(f"  {l}" for l in ra_lines)
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# full report
# --------------------------------------------------------------------------- #
def render_report(assessment: Assessment) -> str:
    cur = assessment.current_state()
    lines: list[str] = []
    lines.append(_RULE)
    lines.append("THREAT THINKING REPORT")
    lines.append(_RULE)
    lines.append("")
    lines.append(f"Application:   {assessment.app}")
    lines.append(f"Assessment:    Attack Cycle #{assessment.cycle:02d}")
    if assessment.scope:
        lines.append(f"Scope:         {assessment.scope}")
    lines.append("")

    # ---- executive summary ------------------------------------------------ #
    by_sev: dict[str, int] = {}
    for f in assessment.findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    confirmed = sum(
        1 for f in assessment.findings if f.exploitability == Exploitability.CONFIRMED
    )
    lines.append("SUMMARY")
    lines.append(f"  Findings:            {len(assessment.findings)}")
    lines.append(f"  Confirmed exploits:  {confirmed}")
    lines.append(f"  By severity:         " + ", ".join(
        f"{k} {v}" for k, v in sorted(by_sev.items(), key=lambda kv: kv[0])
    ) if by_sev else "  By severity:         —")
    lines.append(f"  Residual risk:       {cur.risk}")
    lines.append("")

    # ---- improvement vs previous state ----------------------------------- #
    if assessment.previous_state:
        prev = assessment.previous_state
        imp = security_improvement(prev.risk, cur.risk)
        lines.append("PROGRESS vs PREVIOUS STATE")
        lines.append(f"  {prev.version:<12} risk {prev.risk:<8} -> "
                     f"{cur.version:<12} risk {cur.risk}")
        lines.append(f"  Security improvement: {imp}%")
        lines.append("")

    # ---- findings --------------------------------------------------------- #
    ordered = sorted(
        assessment.findings,
        key=lambda f: finding_risk(f),
        reverse=True,
    )
    for i, f in enumerate(ordered, start=1):
        lines.append(render_finding(f, i))

    lines.append(_RULE)
    lines.append("SECURITY STATE SNAPSHOT")
    lines.append(_RULE)
    for k, v in cur.to_dict().items():
        lines.append(f"  {k:<28} {v}")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# state diff
# --------------------------------------------------------------------------- #
def render_diff(before: SecurityState, after: SecurityState) -> str:
    imp = security_improvement(before.risk, after.risk)
    rows = [
        ("vulnerabilities", before.vulnerabilities, after.vulnerabilities),
        ("confirmed_exploits", before.confirmed_exploits, after.confirmed_exploits),
        ("critical_assets_reachable",
         before.critical_assets_reachable, after.critical_assets_reachable),
        ("attack_paths", before.attack_paths, after.attack_paths),
        ("risk", before.risk, after.risk),
    ]
    lines = [_RULE, "SECURITY STATE DIFF", _RULE, ""]
    lines.append(f"  {'metric':<28}{before.version:>10}{after.version:>12}   delta")
    lines.append("  " + _THIN)
    for name, b, a in rows:
        delta = round(a - b, 2)
        arrow = "↓" if delta < 0 else ("↑" if delta > 0 else "·")
        lines.append(f"  {name:<28}{b:>10}{a:>12}   {arrow} {delta}")
    lines.append("")
    lines.append(f"  Security improvement: {imp}%")
    lines.append("")
    return "\n".join(lines)
