"""
H1 — ingest findings from mature external scanners instead of relying on the
built-in regex engine.

Key idea: every modern SAST tool can emit **SARIF** (a standard JSON format):
Semgrep, gitleaks, CodeQL, Bandit, Trivy, osv-scanner, ... So TTF only needs one
adapter: SARIF -> Finding. That instantly gives thousands of AST-based rules +
dependency-CVE coverage that regex can never match.

Also supports importing TTF-shaped finding JSON (e.g. produced by an LLM scan, H2).

Dependency-free: json + subprocess + shutil from the standard library. The
external tools are optional — if one is not installed, the runner says so and
TTF falls back to the built-in regex engine.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .models import Finding, Severity, Exploitability, AttackerProfile


# --------------------------------------------------------------------------- #
# classification: map a tool's ruleId/message to a TTF vuln_class
# --------------------------------------------------------------------------- #
_CLASS_KEYWORDS: list[tuple[str, str]] = [
    ("sql", "Injection (SQL)"),
    ("nosql", "Injection (NoSQL)"),
    ("xss", "Cross-site scripting (XSS)"),
    ("cross-site-scripting", "Cross-site scripting (XSS)"),
    ("ssrf", "SSRF"),
    ("idor", "Broken Object Level Authorization (IDOR)"),
    ("bola", "Broken Object Level Authorization (IDOR)"),
    ("broken-access", "Broken access control"),
    ("access-control", "Broken access control"),
    ("authoriz", "Broken access control"),
    ("authz", "Broken access control"),
    ("path-traversal", "Path traversal"),
    ("pathtraversal", "Path traversal"),
    ("traversal", "Path traversal"),
    ("deserial", "Insecure deserialization"),
    ("pickle", "Insecure deserialization"),
    ("command", "Injection (command/eval)"),
    ("os-command", "Injection (command/eval)"),
    ("rce", "Injection (command/eval)"),
    ("code-injection", "Injection (command/eval)"),
    ("subprocess", "Injection (command/eval)"),
    ("shell", "Injection (command/eval)"),
    ("eval", "Injection (command/eval)"),
    ("secret", "Secrets exposure"),
    ("hardcoded", "Secrets exposure"),
    ("api-key", "Secrets exposure"),
    ("credential", "Secrets exposure"),
    ("password", "Secrets exposure"),
    ("token", "Secrets exposure"),
    ("crypto", "Weak cryptography"),
    ("md5", "Weak cryptography"),
    ("sha1", "Weak cryptography"),
    ("weak-hash", "Weak cryptography"),
    ("cipher", "Weak cryptography"),
    ("cors", "CORS misconfiguration"),
    ("csrf", "CSRF"),
    ("redirect", "Open redirect"),
    ("jwt", "Authentication weakness"),
    ("auth", "Authentication weakness"),
    ("cve", "Vulnerable dependency"),
    ("ghsa", "Vulnerable dependency"),
    ("dependency", "Vulnerable dependency"),
    ("outdated", "Vulnerable dependency"),
    ("vuln", "Vulnerable dependency"),
]


def _norm(s: str) -> str:
    """Lowercase and turn every run of non-alphanumerics into a single space,
    padded with spaces so we can match whole words / word-prefixes."""
    return " " + re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip() + " "


def _classify(rule_id: str, message: str, tags: list[str]) -> str:
    blob = _norm(" ".join([rule_id or "", message or "", " ".join(tags or [])]))
    for kw, cls in _CLASS_KEYWORDS:
        k = _norm(kw).rstrip()          # keep leading space -> must start at a word boundary
        # match keyword as a word or word-prefix (so 'authoriz' matches 'authorization')
        if k in blob or (k + " ") in blob:
            return cls
    return f"Static finding ({rule_id})" if rule_id else "Static finding"


def _sev_from_cvss(value: Any) -> Severity | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f >= 9.0:
        return Severity.CRITICAL
    if f >= 7.0:
        return Severity.HIGH
    if f >= 4.0:
        return Severity.MEDIUM
    if f > 0:
        return Severity.LOW
    return Severity.INFO


def _sev_from_level(level: str) -> Severity:
    return {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "note": Severity.LOW,
        "none": Severity.LOW,
        "info": Severity.INFO,
    }.get((level or "warning").lower(), Severity.MEDIUM)


def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", (s or "rule")).strip("-")[:40] or "rule"


# --------------------------------------------------------------------------- #
# SARIF parsing
# --------------------------------------------------------------------------- #
def parse_sarif_obj(obj: dict[str, Any], tool_hint: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for run in obj.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = tool_hint or driver.get("name", "sast")
        # build rule lookup by id and by index
        rules = driver.get("rules", []) or []
        rule_by_id: dict[str, dict] = {}
        for idx, r in enumerate(rules):
            rid = r.get("id") or r.get("name") or f"idx{idx}"
            rule_by_id[rid] = r
        for res in run.get("results", []):
            rule_id = res.get("ruleId") or ""
            if not rule_id and "rule" in res:
                i = (res.get("rule") or {}).get("index")
                if isinstance(i, int) and 0 <= i < len(rules):
                    rule_id = rules[i].get("id", "")
            rdef = rule_by_id.get(rule_id, {})
            props = rdef.get("properties", {}) or {}
            tags = props.get("tags", []) or []
            message = ((res.get("message") or {}).get("text") or "").strip()
            # location
            uri, line = "", 0
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0].get("physicalLocation") or {})
                uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
                line = ((phys.get("region") or {}).get("startLine") or 0)
            # severity: prefer CVSS security-severity, else SARIF level
            sev = (
                _sev_from_cvss(props.get("security-severity"))
                or _sev_from_cvss((res.get("properties") or {}).get("security-severity"))
                or _sev_from_level(res.get("level", ""))
            )
            vclass = _classify(rule_id, message, tags)
            where = f"{uri}:{line}" if uri else rule_id
            fid = f"I-{_slug(tool)}-{_slug(rule_id)}-{hashlib.sha1(where.encode()).hexdigest()[:8]}"
            short = (rdef.get("shortDescription") or {}).get("text") or message or rule_id
            findings.append(Finding(
                id=fid,
                title=(short or rule_id)[:120],
                vuln_class=vclass,
                severity=sev,
                exploitability=Exploitability.POTENTIAL,
                attacker=AttackerProfile.EXTERNAL,
                entry_point=where,
                hypothesis=f"[{tool}:{rule_id}] {message}"[:400],
                evidence=f"{where}: {message}"[:500],
                status="OPEN",
                tags=["sarif", _slug(tool)] + [t for t in tags if isinstance(t, str)][:6],
            ))
    return findings


def parse_sarif(path: str, tool_hint: str = "") -> list[Finding]:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_sarif_obj(obj, tool_hint=tool_hint)


# --------------------------------------------------------------------------- #
# TTF-shaped JSON (e.g. LLM scan output, H2)
# --------------------------------------------------------------------------- #
def parse_ttf_findings(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of findings, or {\"findings\": [...]}.")
    return [Finding.from_dict(d) for d in data]


def detect_and_parse(path: str, fmt: str = "auto", tool_hint: str = "") -> list[Finding]:
    if fmt == "sarif":
        return parse_sarif(path, tool_hint)
    if fmt == "ttf":
        return parse_ttf_findings(path)
    # auto-detect
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(obj, dict) and ("runs" in obj or obj.get("$schema", "").find("sarif") >= 0):
        return parse_sarif_obj(obj, tool_hint)
    if isinstance(obj, dict) and "findings" in obj:
        return [Finding.from_dict(d) for d in obj["findings"]]
    if isinstance(obj, list):
        return [Finding.from_dict(d) for d in obj]
    raise ValueError("Could not detect format; pass --format sarif|ttf.")


# --------------------------------------------------------------------------- #
# optional external tool runners (shell out; graceful if not installed)
# --------------------------------------------------------------------------- #
def _run_to_sarif(cmd: list[str], out_sarif: Path, timeout: int = 300) -> None:
    subprocess.run(cmd, check=False, capture_output=True, timeout=timeout)


def run_semgrep(path: str) -> tuple[list[Finding], str]:
    if not shutil.which("semgrep"):
        return [], "semgrep not installed (pip install semgrep) — skipped"
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "semgrep.sarif"
        try:
            subprocess.run(
                ["semgrep", "scan", "--sarif", "--quiet", "--config", "auto",
                 "-o", str(out), path],
                check=False, capture_output=True, timeout=600,
            )
            if out.exists():
                return parse_sarif(str(out), tool_hint="semgrep"), "ok"
        except (subprocess.TimeoutExpired, OSError) as e:
            return [], f"semgrep error: {e}"
    return [], "semgrep produced no output"


def run_gitleaks(path: str) -> tuple[list[Finding], str]:
    if not shutil.which("gitleaks"):
        return [], "gitleaks not installed — skipped"
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "gitleaks.sarif"
        try:
            subprocess.run(
                ["gitleaks", "detect", "--no-git", "--report-format", "sarif",
                 "--report-path", str(out), "--source", path],
                check=False, capture_output=True, timeout=300,
            )
            if out.exists():
                return parse_sarif(str(out), tool_hint="gitleaks"), "ok"
        except (subprocess.TimeoutExpired, OSError) as e:
            return [], f"gitleaks error: {e}"
    return [], "gitleaks produced no output"
