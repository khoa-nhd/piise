"""
① Static scanner — walk source files, apply heuristic detectors, and emit
candidate Findings into an assessment.

Dependency-free (regex only). Detectors are intentionally conservative but a
scanner cannot *prove* anything, so every finding it creates is
`exploitability = POTENTIAL`. Confirm them with the active prober (②) or by hand.

Secret values are masked before being written to evidence — the scanner never
stores a full secret.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Pattern

from .models import Finding, Severity, Exploitability, AttackerProfile


# --------------------------------------------------------------------------- #
# Detector definition
# --------------------------------------------------------------------------- #
@dataclass
class Detector:
    id: str
    vuln_class: str
    severity: Severity
    message: str                       # becomes the finding hypothesis/title
    pattern: Pattern[str]
    attacker: AttackerProfile = AttackerProfile.EXTERNAL
    mask_match: bool = False           # True for secrets -> redact matched text
    tags: list[str] = field(default_factory=list)


def _rx(p: str) -> Pattern[str]:
    return re.compile(p)


# --------------------------------------------------------------------------- #
# Detector catalogue (maps to docs/threat-catalog.md)
# --------------------------------------------------------------------------- #
DETECTORS: list[Detector] = [
    Detector(
        "secret-generic", "Secrets exposure", Severity.HIGH,
        "Hardcoded secret/credential assigned in source.",
        _rx(r"""(?i)\b(api[_-]?key|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*['"][^'"]{6,}['"]"""),
        mask_match=True, tags=["secret"],
    ),
    Detector(
        "secret-aws", "Secrets exposure", Severity.HIGH,
        "AWS access key id pattern in source.",
        _rx(r"\bAKIA[0-9A-Z]{16}\b"), mask_match=True, tags=["secret", "aws"],
    ),
    Detector(
        "private-key", "Secrets exposure", Severity.CRITICAL,
        "Private key material committed in source.",
        _rx(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        mask_match=True, tags=["secret", "key"],
    ),
    Detector(
        "sql-fstring", "Injection (SQL)", Severity.HIGH,
        "SQL built with an f-string / interpolation passed to execute().",
        _rx(r"""(?i)(execute|executemany|query|cursor\.execute)\s*\(\s*f["'][^"']*(select|insert|update|delete|drop)\b"""),
        tags=["injection", "sql"],
    ),
    Detector(
        "sql-concat", "Injection (SQL)", Severity.HIGH,
        "SQL string concatenated with a variable.",
        _rx(r"""(?i)\b(select|insert into|update|delete from)\b[^;\n]*["']\s*\+\s*\w"""),
        tags=["injection", "sql"],
    ),
    Detector(
        "cors-wildcard", "CORS misconfiguration", Severity.MEDIUM,
        "CORS allows any origin ('*').",
        _rx(r"""(?i)(access-control-allow-origin['"\s:=]+\*|origin\s*:\s*['"]\*['"]|cors\(\s*\{\s*origin\s*:\s*['"]\*['"])"""),
        tags=["cors"],
    ),
    Detector(
        "jwt-weak", "Authentication weakness", Severity.HIGH,
        "JWT verification disabled or 'none' algorithm allowed.",
        _rx(r"""(?i)(algorithms?\s*[:=]\s*\[?\s*['"]none['"]|verify(_signature)?\s*[:=]\s*(False|false|0)|['"]?verify['"]?\s*:\s*false)"""),
        tags=["authn", "jwt"],
    ),
    Detector(
        "dangerous-exec", "Injection (command/eval)", Severity.HIGH,
        "Dynamic code/command execution on possibly tainted input.",
        _rx(r"""(?i)(\beval\s*\(|\bexec\s*\(|os\.system\s*\(|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|child_process\.exec\s*\()"""),
        tags=["injection", "rce"],
    ),
    Detector(
        "insecure-deser", "Insecure deserialization", Severity.HIGH,
        "Unsafe deserialization of untrusted data.",
        _rx(r"""(?i)(pickle\.loads\s*\(|yaml\.load\s*\((?![^)]*Loader))"""),
        tags=["deserialization"],
    ),
    Detector(
        "debug-on", "Insecure configuration", Severity.MEDIUM,
        "Debug mode / TLS verification disabled.",
        _rx(r"""(?i)(debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0)"""),
        tags=["config"],
    ),
    Detector(
        "weak-hash", "Weak hashing", Severity.LOW,
        "Weak hash (md5/sha1) — unsafe for passwords.",
        _rx(r"""(?i)\b(md5|sha1)\s*\("""), tags=["crypto"],
    ),
    Detector(
        "idor-route", "Broken Object Level Authorization (IDOR)", Severity.HIGH,
        "Route takes an object id — verify it checks ownership (run ttf probe).",
        _rx(r"""(?i)(@app\.route\(['"][^'"]*<[^>]*id[^>]*>|(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"][^'"]*[:{]id)"""),
        attacker=AttackerProfile.AUTHENTICATED, tags=["idor", "authz", "needs-probe"],
    ),
]


# --------------------------------------------------------------------------- #
# File walking
# --------------------------------------------------------------------------- #
_SCAN_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".rb",
    ".go", ".php", ".cs", ".env", ".yml", ".yaml", ".ini", ".cfg", ".conf",
    ".html", ".htm", ".sql", ".sh",
}
_SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "dist", "build",
    "__pycache__", ".ttf", ".idea", ".vscode", "coverage", ".next",
}
_MAX_BYTES = 2_000_000  # skip files larger than ~2 MB


def _mask(text: str) -> str:
    """Mask the sensitive portion of a line so no full secret is stored."""
    def repl(m: re.Match) -> str:
        s = m.group(0)
        if len(s) <= 6:
            return "***"
        return s[:3] + "***" + s[-2:]
    # mask any quoted string of length >=6, and long unquoted tokens
    text = re.sub(r"""['"][^'"]{6,}['"]""", lambda m: _mask_inner(m.group(0)), text)
    text = re.sub(r"\b[A-Za-z0-9/+_\-]{20,}\b", repl, text)
    return text


def _mask_inner(quoted: str) -> str:
    q = quoted[0]
    body = quoted[1:-1]
    if len(body) <= 4:
        masked = "***"
    else:
        masked = body[:2] + "***" + body[-2:]
    return f"{q}{masked}{q}"


def _stable_id(rule: str, rel: str, lineno: int) -> str:
    h = hashlib.sha1(f"{rule}:{rel}:{lineno}".encode()).hexdigest()[:8]
    return f"S-{rule}-{h}"


def scan_text(text: str, rel: str) -> list[Finding]:
    """Scan one file's text, returning candidate findings."""
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if len(line) > 1000:  # minified/bundled line — skip to limit noise
            continue
        for det in DETECTORS:
            if det.pattern.search(line):
                evidence_line = _mask(line).strip() if det.mask_match else line.strip()
                findings.append(
                    Finding(
                        id=_stable_id(det.id, rel, i),
                        title=det.message,
                        vuln_class=det.vuln_class,
                        severity=det.severity,
                        exploitability=Exploitability.POTENTIAL,
                        attacker=det.attacker,
                        entry_point=f"{rel}:{i}",
                        hypothesis=det.message,
                        evidence=f"{rel}:{i}: {evidence_line}",
                        status="OPEN",
                        tags=list(det.tags) + ["static-scan"],
                    )
                )
    return findings


def scan_path(root: str) -> list[Finding]:
    """Recursively scan a file or directory."""
    base = Path(root)
    findings: list[Finding] = []
    files: list[Path] = []
    if base.is_file():
        files = [base]
    else:
        for p in base.rglob("*"):
            if p.is_dir():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() not in _SCAN_EXT:
                continue
            files.append(p)
    for p in files:
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(base)) if base.is_dir() else p.name
        rel = rel.replace("\\", "/")
        findings.extend(scan_text(text, rel))
    return findings
