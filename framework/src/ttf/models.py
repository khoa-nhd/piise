"""
Data models for a Threat Thinking assessment.

Everything is a plain dataclass with `from_dict` / `to_dict` helpers so an
assessment can live in a single JSON file that both humans and the CLI edit.
No third-party dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    """Qualitative impact rating. `weight` feeds the risk score."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> float:
        return {
            "INFO": 1.0,
            "LOW": 2.0,
            "MEDIUM": 4.0,
            "HIGH": 7.0,
            "CRITICAL": 10.0,
        }[self.value]


class Exploitability(str, Enum):
    """How far a finding has been proven.

    The whole point of the framework: do not stop at POTENTIAL.
    BLOCKED is used after a fix is verified (re-attack failed).
    """

    POTENTIAL = "POTENTIAL"      # hypothesis only, from static reasoning
    PLAUSIBLE = "PLAUSIBLE"      # strong signal, not yet proven end-to-end
    CONFIRMED = "CONFIRMED"      # reproduced against the running app
    BLOCKED = "BLOCKED"          # was confirmed, now verified fixed

    @property
    def factor(self) -> float:
        return {
            "POTENTIAL": 0.4,
            "PLAUSIBLE": 0.7,
            "CONFIRMED": 1.0,
            "BLOCKED": 0.0,
        }[self.value]


class AttackerProfile(str, Enum):
    """Capability tier the finding assumes (Phase 1 mindset)."""

    EXTERNAL = "EXTERNAL"               # unauthenticated, from the internet
    AUTHENTICATED = "AUTHENTICATED"     # ordinary logged-in user
    INSIDER = "INSIDER"                 # valid account with extra context
    PRIVILEGED = "PRIVILEGED"           # staff/admin-adjacent

    @property
    def label(self) -> str:
        return {
            "EXTERNAL": "External attacker (unauthenticated)",
            "AUTHENTICATED": "Authenticated normal user",
            "INSIDER": "Malicious insider",
            "PRIVILEGED": "Privileged / staff account",
        }[self.value]


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #
@dataclass
class AssetExposure:
    """What the attacker could actually reach — the core of Phase 4.

    `accessible` out of `total` of a given asset type. `sensitive` marks
    records whose exposure is itself the impact (PII, secrets, payment data).
    """

    asset_type: str                 # e.g. "user_profile", "order", "email"
    accessible: int = 0
    total: Optional[int] = None     # size of the relevant dataset, if known
    sensitive: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_type": self.asset_type,
            "accessible": self.accessible,
            "total": self.total,
            "sensitive": self.sensitive,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AssetExposure":
        return cls(
            asset_type=d["asset_type"],
            accessible=int(d.get("accessible", 0)),
            total=d.get("total"),
            sensitive=bool(d.get("sensitive", False)),
            note=d.get("note", ""),
        )


@dataclass
class AttackStep:
    """One hop along an attack path (Phase 5).

    `kind` is one of: entry, weakness, boundary, resource, asset.
    Rendering draws them top-to-bottom with arrows.
    """

    kind: str
    label: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "label": self.label}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackStep":
        return cls(kind=d["kind"], label=d["label"])


@dataclass
class AttackPath:
    """From entry point to sensitive asset. Depth = number of steps."""

    id: str
    entry_point: str
    steps: list[AttackStep] = field(default_factory=list)
    impact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entry_point": self.entry_point,
            "steps": [s.to_dict() for s in self.steps],
            "impact": self.impact,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackPath":
        return cls(
            id=d["id"],
            entry_point=d["entry_point"],
            steps=[AttackStep.from_dict(s) for s in d.get("steps", [])],
            impact=d.get("impact", ""),
        )


@dataclass
class ReAttack:
    """Result of re-running exploits after a fix (Phase 7).

    Each entry is a short label plus whether the app still fell.
    `blocked=True` means the attack was stopped (good).
    """

    original_blocked: Optional[bool] = None
    variants: list[dict[str, Any]] = field(default_factory=list)
    regressions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_blocked": self.original_blocked,
            "variants": self.variants,
            "regressions": self.regressions,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ReAttack":
        return cls(
            original_blocked=d.get("original_blocked"),
            variants=list(d.get("variants", [])),
            regressions=list(d.get("regressions", [])),
        )


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """One vulnerability, carried through the whole loop."""

    id: str
    title: str
    vuln_class: str                              # e.g. "Broken Object Level Authorization"
    severity: Severity = Severity.MEDIUM
    exploitability: Exploitability = Exploitability.POTENTIAL
    attacker: AttackerProfile = AttackerProfile.AUTHENTICATED
    entry_point: str = ""
    hypothesis: str = ""                          # Phase 2/3 "if I were an attacker..."
    evidence: str = ""                            # Phase 3 proof (sanitized)
    exposure: list[AssetExposure] = field(default_factory=list)
    attack_path: Optional[AttackPath] = None
    root_cause: str = ""                          # Phase 6 — the invariant that broke
    invariant: str = ""                           # the security rule to restore
    remediation: str = ""                         # Phase 6 — root-cause fix
    reattack: ReAttack = field(default_factory=ReAttack)
    status: str = "OPEN"                          # OPEN | FIXED | RESOLVED | ACCEPTED
    tags: list[str] = field(default_factory=list)

    # -- serialization ----------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "vuln_class": self.vuln_class,
            "severity": self.severity.value,
            "exploitability": self.exploitability.value,
            "attacker": self.attacker.value,
            "entry_point": self.entry_point,
            "hypothesis": self.hypothesis,
            "evidence": self.evidence,
            "exposure": [e.to_dict() for e in self.exposure],
            "attack_path": self.attack_path.to_dict() if self.attack_path else None,
            "root_cause": self.root_cause,
            "invariant": self.invariant,
            "remediation": self.remediation,
            "reattack": self.reattack.to_dict(),
            "status": self.status,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            id=d["id"],
            title=d["title"],
            vuln_class=d.get("vuln_class", ""),
            severity=Severity(d.get("severity", "MEDIUM")),
            exploitability=Exploitability(d.get("exploitability", "POTENTIAL")),
            attacker=AttackerProfile(d.get("attacker", "AUTHENTICATED")),
            entry_point=d.get("entry_point", ""),
            hypothesis=d.get("hypothesis", ""),
            evidence=d.get("evidence", ""),
            exposure=[AssetExposure.from_dict(e) for e in d.get("exposure", [])],
            attack_path=AttackPath.from_dict(d["attack_path"])
            if d.get("attack_path")
            else None,
            root_cause=d.get("root_cause", ""),
            invariant=d.get("invariant", ""),
            remediation=d.get("remediation", ""),
            reattack=ReAttack.from_dict(d.get("reattack", {})),
            status=d.get("status", "OPEN"),
            tags=list(d.get("tags", [])),
        )


# --------------------------------------------------------------------------- #
# Security state snapshot (Phase 8 / versioning)
# --------------------------------------------------------------------------- #
@dataclass
class SecurityState:
    """A point-in-time snapshot used to show progress across loop cycles."""

    version: str
    vulnerabilities: int = 0
    confirmed_exploits: int = 0
    critical_assets_reachable: int = 0
    attack_paths: int = 0
    risk: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "vulnerabilities": self.vulnerabilities,
            "confirmed_exploits": self.confirmed_exploits,
            "critical_assets_reachable": self.critical_assets_reachable,
            "attack_paths": self.attack_paths,
            "risk": round(self.risk, 2),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SecurityState":
        return cls(
            version=d["version"],
            vulnerabilities=int(d.get("vulnerabilities", 0)),
            confirmed_exploits=int(d.get("confirmed_exploits", 0)),
            critical_assets_reachable=int(d.get("critical_assets_reachable", 0)),
            attack_paths=int(d.get("attack_paths", 0)),
            risk=float(d.get("risk", 0.0)),
        )


# --------------------------------------------------------------------------- #
# Assessment (the whole document)
# --------------------------------------------------------------------------- #
@dataclass
class Assessment:
    """Top-level container — one JSON file per assessment cycle."""

    app: str
    cycle: int = 1
    scope: str = ""                              # authorized scope, in words
    findings: list[Finding] = field(default_factory=list)
    previous_state: Optional[SecurityState] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "app": self.app,
            "cycle": self.cycle,
            "scope": self.scope,
            "findings": [f.to_dict() for f in self.findings],
            "previous_state": self.previous_state.to_dict()
            if self.previous_state
            else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Assessment":
        return cls(
            app=d["app"],
            cycle=int(d.get("cycle", 1)),
            scope=d.get("scope", ""),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            previous_state=SecurityState.from_dict(d["previous_state"])
            if d.get("previous_state")
            else None,
        )

    # -- convenience -------------------------------------------------------- #
    def current_state(self) -> SecurityState:
        """Derive a SecurityState snapshot from the current findings."""
        from .metrics import assessment_risk  # local import avoids cycle

        open_findings = [f for f in self.findings if f.status != "RESOLVED"]
        confirmed = [
            f for f in self.findings if f.exploitability == Exploitability.CONFIRMED
        ]
        crit_reachable = sum(
            1
            for f in self.findings
            if f.exploitability == Exploitability.CONFIRMED
            and any(e.sensitive for e in f.exposure)
        )
        paths = sum(1 for f in self.findings if f.attack_path is not None)
        return SecurityState(
            version=f"cycle-{self.cycle}",
            vulnerabilities=len(open_findings),
            confirmed_exploits=len(confirmed),
            critical_assets_reachable=crit_reachable,
            attack_paths=paths,
            risk=assessment_risk(self),
        )
