"""
Metrics that turn "there is a vulnerability" into "an attacker with capability
X reaches Y, and that is Z serious".

Every function here is pure and documented so the numbers in a report are
reproducible and explainable — no black boxes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cycle at runtime
    from .models import Finding, Assessment, AttackPath, AssetExposure


# --------------------------------------------------------------------------- #
# Attack Reach — how much of the relevant asset space is reachable
# --------------------------------------------------------------------------- #
def reach_level(fraction: float, has_privileged: bool = False) -> int:
    """Map a reach fraction to the 0..5 qualitative scale.

        0 = no meaningful access
        1 = own data only
        2 = another single user's data
        3 = multiple users' data
        4 = privileged data
        5 = system-wide / critical assets

    `has_privileged` bumps the level to >=4 when privileged/admin data is in
    the exposed set regardless of count.
    """
    if has_privileged:
        return 5 if fraction >= 0.5 else 4
    if fraction <= 0.0:
        return 0
    if fraction < 1e-9:
        return 1
    if fraction <= 0.0002:        # a handful of records in a large dataset
        return 2
    if fraction < 0.5:
        return 3
    return 5


def attack_reach(exposures: "list[AssetExposure]") -> dict[str, float | int]:
    """Aggregate reach across all exposed asset types.

    Returns a dict with the dominant fraction, the 0..5 level and totals.
    Fraction is computed over asset types that declare a `total`.
    """
    accessible = 0
    total = 0
    has_privileged = False
    for e in exposures:
        if e.total:
            accessible += e.accessible
            total += e.total
        if e.sensitive and e.accessible > 0:
            # sensitive singletons (secrets, admin) count as privileged reach
            has_privileged = has_privileged or e.asset_type in {
                "secret",
                "admin",
                "credential",
                "payment",
                "token",
            }
    fraction = (accessible / total) if total else 0.0
    return {
        "accessible": accessible,
        "total": total,
        "fraction": round(fraction, 6),
        "level": reach_level(fraction, has_privileged),
    }


# --------------------------------------------------------------------------- #
# Attack Depth — how many hops to the sensitive asset
# --------------------------------------------------------------------------- #
def attack_depth(path: "AttackPath | None") -> int:
    """Number of steps from entry to asset. Directly-exposed = 1."""
    if path is None:
        return 0
    return max(1, len(path.steps))


# --------------------------------------------------------------------------- #
# Blast Radius — how many assets are potentially affected
# --------------------------------------------------------------------------- #
def blast_radius(exposures: "list[AssetExposure]") -> dict[str, float | int]:
    """Count + proportion of affected assets.

    Two findings can share a severity rating yet have wildly different blast
    radius (1 user vs 10,000). This surfaces that difference explicitly.
    """
    records = sum(e.accessible for e in exposures)
    sensitive_records = sum(e.accessible for e in exposures if e.sensitive)
    totals = [e.total for e in exposures if e.total]
    proportion = (records / sum(totals)) if totals else 0.0
    return {
        "records": records,
        "sensitive_records": sensitive_records,
        "proportion": round(proportion, 6),
    }


# --------------------------------------------------------------------------- #
# Risk — severity x exploitability x blast
# --------------------------------------------------------------------------- #
def finding_risk(finding: "Finding") -> float:
    """A 0..10-ish risk score combining the three dimensions.

        risk = severity.weight          # 1..10  "how bad if it lands"
             * exploitability.factor    # 0..1   "will it land"
             * blast_scale              # 0.3..1 "how wide"

    A BLOCKED finding scores 0 (exploitability.factor == 0), which is what
    lets Security Improvement drop after a verified fix.
    """
    reach = attack_reach(finding.exposure)
    # blast_scale: floor of 0.3 so a confirmed single-record leak still counts,
    # scaling up with reach level toward 1.0 for system-wide reach.
    blast_scale = 0.3 + 0.7 * (int(reach["level"]) / 5.0)
    score = finding.severity.weight * finding.exploitability.factor * blast_scale
    return round(score, 2)


def assessment_risk(assessment: "Assessment") -> float:
    """Total residual risk across all findings (sum of finding risks)."""
    return round(sum(finding_risk(f) for f in assessment.findings), 2)


# --------------------------------------------------------------------------- #
# Security Improvement — before vs after
# --------------------------------------------------------------------------- #
def security_improvement(pre_risk: float, post_risk: float) -> float:
    """Percentage reduction in risk.

        improvement = 1 - post / pre

    Returns 0.0 when pre_risk is 0 (nothing to improve).
    """
    if pre_risk <= 0:
        return 0.0
    return round((1.0 - (post_risk / pre_risk)) * 100.0, 2)
