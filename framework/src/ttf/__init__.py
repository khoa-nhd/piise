"""
TTF — Threat Thinking Framework
===============================

A lightweight, dependency-free toolkit for running a *threat-thinking loop*
over an application **you own / are developing** (the "vibe-coded" app).

The framework is a methodology first, code second. The code here does three
jobs that are tedious to do by hand:

  1. Model an assessment (findings, attack paths, exposure, security state).
  2. Compute the metrics that make a finding meaningful
     (Attack Reach, Attack Depth, Blast Radius, Risk, Security Improvement).
  3. Render a human-readable Threat Report and diff two security states.

The actual "think like an attacker / try to attack" work is done by you (or an
AI pair-programmer) against your own application, guided by docs/ and prompts/.

Scope guardrail
---------------
This toolkit is for authorized self-assessment only: applications you build,
own, or have written permission to test. See `.ttf/scope.example.json`.
"""

from .models import (
    Severity,
    Exploitability,
    AttackerProfile,
    AssetExposure,
    AttackStep,
    AttackPath,
    Finding,
    SecurityState,
    Assessment,
)
from .metrics import (
    reach_level,
    attack_reach,
    attack_depth,
    blast_radius,
    finding_risk,
    assessment_risk,
    security_improvement,
)
from .detectors import scan_path, scan_text, DETECTORS
from .prober import run_probe, load_config, ScopeError
from .importers import detect_and_parse, parse_sarif, parse_ttf_findings

__version__ = "0.1.0"

__all__ = [
    "Severity",
    "Exploitability",
    "AttackerProfile",
    "AssetExposure",
    "AttackStep",
    "AttackPath",
    "Finding",
    "SecurityState",
    "Assessment",
    "reach_level",
    "attack_reach",
    "attack_depth",
    "blast_radius",
    "finding_risk",
    "assessment_risk",
    "security_improvement",
    "scan_path",
    "scan_text",
    "DETECTORS",
    "run_probe",
    "load_config",
    "ScopeError",
    "detect_and_parse",
    "parse_sarif",
    "parse_ttf_findings",
    "__version__",
]
