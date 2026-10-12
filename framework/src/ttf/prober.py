"""
② Active probe harness — actually exercises access-control weaknesses against an
application **you own**, running locally, with test accounts.

H4: supports several attack classes, chosen per target by its "type":
  - "idor"            cross-user object read (default)
  - "function-authz"  normal user reaches a privileged/admin endpoint
  - "mass-assignment" normal user sets a forbidden field (e.g. role=admin)
  - "auth-bypass"     a protected endpoint responds with no authentication

Each one does the real thing (sends requests, observes the response) and raises
the finding to CONFIRMED / BLOCKED based on what the server actually returns.

Dependency-free: urllib + http.cookiejar. Hard scope guardrails below.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
import http.cookiejar
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urljoin

from .models import (
    Finding, Severity, Exploitability, AttackerProfile,
    AssetExposure, AttackPath, AttackStep, ReAttack,
)

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_SENSITIVE_KEYS = {
    "email", "mail", "phone", "password", "pass", "passwd", "token", "secret",
    "ssn", "address", "card", "cvv", "iban", "dob", "national_id", "role",
}


class ScopeError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# scope guardrail
# --------------------------------------------------------------------------- #
def assert_in_scope(config: dict[str, Any]) -> str:
    base = config.get("base_url", "")
    if not config.get("scope_ack"):
        raise ScopeError(
            "Refusing to probe: set \"scope_ack\": true in the config to confirm "
            "you own/are authorized to test this target."
        )
    host = (urlparse(base).hostname or "").lower()
    is_local = (host in _LOCAL_HOSTS or host.endswith(".localhost")
                or host.endswith(".test"))
    if not is_local and not config.get("i_own_target"):
        raise ScopeError(
            f"Refusing to probe non-local host '{host}'. If you own this target, "
            f"set \"i_own_target\": true in the config. Otherwise this is out of scope."
        )
    return base


# --------------------------------------------------------------------------- #
# minimal HTTP session
# --------------------------------------------------------------------------- #
@dataclass
class Session:
    base_url: str
    token: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"

    def __post_init__(self) -> None:
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar)
        )

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.token:
            scheme = f"{self.auth_scheme} " if self.auth_scheme else ""
            h[self.auth_header] = f"{scheme}{self.token}"
        return h

    def request(self, path: str, method: str = "GET",
                body: dict | None = None) -> tuple[int, bytes]:
        url = urljoin(self.base_url, path)
        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp = self._opener.open(req, timeout=10)
            return resp.getcode(), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read() or b""
        except urllib.error.URLError as e:
            raise ScopeError(f"Cannot reach {url}: {e.reason}") from e


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _login(config: dict[str, Any], account: dict[str, Any]) -> Session:
    auth = config.get("auth", {})
    sess = Session(
        base_url=config["base_url"],
        auth_header=auth.get("auth_header", "Authorization"),
        auth_scheme=auth.get("auth_scheme", "Bearer"),
    )
    login_url = auth.get("login_url")
    if not login_url:
        return sess
    user_field = auth.get("username_field", "username")
    pass_field = auth.get("password_field", "password")
    body = {user_field: account["username"], pass_field: account["password"]}
    status, raw = sess.request(login_url, method=auth.get("method", "POST"), body=body)
    if status >= 400:
        raise ScopeError(f"Login failed for {account['username']} (HTTP {status}).")
    token_field = auth.get("token_field")
    if token_field:
        try:
            sess.token = _dig(json.loads(raw.decode() or "{}"), token_field)
        except json.JSONDecodeError:
            sess.token = None
    return sess


# --------------------------------------------------------------------------- #
# response helpers
# --------------------------------------------------------------------------- #
def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode() or "null")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _leaked_sensitive_keys(raw: bytes) -> list[str]:
    obj = _json(raw)
    found: set[str] = set()

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k.lower() in _SENSITIVE_KEYS:
                    found.add(k.lower())
                walk(v)
        elif isinstance(o, list):
            for it in o:
                walk(it)

    walk(obj)
    return sorted(found)


def _is_accessible(status: int, raw: bytes) -> bool:
    return 200 <= status < 300 and len(raw) > 2


def _plus_one(v: Any) -> Any:
    try:
        return int(v) + 1
    except (TypeError, ValueError):
        return f"{v}1"


def _make_finding(**kw: Any) -> Finding:
    return Finding(**kw)


# --------------------------------------------------------------------------- #
# attack modules
# --------------------------------------------------------------------------- #
def _probe_idor(config, attacker, name_hint, t, reattack) -> Finding:
    tmpl = t["url_template"]
    method = t.get("method", "GET")
    ids = t.get("ids", [])
    sensitive = bool(t.get("sensitive", False))
    asset_type = t.get("asset_type", t["name"])

    accessible = 0
    leaked: set[str] = set()
    statuses: list[int] = []
    for oid in ids:
        status, raw = attacker.request(tmpl.format(id=oid), method=method)
        statuses.append(status)
        if _is_accessible(status, raw):
            accessible += 1
            leaked.update(_leaked_sensitive_keys(raw))

    variants: list[dict[str, Any]] = []
    if ids:
        for label, vid in [("id=0", 0), ("id=-1", -1),
                           (f"id+1 ({ids[0]}+1)", _plus_one(ids[0]))]:
            try:
                vs, vr = attacker.request(tmpl.format(id=vid), method=method)
                variants.append({"label": label, "blocked": not _is_accessible(vs, vr)})
            except Exception:
                pass

    exploit = accessible > 0
    note = (f"leaked fields: {', '.join(sorted(leaked))}" if leaked
            else "no sensitive field names detected")
    return _make_finding(
        id=f"P-{t['name']}", title=f"{t['name']}: cross-user object access via id",
        vuln_class="Broken Object Level Authorization (IDOR)",
        severity=Severity.HIGH if (sensitive or leaked) else Severity.MEDIUM,
        exploitability=_expl(exploit, reattack),
        attacker=AttackerProfile.AUTHENTICATED, entry_point=f"{method} {tmpl}",
        hypothesis=f"Changing id in {tmpl} may return another user's {asset_type}.",
        evidence=(f"As '{name_hint}', requested {len(ids)} object(s) of another user "
                  f"via {tmpl}. Accessible {accessible}/{len(ids)}. Statuses {statuses}. {note}."),
        exposure=[AssetExposure(asset_type, accessible, t.get("total", len(ids)),
                                sensitive or bool(leaked), note)],
        attack_path=AttackPath(f"AP-{t['name']}", f"{method} {tmpl}", [
            AttackStep("entry", f"Authenticated user '{name_hint}'"),
            AttackStep("weakness", f"{t['name']} — ownership not enforced"),
            AttackStep("boundary", "Crosses user trust boundary"),
            AttackStep("resource", f"Victim's {asset_type}"),
            AttackStep("asset", note)],
            impact=f"Read other users' {asset_type}."),
        invariant="A user must never access another user's private resource unless authorized.",
        reattack=ReAttack(original_blocked=(not exploit) if reattack else None,
                          variants=variants),
        status=_status(exploit, reattack), tags=["idor", "authz", "active-probe"])


def _probe_function_authz(config, attacker, name_hint, t, reattack) -> Finding:
    url = t["url"]
    method = t.get("method", "GET")
    status, raw = attacker.request(url, method=method)
    exploit = _is_accessible(status, raw)
    leaked = _leaked_sensitive_keys(raw)
    note = (f"leaked fields: {', '.join(leaked)}" if leaked else "privileged endpoint body returned")
    return _make_finding(
        id=f"P-{t['name']}", title=f"{t['name']}: privileged endpoint reachable by normal user",
        vuln_class="Broken function-level authorization",
        severity=Severity.HIGH, exploitability=_expl(exploit, reattack),
        attacker=AttackerProfile.AUTHENTICATED, entry_point=f"{method} {url}",
        hypothesis=f"A normal user may reach {url} (should be admin/role-gated).",
        evidence=(f"As normal user '{name_hint}', called {method} {url} -> HTTP {status}. "
                  f"{'Served privileged data. ' + note if exploit else 'Blocked.'}"),
        exposure=[AssetExposure(t.get("asset_type", "admin"), 1 if exploit else 0, 1,
                                True, note)] if exploit else [],
        attack_path=AttackPath(f"AP-{t['name']}", f"{method} {url}", [
            AttackStep("entry", f"Authenticated normal user '{name_hint}'"),
            AttackStep("weakness", "No server-side role check"),
            AttackStep("boundary", "Crosses user->admin trust boundary"),
            AttackStep("asset", "Privileged function/data")],
            impact="Normal user performs/reads privileged action."),
        invariant="Every privileged action must verify the caller's role on the server.",
        reattack=ReAttack(original_blocked=(not exploit) if reattack else None),
        status=_status(exploit, reattack), tags=["authz", "function-level", "active-probe"])


def _probe_mass_assignment(config, attacker, name_hint, t, reattack) -> Finding:
    url = t["url"]
    method = t.get("method", "PATCH")
    if "{id}" in url and t.get("id") is not None:
        url = url.format(id=t["id"])
    inject = t.get("inject", {})
    vkey = t.get("verify_key")
    vval = t.get("verify_value")
    status, raw = attacker.request(url, method=method, body=inject)
    obj = _json(raw) or {}
    took_effect = False
    if vkey is not None:
        got = _dig(obj, vkey) if isinstance(obj, dict) else None
        took_effect = (got == vval) if vval is not None else (got is not None)
    accepted = _is_accessible(status, raw)
    exploit = took_effect or (accepted and vkey is None)
    # CONFIRMED only if we verified the forbidden field took effect; else PLAUSIBLE
    if reattack:
        expl = Exploitability.BLOCKED if not exploit else Exploitability.CONFIRMED
    else:
        expl = (Exploitability.CONFIRMED if took_effect
                else (Exploitability.PLAUSIBLE if accepted else Exploitability.BLOCKED))
    note = (f"forbidden field '{vkey}' accepted = {vval!r}" if took_effect
            else (f"request accepted (HTTP {status}); effect unverified" if accepted
                  else f"rejected (HTTP {status})"))
    return _make_finding(
        id=f"P-{t['name']}", title=f"{t['name']}: mass assignment of forbidden field",
        vuln_class="Mass assignment / over-trusting client",
        severity=Severity.HIGH, exploitability=expl,
        attacker=AttackerProfile.AUTHENTICATED, entry_point=f"{method} {url}",
        hypothesis=f"Sending extra field(s) {list(inject)} to {url} may set privileged attributes.",
        evidence=(f"As '{name_hint}', sent {method} {url} with body keys {list(inject)}. "
                  f"HTTP {status}. {note}."),
        exposure=[AssetExposure("privileged_field", 1 if exploit else 0, 1, True, note)]
        if exploit else [],
        attack_path=AttackPath(f"AP-{t['name']}", f"{method} {url}", [
            AttackStep("entry", f"Authenticated normal user '{name_hint}'"),
            AttackStep("weakness", "Request body bound without allow-list"),
            AttackStep("boundary", "Sets attribute only server should control"),
            AttackStep("asset", f"Privileged attribute ({vkey or list(inject)})")],
            impact="User escalates privilege / tampers protected attribute."),
        invariant="Only allow-listed fields are writable; sensitive attributes set server-side.",
        reattack=ReAttack(original_blocked=(not exploit) if reattack else None),
        status=_status(exploit, reattack), tags=["mass-assignment", "authz", "active-probe"])


def _probe_auth_bypass(config, name_hint, t, reattack) -> Finding:
    url = t["url"]
    method = t.get("method", "GET")
    anon = Session(base_url=config["base_url"])  # no token, no login
    status, raw = anon.request(url, method=method)
    exploit = _is_accessible(status, raw)
    leaked = _leaked_sensitive_keys(raw)
    note = (f"leaked fields: {', '.join(leaked)}" if leaked else "protected body returned")
    return _make_finding(
        id=f"P-{t['name']}", title=f"{t['name']}: protected endpoint served without auth",
        vuln_class="Missing authentication",
        severity=Severity.CRITICAL if leaked else Severity.HIGH,
        exploitability=_expl(exploit, reattack),
        attacker=AttackerProfile.EXTERNAL, entry_point=f"{method} {url}",
        hypothesis=f"{url} may respond without any authentication.",
        evidence=(f"Unauthenticated {method} {url} -> HTTP {status}. "
                  f"{'Served data. ' + note if exploit else 'Required auth / blocked.'}"),
        exposure=[AssetExposure(t.get("asset_type", "protected"), 1 if exploit else 0, 1,
                                True, note)] if exploit else [],
        attack_path=AttackPath(f"AP-{t['name']}", f"{method} {url}", [
            AttackStep("entry", "External attacker (no account)"),
            AttackStep("weakness", "Endpoint does not require authentication"),
            AttackStep("boundary", "Crosses internet->authenticated boundary"),
            AttackStep("asset", note)],
            impact="Anyone reaches a protected resource."),
        invariant="Every protected endpoint must require and verify authentication.",
        reattack=ReAttack(original_blocked=(not exploit) if reattack else None),
        status=_status(exploit, reattack), tags=["authn", "auth-bypass", "active-probe"])


# --------------------------------------------------------------------------- #
def _expl(exploit: bool, reattack: bool) -> Exploitability:
    if exploit:
        return Exploitability.CONFIRMED
    return Exploitability.BLOCKED if reattack else Exploitability.PLAUSIBLE


def _status(exploit: bool, reattack: bool) -> str:
    if reattack and not exploit:
        return "RESOLVED"
    return "OPEN"


def run_probe(config: dict[str, Any], reattack: bool = False) -> list[Finding]:
    assert_in_scope(config)
    accounts = config.get("auth", {}).get("accounts", {})
    attacker_name = config.get("attacker", "A")
    attacker_acct = accounts.get(attacker_name)
    attacker = _login(config, attacker_acct) if attacker_acct else Session(config["base_url"])

    findings: list[Finding] = []
    for t in config.get("targets", []):
        typ = t.get("type", "idor")
        if typ == "idor":
            findings.append(_probe_idor(config, attacker, attacker_name, t, reattack))
        elif typ == "function-authz":
            findings.append(_probe_function_authz(config, attacker, attacker_name, t, reattack))
        elif typ == "mass-assignment":
            findings.append(_probe_mass_assignment(config, attacker, attacker_name, t, reattack))
        elif typ == "auth-bypass":
            findings.append(_probe_auth_bypass(config, attacker_name, t, reattack))
    return findings


def load_config(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
