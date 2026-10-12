━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT THINKING REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Application:   Vibe-coded E-commerce App
Assessment:    Attack Cycle #04
Scope:         Authorized self-assessment of my own staging instance (localhost + my test tenant). No third-party systems touched.

SUMMARY
  Findings:            2
  Confirmed exploits:  1
  By severity:         HIGH 2
  Residual risk:       5.04

PROGRESS vs PREVIOUS STATE
  cycle-3      risk 28.5     -> cycle-4      risk 5.04
  Security improvement: 82.32%

────────────────────────────────────────────────────
VULNERABILITY #01 — Messages endpoint still allows cross-user access (regression sibling)
────────────────────────────────────────────────────

Type:            Broken Object Level Authorization (IDOR)
Severity:        HIGH
Exploitability:  CONFIRMED
Attacker:        Authenticated normal user
Entry Point:     GET /api/messages/{id}
Risk score:      5.04
Status:          OPEN

HYPOTHESIS
  The same 'authenticated == authorized' assumption that caused F-001 likely affects sibling endpoints. Messages was not yet migrated to the central policy.

EVIDENCE (sanitized)
  After fixing orders, re-ran the attack class across sibling endpoints. /api/messages/{id} still returns other users' message threads. Reproduced on my own staging tenant.

ATTACK PATH
  Entry: GET /api/messages/{id}
    Authenticated normal user
    ↓
    Messages API — not migrated to central policy
    ↓
    Crosses user trust boundary
    ↓
    Another user's message thread
    ↓
    Private message content (sensitive)
    ↓
    Impact: Read access to other users' private messages.

  Attack depth: 5

IMPACT / EXPOSURE
  message            63/4200  [sensitive]
  email              14  [sensitive]

  Attack Reach:  1.5000%  (level 3/5)
  Blast Radius:  77 records (77 sensitive)

ROOT CAUSE
  Same root cause as F-001: no uniform enforcement point. Fixing one endpoint
  did not fix the class until every sibling routes through the policy layer.

SECURITY INVARIANT TO RESTORE
  A user must never read or modify another user's private resource unless an explicit policy grants it.

REMEDIATION (root-cause fix)
  Route the messages service through the same `authorize()` policy introduced for
  F-001; add the cross-tenant 403 test for messages to the regression suite.

────────────────────────────────────────────────────
VULNERABILITY #02 — Other users' orders readable by ID manipulation
────────────────────────────────────────────────────

Type:            Broken Object Level Authorization (IDOR)
Severity:        HIGH
Exploitability:  BLOCKED
Attacker:        Authenticated normal user
Entry Point:     GET /api/orders/{id}
Risk score:      0.0
Status:          RESOLVED

HYPOTHESIS
  As a normal logged-in user, changing {id} in the orders endpoint may return orders that belong to other customers, because authentication was checked but ownership was not.

EVIDENCE (sanitized)
  As test user A (id 101), requested order ids sequentially around my own. Server returned full order bodies for ids I do not own, including customer name, email and shipping address. Reproduced against my own staging tenant only; values redacted here.

ATTACK PATH
  Entry: GET /api/orders/{id}
    Authenticated normal user
    ↓
    Orders API — missing ownership check
    ↓
    Crosses user trust boundary (A -> B)
    ↓
    Another user's order object
    ↓
    Customer email + shipping address (PII)
    ↓
    Impact: Read access to other customers' order and contact information.

  Attack depth: 5

IMPACT / EXPOSURE
  user_profile       24/1000
  order              51/2125
  email              37  [sensitive]
  password           0  [sensitive]
  payment            0  [sensitive]

  Attack Reach:  2.4000%  (level 3/5)
  Blast Radius:  112 records (37 sensitive)

ROOT CAUSE
  Authorization was treated as equal to authentication. There is no centralized
  ownership/policy layer; each controller re-implements access checks ad hoc, and
  the orders controller simply forgot to compare order.user_id to the caller.

SECURITY INVARIANT TO RESTORE
  A user must never read or modify another user's private resource unless an explicit policy grants it.

REMEDIATION (root-cause fix)
  Add a central authorization policy enforced in the service layer (not per-route):
  every object fetch goes through `authorize(actor, action, resource)` which checks
  ownership/role. Orders, profiles, messages and invoices all routed through it.
  Unit + integration tests assert 403 for cross-tenant access.

RE-ATTACK
  Original exploit:    BLOCKED ✓
  Variant attacks:     5/5 blocked
    - id+1 / id-1 sequential       BLOCKED ✓
    - id=0 and id=-1               BLOCKED ✓
    - ?id= query vs path param     BLOCKED ✓
    - PUT body id override         BLOCKED ✓
    - different HTTP method (HEAD) BLOCKED ✓
  Regression attacks:  2/3 blocked
    - GET /api/profile/{id}        BLOCKED ✓
    - GET /api/invoices/{id}       BLOCKED ✓
    - GET /api/messages/{id}       STILL VULNERABLE ✗

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY STATE SNAPSHOT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  version                      cycle-4
  vulnerabilities              1
  confirmed_exploits           1
  critical_assets_reachable    1
  attack_paths                 2
  risk                         5.04
