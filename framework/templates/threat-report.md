# Threat Report (template thủ công)

> Dùng khi không chạy CLI. Nếu dùng CLI thì chạy `python -m ttf report assessment.json`
> sẽ tự sinh bản đầy đủ hơn. Xem bản đã render ở `examples/ecommerce-idor/report.md`.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT THINKING REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Application:   <app>
Assessment:    Attack Cycle #<n>
Scope:         <phạm vi được phép, vd localhost/staging của tôi>

SUMMARY
  Findings:            <n>
  Confirmed exploits:  <n>
  By severity:         CRITICAL _ · HIGH _ · MEDIUM _ · LOW _
  Residual risk:       <số>

PROGRESS vs PREVIOUS STATE
  cycle-<n-1> risk <x>  ->  cycle-<n> risk <y>
  Security improvement: <%>

──────────────────────────────────────────────────
VULNERABILITY #01 — <tiêu đề>
──────────────────────────────────────────────────
Type:            <lớp lỗi>
Severity:        <...>
Exploitability:  POTENTIAL | PLAUSIBLE | CONFIRMED | BLOCKED
Attacker:        <tier>
Entry Point:     <endpoint>
Risk score:      <số>

HYPOTHESIS       <...>
EVIDENCE         <đã redact>

ATTACK PATH
  <entry> → <weakness> → <boundary> → <resource> → <asset>
  Attack depth: <n>

IMPACT / EXPOSURE
  <asset_type>  <accessible>/<total>  [sensitive?]
  Attack Reach: <%> (level <0-5>)
  Blast Radius: <records> (<sensitive> sensitive)

ROOT CAUSE       <nguyên nhân gốc>
INVARIANT        <quy tắc phải giữ>
REMEDIATION      <fix tập trung>

RE-ATTACK
  Original exploit:   BLOCKED ✓ / STILL VULNERABLE ✗
  Variant attacks:    <k>/<m> blocked
  Regression attacks: <k>/<m> blocked

──────────────────────────────────────────────────
SECURITY STATE SNAPSHOT
  vulnerabilities            <n>
  confirmed_exploits         <n>
  critical_assets_reachable  <n>
  attack_paths               <n>
  risk                       <số>
```
