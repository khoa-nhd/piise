# Attack Path — <finding id>

> Phase 5. Ghi đường đi của attacker và vẽ Threat Graph trước/sau fix.

## Bảng
```
Attack Path #<n>
Entry:     <entry point>
Weakness:  <điểm yếu>
Attacker:  <external | authenticated | insider>
Traversal: <A → B → C>
Impact:    <tác động>
Severity:  <INFO|LOW|MEDIUM|HIGH|CRITICAL>
Depth:     <số bước>
```

## Threat Graph — TRƯỚC remediation
```
┌─────────────┐
│  Internet   │
└──────┬──────┘
       ▼
┌─────────────┐
│ API Endpoint│
└──────┬──────┘
   Missing AuthZ
       ▼
┌─────────────┐
│ User Object │
└──────┬──────┘
       ▼
┌─────────────┐
│ Order Data  │
└──────┬──────┘
       ▼
┌─────────────┐
│ Email / PII │
└─────────────┘
```

## Threat Graph — SAU remediation
```
Internet
   ↓
API
   ↓
Authorization ✓
   ↓
BLOCKED
```

## Steps (để đưa vào JSON `attack_path.steps`)
```json
[
  {"kind": "entry",    "label": "Authenticated normal user"},
  {"kind": "weakness", "label": "Missing ownership check"},
  {"kind": "boundary", "label": "Crosses user trust boundary (A -> B)"},
  {"kind": "resource", "label": "Another user's object"},
  {"kind": "asset",    "label": "Email / PII"}
]
```
