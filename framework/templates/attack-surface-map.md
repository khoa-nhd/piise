# Attack Surface Map — <app name>

> Phase 2. Liệt kê mọi entry point, data store, cơ chế auth, dịch vụ ngoài, và trust
> boundaries. Mục tiêu: biết attacker vào từ đâu và sau mỗi ranh giới là asset gì.

## Sơ đồ thành phần
```
Application
├── Frontend   (<màn hình>)            secrets lộ ở client? ___
├── API        (<liệt kê route>)
├── Database   (<bảng>)
├── Auth       (<JWT/session>)
└── External   (<storage / AI API / payment / ...>)
```

## Entry points
| Entry point | Method | Auth? | Input kiểm soát được | Asset phía sau |
|-------------|--------|-------|----------------------|----------------|
| /api/... | GET | user | path `{id}` | order (PII) |
|  |  |  |  |  |

## Trust boundaries
| ID | Ranh giới | Từ → Đến | Asset cần bảo vệ sau ranh giới | Cơ chế chặn hiện có |
|----|-----------|----------|-------------------------------|---------------------|
| TB1 | Internet → App | ẩn danh → app | — | input validation? |
| TB2 | AuthN | ẩn danh → đã đăng nhập | tài nguyên user | token verify? |
| TB3 | AuthZ | user A → user B / admin | dữ liệu người khác | ownership/role check? |

## Lớp lỗi đáng nghi (đối chiếu docs/threat-catalog.md)
- [ ] IDOR/BOLA  - [ ] Function/role authz  - [ ] Mass assignment  - [ ] AuthN weak
- [ ] Injection  - [ ] SSRF  - [ ] Secrets exposure  - [ ] Excessive data exposure
- [ ] File upload  - [ ] CORS/CSRF  - [ ] Rate limiting  - [ ] Prompt injection (nếu có LLM)
