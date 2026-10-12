# Phase 8 — Security Report

> Không chỉ "Found 7 vulnerabilities". Xuất một **Threat Report**: với mỗi lỗi là
> evidence + metrics + attack path + root cause + kết quả re-attack, cộng một
> **Security State** snapshot để đo tiến bộ qua các vòng.

## Mục tiêu
Tổng hợp mọi thứ thành tài liệu hành động được, và lưu snapshot để so sánh vòng sau.

## Threat Report gồm gì
- **Summary**: số finding, số CONFIRMED, phân bố severity, residual risk.
- **Progress vs previous state**: risk trước → sau, % Security Improvement.
- **Mỗi finding**: type, severity, exploitability, attacker, entry point, risk score,
  hypothesis, evidence (redacted), attack path + depth, exposure + Attack Reach +
  Blast Radius, root cause, invariant, remediation, re-attack (original/variants/
  regressions).
- **Security State snapshot**: vulnerabilities / confirmed exploits / critical assets
  reachable / attack paths / risk.

## Xuất bằng toolkit
```bash
PYTHONPATH=src python -m ttf report assessment.json --out report.md
PYTHONPATH=src python -m ttf diff   cycle-N.json cycle-N+1.json
```
Mẫu thủ công (nếu không dùng CLI): [../../templates/threat-report.md](../../templates/threat-report.md).
Ví dụ đã render: [../../examples/ecommerce-idor/report.md](../../examples/ecommerce-idor/report.md).

## Security State qua các vòng (ví dụ)
```
VERSION 0:  vuln 12 · confirmed 7 · critical reachable 4 · paths 18
VERSION 1:  vuln 5  · confirmed 2 · critical reachable 1 · paths 7
VERSION 2:  vuln 3  · confirmed 0 · critical reachable 0 · paths 3
```
Security Improvement = `1 − PostFixRisk / PreFixRisk`. Xem [../metrics.md](../metrics.md).

## Threat Graph (trước/sau)
Có thể vẽ đồ thị attack path trước và sau remediation để thấy ranh giới AuthZ đã chặn
attacker ở đâu (mẫu trong [../../templates/attack-path.md](../../templates/attack-path.md)).

## Done when
- [ ] Report chứa đủ: evidence, metrics, attack path, root cause, re-attack cho mỗi finding.
- [ ] Đã lưu Security State snapshot của vòng này để so sánh vòng sau.
