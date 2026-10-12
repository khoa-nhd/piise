# Metrics

Mọi công thức ở đây khớp đúng với code trong [`src/ttf/metrics.py`](../src/ttf/metrics.py)
và có thể tái lập — không có hộp đen. Chia thành 5 nhóm + các metric đặc trưng.

## 5 nhóm metric

**A. Vulnerability** — số lượng, loại, severity, confidence, exploitability.
**B. Attack** — số attack paths, attack depth, số bước, entry points, lần vượt trust boundary, leo quyền.
**C. Exposure** — số asset/record lộ, loại dữ liệu, % tập dữ liệu, Attack Reach.
**D. Remediation** — số lỗi đã fix, root-cause coverage, số endpoint ảnh hưởng, số regression.
**E. Security improvement** — mức giảm rủi ro giữa hai vòng.

---

## Severity → weight
| Severity | weight |
|----------|--------|
| INFO | 1 |
| LOW | 2 |
| MEDIUM | 4 |
| HIGH | 7 |
| CRITICAL | 10 |

## Exploitability → factor
| Mức | factor | ý nghĩa |
|-----|--------|---------|
| POTENTIAL | 0.4 | mới là giả thuyết |
| PLAUSIBLE | 0.7 | tín hiệu mạnh |
| CONFIRMED | 1.0 | đã tái hiện |
| BLOCKED | 0.0 | đã fix & verify (nên risk = 0) |

## Attack Reach
```
fraction = Σ accessible / Σ total      (chỉ tính asset type có khai báo total)
```
Thang định tính 0–5 (`reach_level`):
```
0  fraction = 0            → không truy cập ý nghĩa
1  ~0                      → chỉ dữ liệu của mình
2  ≤ 0.02%                 → dữ liệu của một user khác
3  < 50%                   → nhiều user
4  có asset đặc quyền, fraction < 50%
5  ≥ 50%, hoặc asset đặc quyền với fraction ≥ 50% → toàn hệ thống / critical
```
Asset "đặc quyền" = loại nhạy cảm thuộc {secret, admin, credential, payment, token}.

## Attack Depth
Số bước của attack path (lộ trực tiếp = 1). Depth lớn ⇒ cần nhiều chặng hơn để tới
asset ⇒ khó khai thác hơn (dù không giảm severity).

## Blast Radius
```
records           = Σ accessible
sensitive_records = Σ accessible (chỉ asset sensitive)
proportion        = records / Σ total
```
Dùng để phân biệt hai lỗi cùng severity nhưng khác quy mô (1 vs 10.000 bản ghi).

## Risk (mỗi finding)
```
blast_scale   = 0.3 + 0.7 * (reach_level / 5)          # 0.3 .. 1.0
finding_risk  = severity.weight * exploitability.factor * blast_scale
```
- `severity.weight` (1..10): tệ cỡ nào nếu xảy ra.
- `exploitability.factor` (0..1): có xảy ra không. BLOCKED = 0 ⇒ risk về 0 sau khi fix verify.
- `blast_scale` (0.3..1): rộng cỡ nào, sàn 0.3 để một lỗ lộ 1 bản ghi vẫn được tính.

Risk của cả assessment = tổng `finding_risk` của mọi finding.

## Security Improvement
```
improvement (%) = (1 − PostFixRisk / PreFixRisk) * 100
```
Trả 0 nếu PreFixRisk = 0. Ví dụ 80 → 15 ⇒ cải thiện 81.25%.

## Security State (snapshot mỗi vòng)
| trường | ý nghĩa |
|--------|---------|
| vulnerabilities | số finding chưa RESOLVED |
| confirmed_exploits | số finding Exploitability = CONFIRMED |
| critical_assets_reachable | số finding CONFIRMED có exposure nhạy cảm |
| attack_paths | số finding có attack path |
| risk | residual risk (tổng finding_risk) |

So sánh hai snapshot bằng `python -m ttf diff a.json b.json`.
