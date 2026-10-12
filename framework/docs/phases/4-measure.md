# Phase 4 — Measure (What can the attacker actually reach?)

> Đừng dừng ở `vulnerability = 1`. Đo **attacker thực sự chạm tới bao nhiêu** — đây là
> metric trung tâm phân biệt một lỗi "1 user" với một lỗi "10.000 user".

## Mục tiêu
Lượng hoá *exposure* và *reach* của mỗi finding đã CONFIRMED.

## Đo cái gì
**Data Exposure** — phân loại dữ liệu chạm tới, từ ít nhạy cảm đến nghiêm trọng:
```
public → private profile → email/phone → order history
       → internal metadata → admin data → secrets
```
Với mỗi loại asset, ghi: `accessible` (số bản ghi lấy được) / `total` (kích thước tập
liên quan, nếu biết) / `sensitive` (có phải PII/secret/payment).

**Attack Reach** — tỉ lệ tài nguyên chạm tới sau khai thác:
```
Reach = accessible assets / total relevant assets
```
Ví dụ 24/1000 user ⇒ 2.4%. Kèm thang định tính 0–5 (xem [../metrics.md](../metrics.md)):
```
0 no access · 1 own data · 2 one other user · 3 multiple users
4 privileged data · 5 system-wide / critical
```

**Blast Radius** — số lượng/tỉ lệ asset *có thể* bị ảnh hưởng (kể cả chưa truy cập
hết). Hai lỗi cùng "HIGH" có thể khác blast radius 1 vs 10.000.

## Cách làm
1. Từ bước tái hiện ở Phase 3, liệt kê các loại asset chạm tới.
2. Điền `accessible/total/sensitive` cho từng loại (dùng dữ liệu test của bạn).
3. Để CLI tính Reach/Blast/Risk: nhập vào `assessment.json` → `python -m ttf report`.

## Output
Mảng `exposure[]` cho mỗi finding; các số Reach/Blast do toolkit tính.

## Done when
- [ ] Mỗi finding CONFIRMED có ≥1 mục `exposure`.
- [ ] Biết Attack Reach (fraction + level) và Blast Radius của nó.
