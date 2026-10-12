# Phase 5 — Trace (Attack Path A → B)

> Ghi lại attacker đi **từ đâu → đến đâu**: entry point → điểm yếu → vượt trust
> boundary → resource → sensitive asset. Đây là phần đáng visualize nhất.

## Mục tiêu
Biến mỗi finding thành một **attack path** có thứ tự bước, để thấy rõ attacker cần đi
mấy chặng (Attack Depth) và vượt ranh giới nào.

## Cấu trúc một attack path
```
Entry Point
   ↓
Weakness (điểm yếu bị lợi dụng)
   ↓
Privilege / Trust Boundary Crossing
   ↓
Resource (object chạm tới)
   ↓
Sensitive Asset (thứ thực sự có giá trị)
```

Mỗi bước có `kind` ∈ {`entry`, `weakness`, `boundary`, `resource`, `asset`} để
toolkit render và tính **Attack Depth = số bước**.

## Ví dụ (report)
```
Attack Path #03
Entry:     GET /api/orders/{id}
Weakness:  Broken Object Level Authorization
Attacker:  Authenticated normal user
Traversal: User → Order → Customer information
Impact:    Truy cập thông tin đơn hàng của user khác
Severity:  High
```

## Vì sao đo Attack Depth
Phân biệt "critical asset lộ trực tiếp" (depth 1 — rất tệ) với "phải đi nhiều bước mới
tới" (depth 5 — khó khai thác hơn). Depth + Reach + Severity cùng định hình rủi ro.

## Cách làm
1. Từ Phase 3/4, sắp các bước theo đúng thứ tự attacker đi.
2. Gắn `kind` cho từng bước; ghi `impact` ở cuối.
3. Điền vào `attack_path` của finding (mẫu: [../../templates/attack-path.md](../../templates/attack-path.md)).

## Output
`attack_path` cho mỗi finding; Attack Depth do toolkit tính.

## Done when
- [ ] Mỗi finding CONFIRMED có attack path từ entry tới sensitive asset.
- [ ] Mỗi lần vượt trust boundary được đánh dấu bằng bước `boundary`.
