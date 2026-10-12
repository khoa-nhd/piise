# Phase 7 — Re-attack (Verify + Variants + Regression)

> Fix xong chưa đủ. Chạy lại chính exploit cũ, rồi thử **biến thể** và **endpoint anh
> em**. Mục tiêu: chặn cả *attack class*, không chỉ mẫu exploit.

## Mục tiêu
Xác nhận finding thực sự `BLOCKED`, và phát hiện *security regression* — nơi khác dùng
chung giả định sai nhưng chưa được fix.

## Ba lớp kiểm tra

**1. Original exploit (bắt buộc)**
```
Before:  User A → User B data ✓ (lộ)
After:   User A → User B data ✗ (HTTP 403)
```

**2. Variant attacks** — cùng một lớp lỗi, đổi hình thức:
```
/id/123   /id/124   /id/0   /id/-1
?id=123   POST body   PUT body
endpoint khác · HTTP method khác (GET/HEAD/PUT)
```
Nếu fix chỉ chặn đúng mẫu mà biến thể vẫn qua ⇒ chưa fix tận gốc, quay lại Phase 6.

**3. Regression attacks** — các endpoint "anh em" chia sẻ invariant:
```
/orders/:id   → FIXED
/profile/:id  → FIXED
/invoices/:id → FIXED
/messages/:id → STILL VULNERABLE   ← finding mới! quay lại DISCOVER
```

## Vòng lặp
```
original exploit → FIX → re-run → variants → regressions
   ├── tất cả BLOCKED  → finding RESOLVED
   └── còn qua được    → tạo finding mới → quay lại Phase 2/3
```

## Cách làm
1. Chạy lại exploit gốc; đặt `reattack.original_blocked`.
2. Liệt kê biến thể hợp lý cho lớp lỗi; ghi `blocked` cho từng cái.
3. Từ danh sách endpoint anh em (Phase 6), tấn công lại; cái nào còn lộ → finding mới.

Prompt hỗ trợ: [../../prompts/phase7-re-attack.md](../../prompts/phase7-re-attack.md)

## Output
`reattack` (original + variants + regressions) cho finding đã fix; các finding mới cho
regression còn mở; status → `RESOLVED` khi mọi mục BLOCKED.

## Done when
- [ ] Exploit gốc BLOCKED và các biến thể BLOCKED.
- [ ] Mọi endpoint anh em đã được tấn công lại; regression còn lại thành finding mới.
