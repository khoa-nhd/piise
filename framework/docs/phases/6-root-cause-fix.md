# Phase 6 — Root-Cause Fix

> Đây là chỗ framework **không** biến thành "AI pentest tool" đơn thuần. Đừng để AI chỉ
> sửa dòng code gây lỗi. Hỏi: *"Vì sao vulnerability tồn tại?"* và sửa **security
> invariant**, không vá triệu chứng.

## Mục tiêu
Tìm nguyên nhân gốc, phát biểu lại **invariant** bị vỡ, và fix ở tầng tái sử dụng được
sao cho *cả lớp lỗi* biến mất — không chỉ một endpoint.

## Đào tới gốc (5 Whys)
```
Observed:  User A đọc được order của User B
  Why? Controller không kiểm tra ownership
  Why? Không có authorization middleware/policy tập trung
  Why? Không có chính sách phân quyền dùng chung
  Why? Lập trình viên ngầm hiểu authentication = authorization
  Why? Yêu cầu bảo mật vắng mặt trong quy trình phát triển  ← ROOT CAUSE
```

## Phát biểu invariant
Một câu khẳng định luôn phải đúng, ví dụ:
> *A user must never access another user's private resource unless explicitly authorized.*

## Fix theo gốc, không theo triệu chứng
Thay vì nhét vào **một** endpoint:
```python
if user.id != order.user_id:
    return 403
```
Hãy dựng **điểm thực thi dùng chung**:
```
Central authorization policy
      ↓
Reusable middleware / service-layer check
      ↓
Object ownership / role check
      ↓
Áp cho MỌI endpoint liên quan
```
Nguyên tắc: **Fix the security invariant, not just the symptom.** Sau khi fix, quét
toàn app xem invariant này còn bị phá ở đâu nữa (đầu vào cho Phase 7 regression).

## Cách làm
1. Chạy 5 Whys tới khi chạm nguyên nhân quy trình/thiết kế.
2. Viết invariant (1 câu).
3. Thiết kế fix ở tầng dùng chung; liệt kê mọi endpoint phải đi qua nó.
4. Thêm test khẳng định invariant (vd: cross-tenant → 403).

Prompt hỗ trợ: [../../prompts/phase6-root-cause.md](../../prompts/phase6-root-cause.md)

## Output
`root_cause`, `invariant`, `remediation` cho finding; danh sách endpoint "anh em" cần
kiểm tra ở Phase 7; status → `FIXED`.

## Done when
- [ ] Root cause chạm tầng thiết kế/quy trình, không dừng ở dòng code.
- [ ] Có invariant + fix tập trung + test bảo vệ invariant.
