# Prompt — Phase 6: Root-Cause Fix

(Kèm `system-threat-agent.md` làm nền.)

---

Lỗi đã CONFIRMED:

```
<mô tả finding + evidence đã redact + attack path>
```

Đừng vá một dòng. Giúp tôi sửa **tận gốc**:

1. **5 Whys** — đào từ triệu chứng tới tầng thiết kế/quy trình. Dừng khi chạm nguyên
   nhân mà việc sửa nó ngăn được *cả lớp lỗi*.
2. **Invariant** — phát biểu 1 câu quy tắc bảo mật phải luôn đúng.
3. **Fix tập trung** — đề xuất điểm thực thi dùng chung (middleware/policy/service
   layer) thay vì sửa lẻ từng endpoint; nêu rõ MỌI nơi phải đi qua nó.
4. **Test bảo vệ invariant** — ví dụ test khẳng định (vd cross-tenant → 403).
5. **Danh sách endpoint "anh em"** chia sẻ invariant này, để tôi re-attack ở Phase 7.

So sánh ngắn: cách vá triệu chứng (xấu) vs cách sửa gốc (tốt) cho trường hợp này. Kết
lại bằng JSON cho finding (`root_cause`, `invariant`, `remediation`, gợi ý
`reattack.regressions`).
