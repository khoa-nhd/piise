# Prompt — Phase 7: Re-attack (Verify + Variants + Regression)

(Kèm `system-threat-agent.md` làm nền. Chỉ trên app của tôi, localhost/staging.)

---

Tôi vừa áp dụng fix sau cho finding đã CONFIRMED:

```
<mô tả fix + invariant + danh sách endpoint anh em từ Phase 6>
```

Giúp tôi kiểm tra fix có chặn cả *lớp lỗi* chưa:

1. **Original exploit** — chạy lại bước tái hiện cũ trên app của tôi; kỳ vọng giờ bị
   chặn (vd 403). Đặt `reattack.original_blocked`.
2. **Variant attacks** — cùng lớp lỗi, đổi hình thức: id+1/id-1, id=0/-1, query vs path
   param, body override, đổi HTTP method, endpoint lân cận. Với mỗi biến thể ghi
   `{label, blocked}`. Nếu biến thể nào qua ⇒ fix chưa tận gốc, chỉ ra cần sửa gì.
3. **Regression** — tấn công lại từng endpoint "anh em". Cái nào còn lộ ⇒ tạo **finding
   mới** (status OPEN) và nhắc tôi quay lại Phase 2/3 cho nó.

Giữ an toàn: dùng dữ liệu test, redact evidence, không payload nhắm hệ thống khác. Kết
lại bằng JSON `reattack` cho finding đã fix + (nếu có) các finding mới cho regression.
