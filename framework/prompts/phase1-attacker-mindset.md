# Prompt — Phase 1: Attacker Mindset

(Kèm `system-threat-agent.md` làm nền.)

---

Đây là tính năng/endpoint tôi vừa viết trong app **của tôi**:

```
<dán code/diff/mô tả + endpoint liên quan>
```

Đóng vai attacker và trả lời **theo từng tier**. Với mỗi tier, đừng hỏi chung chung
"có lỗi không" — hãy nêu **mục tiêu cụ thể** attacker nhắm tới và *vì sao tính năng này
có thể cho phép*.

- **External (chưa đăng nhập):** endpoint nào lộ ra? input nào tôi kiểm soát? secret ở
  frontend? API trả dư dữ liệu? có đổi được định danh resource?
- **Authenticated (user thường):** leo quyền? đọc/sửa object user khác? gọi API ngoài
  UI (đổi method/body/field ẩn)? field nào tin client quá mức?
- **Insider (account hợp lệ):** chạm dữ liệu vượt quyền tới đâu? có bị log lại không?

Trước tiên liệt kê **assets cần bảo vệ** trong tính năng này. Kết quả: danh sách
"attacker goals theo tier", mỗi mục gắn với một vùng code/endpoint để soi ở Phase 2.
