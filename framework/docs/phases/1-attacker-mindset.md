# Phase 1 — Attacker Mindset

> Linh hồn của framework. **Trước khi** scan, hỏi: *"Nếu tôi là attacker thì tôi sẽ
> làm gì?"* — và quan trọng hơn: *"Một attacker với capability X làm được những gì?"*

## Mục tiêu
Chuyển từ câu hỏi yếu "Có vulnerability nào?" sang câu hỏi mạnh "Attacker với năng
lực X đạt được mục tiêu Y bằng cách nào?". Việc này định hướng toàn bộ loop.

## Ba hồ sơ attacker (capability tiers)

**External attacker (chưa đăng nhập)**
- Tôi thấy những endpoint nào? Cái nào không cần auth?
- Input nào tôi kiểm soát? Có secret lộ ở frontend không?
- API có trả dư dữ liệu không? Có endpoint debug/admin nào không?
- Tôi đổi được `user_id`/định danh resource không?

**Authenticated attacker (user thường)**
- Tôi leo quyền được không? Xem/sửa object của user khác được không?
- Tôi gọi được API mà UI không expose không? (đổi method, body, field ẩn)
- Có field nào tin tưởng client quá mức (role, price, isAdmin) không?

**Malicious insider (account hợp lệ, nhiều ngữ cảnh)**
- Với account hợp lệ, tôi chạm tới dữ liệu vượt quyền tới đâu?
- Có log/audit nào ghi lại hành vi của tôi không?

## Cách làm (khi vibe coding)
1. Liệt kê **assets** cần bảo vệ (PII, payment, secrets, admin, nội dung riêng tư).
2. Với mỗi tier attacker, viết 3–5 **mục tiêu** attacker có thể nhắm tới.
3. Gắn mỗi mục tiêu vào tính năng/endpoint vừa viết → đó là nơi ưu tiên soi ở Phase 2–3.

Prompt hỗ trợ: [../../prompts/phase1-attacker-mindset.md](../../prompts/phase1-attacker-mindset.md)

## Output
Một danh sách ngắn "attacker goals theo tier", mỗi mục dẫn tới một vùng nghi ngờ của
app. Đây là đầu vào cho Phase 2.

## Done when
- [ ] Đã xác định assets cần bảo vệ.
- [ ] Mỗi tier attacker có ≥3 mục tiêu cụ thể gắn với code vừa viết.
