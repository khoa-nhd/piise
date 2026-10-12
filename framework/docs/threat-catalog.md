# Threat Catalog — các lớp lỗi hay gặp ở app vibe-coded

Danh mục để Phase 1–2 không bỏ sót. Mỗi mục: dấu hiệu, câu hỏi attacker, invariant cần
giữ. Đây là checklist tư duy, không phải payload tấn công.

## 1. Broken Object Level Authorization (IDOR / BOLA)
- **Dấu hiệu:** endpoint nhận `{id}` và trả object theo id mà không so chủ sở hữu.
- **Attacker hỏi:** đổi `{id}` có đọc/sửa được object của người khác không?
- **Invariant:** user không chạm resource riêng của user khác trừ khi được cấp phép rõ ràng.

## 2. Broken Function/Role Authorization
- **Dấu hiệu:** route admin dựa vào UI ẩn, không kiểm role ở server.
- **Attacker hỏi:** gọi thẳng `/admin/*` hoặc action đặc quyền khi là user thường được không?
- **Invariant:** mọi action đặc quyền kiểm tra role ở server, không tin client.

## 3. Mass Assignment / over-trusting client
- **Dấu hiệu:** bind thẳng request body vào model (`role`, `isAdmin`, `price`, `balance`).
- **Attacker hỏi:** thêm field không có trong UI vào body thì sao?
- **Invariant:** chỉ nhận allow-list field; thuộc tính nhạy cảm set ở server.

## 4. Authentication weaknesses
- **Dấu hiệu:** JWT không verify/`alg=none`, secret yếu/nhúng client, session không hết hạn,
  reset token đoán được.
- **Attacker hỏi:** giả mạo/kéo dài phiên, bỏ qua đăng nhập được không?
- **Invariant:** token được ký & verify đúng; secret ở server; phiên có vòng đời.

## 5. Injection (SQL/NoSQL/command/template)
- **Dấu hiệu:** nối chuỗi vào query/command/template từ input.
- **Attacker hỏi:** chèn cú pháp điều khiển để đổi ý nghĩa query/command được không?
- **Invariant:** luôn parameterize / escape theo ngữ cảnh; không nối input vào mã.

## 6. SSRF & unsafe outbound fetch
- **Dấu hiệu:** server fetch URL do người dùng cung cấp (webhook, "import from URL", ảnh).
- **Attacker hỏi:** trỏ tới `169.254.169.254`/dịch vụ nội bộ để lấy metadata/secret?
- **Invariant:** allow-list đích; chặn địa chỉ nội bộ/link-local.

## 7. Secrets exposure
- **Dấu hiệu:** API key/token trong bundle frontend, repo, log, response lỗi.
- **Attacker hỏi:** đọc source/map/log có nhặt được secret không?
- **Invariant:** secret chỉ ở server; không log; xoay vòng khi lộ.

## 8. Excessive data exposure
- **Dấu hiệu:** API trả nguyên object (gồm field nội bộ/nhạy cảm) để client tự lọc.
- **Attacker hỏi:** đọc response thô có thấy field không hiển thị trên UI không?
- **Invariant:** serialize theo allow-list cho đúng người xem.

## 9. Insecure file upload / path handling
- **Dấu hiệu:** nhận file không giới hạn type/size; dùng tên file để ghép path.
- **Attacker hỏi:** upload nội dung nguy hiểm, hay `../` thoát thư mục được không?
- **Invariant:** kiểm type/size; sinh tên phía server; chống path traversal.

## 10. CORS / CSRF / clickjacking misconfig
- **Dấu hiệu:** `Access-Control-Allow-Origin: *` kèm credentials; thiếu CSRF token; thiếu frame headers.
- **Attacker hỏi:** trang khác gọi API thay người dùng, hay nhúng iframe lừa click được không?
- **Invariant:** origin allow-list; chống CSRF cho action thay đổi trạng thái; chặn frame.

## 11. Rate limiting / resource abuse
- **Dấu hiệu:** endpoint đắt (login, OTP, search, AI call) không giới hạn.
- **Attacker hỏi:** brute-force/bơm chi phí/làm cạn tài nguyên được không?
- **Invariant:** rate-limit theo danh tính + chi phí; backoff.

## 12. Prompt injection / unsafe AI integration (app có LLM)
- **Dấu hiệu:** nội dung không tin cậy được nối thẳng vào prompt; cho LLM gọi tool có side-effect mà không chặn.
- **Attacker hỏi:** nhét chỉ thị vào dữ liệu để chiếm hành vi của agent được không?
- **Invariant:** coi output model & nội dung lấy qua tool là *dữ liệu*, không phải lệnh; action side-effect phải xác nhận.

---
Mỗi khi vừa code một tính năng, rà nhanh 12 mục trên, chọn mục liên quan rồi đưa vào loop.
