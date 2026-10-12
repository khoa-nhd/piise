# Tích hợp TTF vào AI lúc vibe coding

Ba cấp độ, từ nhẹ tới tự động hoàn toàn. Dùng cấp nào cũng được — cộng dồn càng tốt.
Trước tiên cài lệnh `ttf` một lần:

```bash
pip install -e <đường-dẫn-tới-framework>     # tạo lệnh `ttf` toàn cục
# hoặc không cài:  đặt TTF_HOME=<framework> rồi dùng  python -m ttf  với PYTHONPATH=%TTF_HOME%/src
```

> Các file dưới đây đặt trong **repo app của bạn**, không phải repo framework.
> Đặt biến môi trường `TTF_HOME` = đường dẫn tới framework để AI tìm được docs/prompts/schema.

---

## Cấp 1 — Rules file (quan trọng nhất, "dạy" AI tự chạy loop)

Làm cho AI **tự áp** threat-thinking mỗi khi viết code rủi ro, không cần dán prompt.

| Công cụ | Chép file này | Thành |
|---------|---------------|-------|
| Claude Code | `CLAUDE.md` | `<app>/CLAUDE.md` |
| Cursor | `cursorrules.txt` | `<app>/.cursorrules` |
| Windsurf | `cursorrules.txt` | `<app>/.windsurfrules` |
| GitHub Copilot | `cursorrules.txt` | `<app>/.github/copilot-instructions.md` |

Các file này tự nạp vào ngữ cảnh mỗi session → AI nhớ loop + rào an toàn + biết gọi `ttf`.

## Cấp 2 — Slash command (bấm 1 lệnh khi muốn soi)

Chép `threatcheck.md` → `<app>/.claude/commands/threatcheck.md`. Khi code xong một
feature, gõ `/threatcheck` trong Claude Code: nó tự lấy `git diff`, chạy `ttf scan`, rồi
làm trọn threat-thinking pass trên đúng phần vừa đổi. (Cursor: tạo một saved prompt
tương đương từ nội dung file.)

## Cấp 3 — Hook (tự động hoàn toàn, không cần gõ gì)

Gộp `claude-settings.hook.json` vào `<app>/.claude/settings.json` (thay `<TTF_HOME>`).
Mỗi lần Claude ghi/sửa file, `ttf_hook.py` quét ngay file đó; nếu có lỗi HIGH/CRITICAL
nó **đẩy ngược findings cho Claude** để sửa trong cùng lượt. Tắt bằng cách xoá hook.

Thử nhanh hook (giả lập payload của Claude Code):
```bash
echo '{"tool_input":{"file_path":"examples/demo-app/app.py"}}' | python integrations/ttf_hook.py
```

---

## Cổng commit (tuỳ chọn) — chặn lỗi lọt vào git

Chép `pre-commit` → `<app>/.git/hooks/pre-commit` (và `chmod +x`). Nó chạy `ttf scan`
trên repo; nếu xuất hiện finding HIGH/CRITICAL mới thì chặn commit. Đây là lưới an toàn
cuối, bổ sung cho loop lúc code.

---

## Luồng dùng điển hình (app đang code dở)

1. Một lần: `pip install -e <framework>`, đặt `TTF_HOME`, chép `CLAUDE.md` vào app.
2. Mỗi feature rủi ro: AI tự nhắc loop (Cấp 1) **hoặc** bạn gõ `/threatcheck` (Cấp 2).
3. (Tuỳ) Bật hook (Cấp 3) để mọi file ghi ra đều được quét ngay.
4. Với IDOR: viết `probe.config.json`, chạy app local, `ttf probe ... --merge` để xác nhận.
5. Fix gốc → `ttf probe --reattack` → `ttf report` / `ttf diff` xem % cải thiện.
