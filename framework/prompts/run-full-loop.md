# Prompt — Run the full loop on a feature

Dùng khi vừa code xong một tính năng và muốn AI chạy trọn loop một lượt. Kèm theo
`system-threat-agent.md` làm nền.

---

Tôi vừa thêm/sửa tính năng sau trong app **của tôi** (phạm vi: <localhost/staging của tôi>):

```
<dán diff hoặc mô tả tính năng + các file/endpoint liên quan>
```

Hãy chạy Threat Thinking Loop cho phần này và trả về theo đúng thứ tự:

1. **Attacker Mindset** — với 3 tier (external / authenticated / insider), mỗi tier nêu
   2–3 mục tiêu attacker có thể nhắm vào chính tính năng này.
2. **Discover** — liệt kê entry points + trust boundaries liên quan; đối chiếu nhanh với
   `docs/threat-catalog.md` để chọn các lớp lỗi đáng nghi.
3. **Exploit (prove)** — với mỗi nghi ngờ, nêu cách *chứng minh có kiểm soát trên app
   của tôi* (bước tái hiện tối thiểu, tài khoản/dữ liệu test cần có) và gán mức
   Exploitability. **Không** đưa payload để tấn công hệ thống khác.
4. **Measure** — liệt kê exposure (asset_type / accessible / total / sensitive) và nêu
   Attack Reach + Blast Radius dự kiến.
5. **Trace** — vẽ attack path (entry → weakness → boundary → resource → asset) + Attack Depth.
6. **Root-cause Fix** — chạy 5 Whys tới tầng thiết kế; phát biểu invariant; đề xuất fix ở
   tầng dùng chung + test bảo vệ invariant; liệt kê endpoint "anh em" cần kiểm ở bước 7.
7. **Re-attack plan** — exploit gốc + danh sách biến thể + danh sách regression cần thử.
8. **Report JSON** — xuất một mảng `findings` khớp `schema/finding.schema.json` để tôi
   dán vào `assessment.json`, rồi tôi chạy `python -m ttf report`.

Nếu phần nào chưa đủ dữ liệu để chắc chắn, nói rõ "cần kiểm tra gì tiếp" thay vì đoán.
Giữ đúng rào an toàn trong system prompt.
