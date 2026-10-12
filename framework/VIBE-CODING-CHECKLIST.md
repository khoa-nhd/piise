# Vibe-Coding Threat Checklist (vòng nhẹ)

> Dán checklist này ngay sau khi vừa code xong một tính năng *có input người dùng,
> phân quyền, hoặc dữ liệu nhạy cảm*. Mục tiêu: chạy một vòng loop rút gọn trong vài
> phút. Khi nghi ngờ điều gì nghiêm trọng → chuyển sang `prompts/run-full-loop.md`.
>
> **Chỉ áp dụng cho app của bạn, trên localhost/staging của bạn.**

## 30 giây: có cần soi không?
Tính năng vừa viết có chạm bất kỳ cái nào sau không?
- [ ] Nhận input người dùng (query/body/param/header/upload)
- [ ] Trả/đọc dữ liệu của *một user cụ thể* (có `{id}`, ownership)
- [ ] Hành động cần quyền (admin, đổi trạng thái, thanh toán)
- [ ] Dữ liệu nhạy cảm (PII, secret, payment, nội dung riêng tư)
- [ ] Gọi ra ngoài (fetch URL, third-party, AI API, storage)

Nếu không tick ô nào → bỏ qua. Tick ≥1 → chạy phần dưới.

## 1 · Attacker mindset
- [ ] External / authenticated / insider — mỗi loại *có thể muốn gì* ở tính năng này?

## 2 · Discover
- [ ] Entry points mới? Trust boundary nào bị chạm (AuthN? AuthZ? Internet→app)?
- [ ] Đối chiếu nhanh `docs/threat-catalog.md` — chọn 1–3 lớp lỗi đáng nghi.

## 3 · Prove (không đoán)
- [ ] Với mỗi nghi ngờ: *chứng minh có kiểm soát trên app của tôi* (2 user test A/B,
      dữ liệu seed). Lộ thật → CONFIRMED + evidence đã redact. Không → hạ mức/đóng.

## 4 · Measure
- [ ] Attacker lấy được *gì* và *bao nhiêu*? (asset_type / accessible / total / sensitive)
- [ ] Ước lượng Attack Reach (fraction + level 0–5) và Blast Radius.

## 5 · Trace
- [ ] entry → weakness → boundary → resource → asset. Attack depth = ?

## 6 · Root-cause fix (không vá triệu chứng)
- [ ] 5 Whys tới tầng thiết kế. Viết **invariant** (1 câu).
- [ ] Fix ở tầng dùng chung (middleware/policy), không sửa lẻ. Thêm test bảo vệ invariant.
- [ ] Liệt kê endpoint "anh em" dùng chung invariant.

## 7 · Re-attack
- [ ] Exploit gốc giờ bị chặn? Thử biến thể (id±1, 0, -1, query↔path, body override, đổi method).
- [ ] Tấn công lại endpoint "anh em" → cái nào còn lộ = finding mới (quay lại bước 2).

## 8 · Report
- [ ] Ghi finding vào `assessment.json` (theo `schema/finding.schema.json`).
- [ ] `PYTHONPATH=src python -m ttf report assessment.json --out report.md`
- [ ] Lưu Security State vòng này để `ttf diff` với vòng sau.

---
Nguyên tắc vàng: **Prove, don't guess · Measure reach, not presence · Fix the invariant,
re-attack the class.**
