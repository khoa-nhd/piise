---
description: Chạy threat-thinking loop trên thay đổi hiện tại (scan + mindset + fix gốc)
---

Chạy một vòng Threat Thinking Loop trên các thay đổi chưa commit của repo này.

Bối cảnh thay đổi hiện tại:
!`git diff --stat` 
!`git diff`

Các bước:

1. Chạy static scan trên mã nguồn và tóm tắt findings:
   !`ttf scan . --out .ttf-assessment.json 2>&1 | head -40`

2. Với phần diff ở trên, làm **threat-thinking pass** (giữ đúng rào an toàn: chỉ app
   local của tôi, dữ liệu test, redact evidence):
   - Attacker mindset (external / authenticated / insider) cho đúng code vừa đổi.
   - Nghi ngờ nào từ scan hoặc từ diff? Gán POTENTIAL/PLAUSIBLE/CONFIRMED, nói cách tái
     hiện trên app local. Nếu có endpoint `{id}` → đề xuất lệnh `ttf probe` tương ứng.
   - Measure (reach/blast), Trace (entry→…→asset).
   - **Root-cause fix**: invariant + fix tầng dùng chung + test. Không vá một dòng.
   - Re-attack plan: biến thể + endpoint anh em.

3. Xuất khối JSON `findings` khớp schema để tôi ghép vào assessment, rồi gợi ý lệnh
   `ttf report`.

Nếu diff không chạm input/authz/dữ liệu nhạy cảm/gọi ngoài thì nói rõ "không cần soi"
và dừng.

$ARGUMENTS
