# 00 — Tổng quan: Threat Thinking Loop

## Ý tưởng cốt lõi

Quy trình thông thường dừng quá sớm:

```
Code → Scan → Fix
```

Threat Thinking Loop kéo dài tư duy đến tận tác động thật và nguyên nhân gốc:

```
Build → Think like attacker → Discover → Prove → Measure → Trace
      → Root-cause Fix → Re-attack → Discover again → Report
```

**Điểm quan trọng nhất:** "có vulnerability" *không* phải điểm kết thúc. Bạn phải trả
lời được chuỗi: attacker đi **từ đâu → qua bước nào → đến đâu → lấy được gì → nghiêm
trọng đến mức nào**. Đó là chỗ framework khác một scanner.

## Sơ đồ loop

```
┌─────────────────────────────┐
│ 1. ATTACKER MINDSET         │  "Nếu tôi là attacker?"
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ 2. DISCOVER                 │  Attack surface + trust boundaries
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ 3. EXPLOIT (PROVE)          │  Khai thác được THẬT không?
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ 4. MEASURE                  │  Attacker thực sự lấy được gì?
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ 5. TRACE                    │  Attack path A → B
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ 6. ROOT-CAUSE FIX           │  Sửa invariant, không vá triệu chứng
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ 7. RE-ATTACK                │  Tấn công lại + variant + regression
└──────────────┬──────────────┘
               ↓
        ┌──────┴──────┐
        ↓             ↓
      PASS         NEW BUG ──────→ quay lại DISCOVER
        ↓
┌─────────────────────────────┐
│ 8. SECURITY REPORT          │  Evidence + metrics + attack path
└─────────────────────────────┘
```

## Ba nguyên tắc xuyên suốt

1. **Prove, don't guess.** Mỗi finding mang một mức *Exploitability*:
   `POTENTIAL → PLAUSIBLE → CONFIRMED`. Chỉ CONFIRMED mới được tính là rủi ro đầy đủ.
2. **Measure reach, not just presence.** Đo *attacker lấy được bao nhiêu* (Attack
   Reach, Blast Radius), không chỉ đếm số lỗi.
3. **Fix the invariant, re-attack the class.** Sửa nguyên nhân gốc (một security
   invariant), rồi tấn công lại cả *lớp lỗi* — gồm các endpoint "anh em" (regression).

## Trust boundary là gì (và vì sao quan trọng)

Trust boundary là ranh giới nơi mức độ tin cậy thay đổi: Internet → app, user này →
user khác, user thường → admin, app → database/third-party. **Hầu hết lỗ hổng nghiêm
trọng là một lần vượt trust boundary mà lẽ ra phải bị chặn.** Phase 2 vẽ các ranh giới
này; Phase 5 ghi lại ranh giới nào bị vượt.

## Vòng đời một finding

```
hypothesis (P1/P2)
   → proven exploit (P3, Exploitability=CONFIRMED, có evidence)
   → measured exposure + reach (P4)
   → attack path + depth (P5)
   → root cause + invariant + remediation (P6, status=FIXED)
   → re-attack blocked + variants + regressions (P7, Exploitability=BLOCKED)
   → status=RESOLVED, vào report (P8)
```

Mỗi vòng loop tạo một **Security State** snapshot. So sánh các snapshot cho thấy tiến
bộ thật (risk giảm bao nhiêu %), xem [metrics.md](metrics.md).

## Khi nào chạy loop lúc vibe coding

Chạy một vòng nhẹ ngay sau khi vừa thêm/sửa bất kỳ thứ nào sau:
- endpoint/route mới, hoặc đổi logic phân quyền;
- xử lý input người dùng (query, form, upload, params);
- truy cập dữ liệu nhạy cảm (user khác, PII, payment, secrets);
- tích hợp third-party / AI API / storage.

Dùng [../VIBE-CODING-CHECKLIST.md](../VIBE-CODING-CHECKLIST.md) cho vòng nhẹ, hoặc các
prompt trong [../prompts/](../prompts/) khi muốn AI chạy đầy đủ từng phase.
