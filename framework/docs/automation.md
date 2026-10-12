# Automation — lớp "dò" + "attack thử" chạy thật

TTF **không cố làm một scanner tốt hơn**. Nó là lớp **điều phối + chứng minh + đo +
loop** đặt *trên* các công cụ mạnh nhất cho từng việc. Lớp "dò" (discover) có 3 nguồn,
lớp "attack thử" (confirm) là probe động.

```
Tĩnh (độ phủ)                    Động (chứng minh)
─────────────                    ─────────────────
① builtin regex   ─┐
Semgrep/CodeQL…   ─┼─► assessment.json ─► ② probe (4 lớp) ─► report / diff
LLM semantic scan ─┘     (findings[])       CONFIRMED/BLOCKED
```

> Quy tắc: tĩnh chỉ cho ra **POTENTIAL** (nghi). Probe mới nâng lên **CONFIRMED** (chắc)
> hoặc **BLOCKED** (đã fix).

---

## Lớp DÒ (discover) — 3 nguồn, bù nhau

### ① builtin regex — `ttf scan` (0 phụ thuộc)
```bash
ttf scan ./src --out assessment.json
```
Nhanh, chạy mọi nơi, nhưng chỉ bắt **mẫu đã biết**. Dùng làm fallback khi chưa cài gì.

### H1 — cắm SAST có sẵn qua SARIF (độ phủ cao nhất)
Mọi SAST hiện đại xuất **SARIF** (JSON chuẩn). TTF có một adapter duy nhất: SARIF →
`Finding`. Nhờ đó dùng được hàng nghìn rule AST + quét CVE thư viện.

```bash
# cách A: TTF tự gọi công cụ (nếu đã cài)
ttf scan ./src --engine semgrep --out assessment.json --merge
ttf scan ./src --engine all      # builtin + semgrep + gitleaks

# cách B: bạn tự chạy công cụ rồi import file SARIF (dùng được với MỌI tool)
semgrep scan --config auto --sarif -o sg.sarif ./src
ttf import sg.sarif --out assessment.json --merge
```
Hỗ trợ sẵn runner cho **semgrep** và **gitleaks**; mọi tool khác (CodeQL, Bandit, Trivy,
osv-scanner…) chỉ cần xuất SARIF rồi `ttf import`. Preset chạy loạt tool:
[../integrations/run-scanners.sh](../integrations/run-scanners.sh).

### H2 — LLM semantic scan (bắt lỗi logic)
Static mù với lỗi *logic/nghiệp vụ/thiếu authz*. Cho AI đọc *hiểu* code rồi xuất findings
đúng schema, nhập lại như mọi nguồn khác:
```bash
# dán prompts/phase2-llm-scan.md + diff cho AI -> nó xuất llm-findings.json
ttf import llm-findings.json --format ttf --out assessment.json --merge
```
AI để mức POTENTIAL/PLAUSIBLE; nếu là IDOR/authz/… thì probe sẽ xác nhận.

---

## Lớp ATTACK THỬ (confirm) — `ttf probe`, 4 lớp tấn công (H4)

Thực sự gửi request vào app **local** của bạn, nâng finding lên CONFIRMED/BLOCKED. Chọn
lớp tấn công bằng `type` trong mỗi target của config:

| `type` | Làm gì | Kết luận "lộ" khi |
|--------|--------|-------------------|
| `idor` | đăng nhập A, đọc object của B | trả 2xx + dữ liệu của B |
| `function-authz` | user thường gọi endpoint admin | trả 2xx (lẽ ra 403) |
| `mass-assignment` | gửi field cấm (vd `role:admin`) | field đó *có tác dụng* trong phản hồi |
| `auth-bypass` | gọi endpoint bảo vệ **không** token | trả 2xx + dữ liệu |

```bash
ttf probe probe.config.json --out assessment.json --merge             # vòng đầu
ttf probe probe.config.json --out assessment.json --merge --reattack  # sau khi fix
```
Config mẫu đủ 4 lớp: [../examples/demo-app/probe.config.json](../examples/demo-app/probe.config.json).

**Rào an toàn (cứng):** từ chối nếu thiếu `scope_ack`; chỉ host local trừ khi ghi
`i_own_target`; chỉ dùng tài khoản test; evidence chỉ ghi *tên trường* nhạy cảm + status,
không lưu giá trị thật.

---

## Demo end-to-end (đã kiểm chứng)

```bash
python examples/demo-app/app.py            # VULNERABLE (4 lỗi)  [terminal khác]
ttf probe examples/demo-app/probe.config.json --out demo.json       # 4/4 CONFIRMED
ttf report demo.json --out demo-report.md

TTF_DEMO_FIXED=1 python examples/demo-app/app.py                     # FIXED [terminal khác]
ttf probe examples/demo-app/probe.config.json --out demo.json --merge --reattack  # 4/4 BLOCKED
ttf diff cycle_truoc.json demo.json        # % cải thiện
```
Kết quả thực: 4 lớp tấn công đi từ CONFIRMED → BLOCKED sau fix; risk giảm tương ứng.

---

## Giới hạn (nói thẳng)
- builtin regex yếu (chỉ mẫu đã biết) → dùng Semgrep/LLM bù.
- probe tự động 4 lớp **access-control/authn**; injection/SSRF… vẫn xác nhận qua LLM + tay.
- LLM scan có thể bịa/bỏ sót → luôn để POTENTIAL/PLAUSIBLE rồi probe xác nhận khi có thể.
- Suy luận root-cause (Phase 6) là người + AI.
