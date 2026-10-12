# Threat Thinking Framework (TTF)

> Một **threat-thinking loop** để lồng vào lúc *vibe coding*: vừa code (với AI) vừa
> tự nghĩ như attacker, chứng minh khai thác được, đo mức độ, truy vết đường đi,
> sửa tận gốc, tấn công lại, rồi xuất báo cáo.
>
> **Chỉ dùng cho ứng dụng bạn sở hữu / đang phát triển, hoặc có phép kiểm thử.**
> Xem [`.ttf/scope.example.json`](.ttf/scope.example.json).

---

## Vì sao khác một vulnerability scanner

Scanner dừng ở *"có thể có lỗi"*. Framework này không coi đó là điểm kết thúc. Nó
bắt bạn trả lời: **attacker thực sự đi từ đâu → qua những bước nào → đến đâu → lấy
được gì → tác động lớn đến mức nào**, rồi **sửa invariant (nguyên nhân gốc)** chứ
không vá một dòng, và **tấn công lại** để chắc rằng cả *lớp lỗi* bị chặn, không chỉ
mẫu lỗi.

```
Build → Think like attacker → Discover → Prove → Measure → Trace
      → Root-cause Fix → Re-attack → Discover again → Report   ↺
```

Loop **không kết thúc sau khi fix** — mỗi fix mở ra một vòng tìm lỗi mới (đặc biệt là
*regression* ở các endpoint "anh em" dùng chung giả định sai).

---

## 8 phases

| # | Phase | Câu hỏi cốt lõi | Tài liệu |
|---|-------|-----------------|----------|
| 1 | Attacker Mindset | "Nếu tôi là attacker thì sẽ làm gì?" | [docs/phases/1-attacker-mindset.md](docs/phases/1-attacker-mindset.md) |
| 2 | Discover | Attack surface & trust boundaries ở đâu? | [docs/phases/2-discover.md](docs/phases/2-discover.md) |
| 3 | Exploit (Prove) | Có khai thác **thật** được không? | [docs/phases/3-exploit.md](docs/phases/3-exploit.md) |
| 4 | Measure | Attacker **thực sự lấy được gì**? | [docs/phases/4-measure.md](docs/phases/4-measure.md) |
| 5 | Trace | Attack path A → B đi qua đâu? | [docs/phases/5-trace.md](docs/phases/5-trace.md) |
| 6 | Root-cause Fix | **Vì sao** lỗi tồn tại? Invariant nào vỡ? | [docs/phases/6-root-cause-fix.md](docs/phases/6-root-cause-fix.md) |
| 7 | Re-attack | Fix chặn cả *lớp lỗi* + regression chưa? | [docs/phases/7-re-attack.md](docs/phases/7-re-attack.md) |
| 8 | Report | Evidence + metrics + attack path | [docs/phases/8-report.md](docs/phases/8-report.md) |

Tổng quan + sơ đồ loop: [docs/00-overview.md](docs/00-overview.md).
Bộ metrics (Attack Reach, Attack Depth, Blast Radius, Risk, Security Improvement,
Security State): [docs/metrics.md](docs/metrics.md).

---

## Hai lớp: methodology (prompt/docs) + tooling chạy thật (Python)

Framework có **hai lớp khác bản chất**:

1. **Methodology** — `docs/`, `prompts/`, `templates/`, checklist: văn bản hướng dẫn
   bạn + AI tư duy theo loop. Dùng cho suy luận (mindset, root-cause).
2. **Tooling chạy thật** — `src/ttf/`: code Python thuần (không gọi AI), gồm:
   - **① Scanner** `ttf scan` — tự quét source tìm pattern lỗi (secret, SQLi, CORS,
     JWT, IDOR-route…) và tự điền findings.
   - **② Probe** `ttf probe` — tự đăng nhập tài khoản test rồi **thử tấn công IDOR
     thật** trên app local của bạn, tự đo exposure + re-attack. Có rào an toàn cứng
     (chỉ host local, bắt buộc `scope_ack`).
   - **Metrics + report** `ttf report/diff/state/validate` — biến dữ liệu thành báo cáo
     + metric + % cải thiện.

   Chi tiết lớp tự động: [docs/automation.md](docs/automation.md). Chạy thử trọn vòng
   với demo app cố tình có lỗi: [examples/demo-app/](examples/demo-app/).

---

## Ba cách dùng

### A. Trong lúc vibe coding (không cần code, chỉ cần tư duy + AI)

Sau khi viết xong một tính năng có **đầu vào người dùng, quyền truy cập, hoặc dữ
liệu nhạy cảm**, dán [VIBE-CODING-CHECKLIST.md](VIBE-CODING-CHECKLIST.md) hoặc một
prompt trong [`prompts/`](prompts/) vào AI pair-programmer của bạn. Mỗi prompt tương
ứng một phase và bắt AI đi đúng loop thay vì chỉ "quét qua".

Nguyên tắc an toàn khi để AI đóng vai attacker:
- Chỉ nhắm vào app của **bạn**, ưu tiên `localhost` / staging của chính bạn.
- "Khai thác" = *chứng minh* trên instance của bạn (đọc được bản ghi test), **không**
  phát tán payload, không nhắm hệ thống của người khác, không né bot-detection.
- Dùng **dữ liệu test** (seed/fixture), không dùng credential/dữ liệu thật.

### B. Tự động: dò (3 nguồn) + attack thử (4 lớp)

Cài lệnh `ttf` một lần: `pip install -e .` (hoặc dùng `PYTHONPATH=src python -m ttf`).

```bash
# DÒ tĩnh — 3 nguồn bù nhau:
ttf scan ./src --out assessment.json                 # ① builtin regex (0 phụ thuộc)
ttf scan ./src --engine all --out assessment.json --merge   # + semgrep + gitleaks (nếu đã cài)
ttf import semgrep.sarif --out assessment.json --merge       # H1: nhập SARIF bất kỳ tool
ttf import llm-findings.json --format ttf --out assessment.json --merge   # H2: findings AI tạo

# ATTACK THỬ động — 4 lớp (idor / function-authz / mass-assignment / auth-bypass):
ttf probe probe.config.json --out assessment.json --merge              # -> CONFIRMED
ttf probe probe.config.json --out assessment.json --merge --reattack   # sau fix -> BLOCKED
```
Chi tiết kiến trúc 3-lớp-dò + 4-lớp-tấn-công + rào an toàn: [docs/automation.md](docs/automation.md).
Chạy thử end-to-end (demo app có đủ 4 lỗi): [examples/demo-app/](examples/demo-app/).

### C. CLI để mô hình hoá + xuất báo cáo

Toolkit Python (chỉ dùng thư viện chuẩn, không cần cài gì):

```bash
# Tạo khung assessment rỗng
PYTHONPATH=src python -m ttf init "My App" --out my-assessment.json

# Kiểm tra tính nhất quán (vd: CONFIRMED mà thiếu evidence, HIGH mà thiếu root cause)
PYTHONPATH=src python -m ttf validate my-assessment.json

# Xuất Threat Report
PYTHONPATH=src python -m ttf report my-assessment.json --out report.md

# Snapshot security state (JSON) và so sánh 2 vòng
PYTHONPATH=src python -m ttf state  my-assessment.json
PYTHONPATH=src python -m ttf diff   cycle3.json cycle4.json
```

Ví dụ hoàn chỉnh (IDOR e-commerce từ spec): [examples/ecommerce-idor/](examples/ecommerce-idor/) —
mở [report.md](examples/ecommerce-idor/report.md) để xem output.

---

## Cấu trúc thư mục

```
framework/
├── README.md
├── VIBE-CODING-CHECKLIST.md     # checklist dán nhanh khi đang code
├── docs/
│   ├── 00-overview.md           # loop + triết lý
│   ├── automation.md            # ① scanner + ② probe (lớp chạy tự động)
│   ├── metrics.md               # định nghĩa & công thức mọi metric
│   ├── threat-catalog.md        # các lớp lỗi hay gặp ở app vibe-coded
│   └── phases/1..8-*.md         # 8 phase, mỗi phase 1 file
├── prompts/                     # prompt template cho AI pair-programmer theo từng phase
├── templates/                   # mẫu attack-surface-map / attack-path / threat-report
├── schema/                      # JSON Schema cho finding / assessment / security-state
├── examples/
│   ├── ecommerce-idor/          # ví dụ assessment + report đã render
│   └── demo-app/                # app cố tình có lỗi (stdlib) + probe config để chạy thử
├── src/ttf/                     # toolkit Python:
│   ├── models.py metrics.py report.py cli.py
│   ├── detectors.py             # ① builtin regex scanner
│   ├── importers.py             # H1: SARIF/LLM-findings -> Finding
│   └── prober.py                # ②/H4: probe 4 lớp (idor/authz/mass-assign/auth-bypass)
├── tests/                       # smoke + scanner tests (python thuần)
└── .ttf/scope.example.json      # khai báo phạm vi được phép kiểm thử
```

## Yêu cầu

- Python 3.11+ cho CLI (đã test trên 3.14, không phụ thuộc thư viện ngoài).
- Phần methodology + prompts không cần cài gì.

## Giới hạn & đạo đức

Framework hỗ trợ **kiểm thử phòng thủ / tự đánh giá có phép**. Nó không tạo ra
exploit đóng gói sẵn để tấn công hệ thống người khác, không né tránh phát hiện, và
không thực hiện hành vi phá hoại. Luôn khai báo phạm vi trong `.ttf/scope.json`
trước khi bắt đầu một vòng.
