# Prompt — H2: LLM-based semantic scan

(Kèm `system-threat-agent.md` làm nền.)

Dùng khi muốn AI tìm những lỗi mà regex/SAST **không thấy**: lỗi logic/nghiệp vụ,
thiếu kiểm tra phân quyền, tin client sai, luồng dữ liệu (taint) phức tạp. AI đọc *hiểu*
code, không chỉ so mẫu.

---

Đọc phần code/diff sau của app **tôi sở hữu** và tìm lỗ hổng bảo mật — tập trung vào
thứ mà công cụ tĩnh bỏ sót: **logic, phân quyền, tin tưởng client, luồng dữ liệu**.

```
<dán diff hoặc các file liên quan>
```

Đối chiếu với `$TTF_HOME/docs/threat-catalog.md`. Với mỗi lỗ hổng:
- `vuln_class`, `severity`, `attacker` (EXTERNAL/AUTHENTICATED/INSIDER/PRIVILEGED).
- `entry_point` (file:line hoặc route), `hypothesis` (vì sao nghi), `evidence` (trích
  code, **redact** dữ liệu thật).
- `exploitability`: để **POTENTIAL** hoặc **PLAUSIBLE** — vì đây là đọc code, chưa chứng
  minh động. (Việc nâng lên CONFIRMED để `ttf probe` lo.) Nếu là lỗi dạng IDOR/authz/
  mass-assignment/auth-bypass, **nói rõ nên tạo target `ttf probe` nào** để xác nhận.
- `attack_path.steps` (entry→weakness→boundary→resource→asset) nếu suy ra được.

Yêu cầu định dạng đầu ra: **CHỈ** một khối JSON là **mảng findings** khớp
`$TTF_HOME/schema/finding.schema.json`, ví dụ:

```json
[
  {
    "id": "L-001",
    "title": "...",
    "vuln_class": "Broken access control",
    "severity": "HIGH",
    "exploitability": "PLAUSIBLE",
    "attacker": "AUTHENTICATED",
    "entry_point": "routes/orders.js:42",
    "hypothesis": "...",
    "evidence": "...",
    "attack_path": {"id":"AP-L1","entry_point":"...","steps":[{"kind":"entry","label":"..."}],"impact":"..."},
    "tags": ["llm-scan"]
  }
]
```

Lưu khối JSON đó vào `llm-findings.json`, rồi tôi nhập vào assessment bằng:

```bash
ttf import llm-findings.json --format ttf --out assessment.json --merge
```

Không bịa lỗi để cho đủ số — nếu không chắc, ghi `exploitability: POTENTIAL` và nói cần
kiểm chứng gì. Giữ nguyên rào an toàn trong system prompt.
