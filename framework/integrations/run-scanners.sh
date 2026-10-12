#!/usr/bin/env bash
# Preset: chạy loạt SAST (nếu đã cài) + import toàn bộ vào một assessment.
# Dùng:  bash integrations/run-scanners.sh <thư-mục-src> [assessment.json]
# Công cụ nào chưa cài sẽ bị bỏ qua, không lỗi.

set -uo pipefail
SRC="${1:-.}"
OUT="${2:-assessment.json}"
TMP="$(mktemp -d)"

echo "==> builtin regex"
ttf scan "$SRC" --out "$OUT" --merge --engine builtin

if command -v semgrep >/dev/null 2>&1; then
  echo "==> semgrep"
  semgrep scan --config auto --sarif --quiet -o "$TMP/semgrep.sarif" "$SRC" || true
  [ -f "$TMP/semgrep.sarif" ] && ttf import "$TMP/semgrep.sarif" --tool semgrep --out "$OUT" --merge
else
  echo "   (semgrep chưa cài: pip install semgrep)"
fi

if command -v gitleaks >/dev/null 2>&1; then
  echo "==> gitleaks"
  gitleaks detect --no-git --report-format sarif --report-path "$TMP/gitleaks.sarif" --source "$SRC" || true
  [ -f "$TMP/gitleaks.sarif" ] && ttf import "$TMP/gitleaks.sarif" --tool gitleaks --out "$OUT" --merge
else
  echo "   (gitleaks chưa cài)"
fi

if command -v osv-scanner >/dev/null 2>&1; then
  echo "==> osv-scanner (CVE thư viện)"
  osv-scanner --format sarif --output "$TMP/osv.sarif" "$SRC" || true
  [ -f "$TMP/osv.sarif" ] && ttf import "$TMP/osv.sarif" --tool osv --out "$OUT" --merge
else
  echo "   (osv-scanner chưa cài)"
fi

rm -rf "$TMP"
echo "==> xong. Xem:  ttf report $OUT --out report.md"
echo "    Xác nhận động:  ttf probe <probe.config.json> --out $OUT --merge"
