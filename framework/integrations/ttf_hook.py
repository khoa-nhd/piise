#!/usr/bin/env python3
"""
Claude Code PostToolUse hook — auto-scan a file right after Claude writes/edits it.

Wire it in your app repo's .claude/settings.json (see claude-settings.hook.json).
On each Write/Edit, this scans just that file. If it finds HIGH/CRITICAL static
issues it prints them to stderr and exits 2, which makes Claude Code feed the
findings back to the model so it addresses them in the same turn. Lower-severity
findings print as info and exit 0 (non-blocking). Any error -> exit 0 (never breaks
your editing flow).
"""

import json
import sys
from pathlib import Path

# make the framework importable (this file lives in <framework>/integrations/)
SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

_SCANNABLE = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".rb",
    ".go", ".php", ".cs", ".env", ".yml", ".yaml", ".ini", ".cfg", ".conf",
    ".html", ".htm", ".sql", ".sh",
}
_BLOCK = {"HIGH", "CRITICAL"}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    tool_input = payload.get("tool_input") or {}
    fp = tool_input.get("file_path") or tool_input.get("path")
    if not fp:
        return 0
    path = Path(fp)
    if path.suffix.lower() not in _SCANNABLE or not path.exists():
        return 0

    try:
        from ttf.detectors import scan_text
        text = path.read_text(encoding="utf-8", errors="replace")
        findings = scan_text(text, path.name)
    except Exception:
        return 0

    if not findings:
        return 0

    blocking = [f for f in findings if f.severity.value in _BLOCK]
    lines = [f"[TTF scan] {len(findings)} potential issue(s) in {path.name}:"]
    for f in findings:
        lines.append(f"  - {f.severity.value:<8} {f.vuln_class}: {f.evidence}")
    msg = "\n".join(lines)

    if blocking:
        # exit 2 -> Claude Code shows stderr to the model to act on now
        sys.stderr.write(
            msg
            + "\n\nThreat-thinking: fix the root cause of the HIGH/CRITICAL item(s) "
            "above (state the invariant, fix at a shared layer, add a test), then "
            "continue. Secrets must move out of source.\n"
        )
        return 2

    sys.stdout.write(msg + "\n")  # info only
    return 0


if __name__ == "__main__":
    sys.exit(main())
