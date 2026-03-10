#!/usr/bin/env bash
# Claude Code Security Hooks — Standalone Installer
# Use this if you prefer not to use the Claude Code plugin system.
# Plugin users: /plugin marketplace add atompilot/claude-code-security-hooks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_SRC="$SCRIPT_DIR/plugins/security-hooks/hooks"
HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS="$HOME/.claude/settings.json"

echo "🔒 Installing Claude Code Security Hooks (standalone)..."

# 1. Create hooks directory
mkdir -p "$HOOKS_DIR"

# 2. Copy hook scripts
cp "$HOOKS_SRC/block_rm.py" "$HOOKS_DIR/block_rm.py"
cp "$HOOKS_SRC/block_pipe_to_shell.py" "$HOOKS_DIR/block_pipe_to_shell.py"
cp "$HOOKS_SRC/detect_prompt_injection.py" "$HOOKS_DIR/detect_prompt_injection.py"
chmod +x "$HOOKS_DIR/block_rm.py" \
         "$HOOKS_DIR/block_pipe_to_shell.py" \
         "$HOOKS_DIR/detect_prompt_injection.py"
echo "✅ Hook scripts installed to $HOOKS_DIR"

# 3. Backup settings.json
if [ -f "$SETTINGS" ]; then
    BACKUP="$SETTINGS.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$SETTINGS" "$BACKUP"
    echo "✅ Backed up settings to $BACKUP"
else
    echo '{}' > "$SETTINGS"
fi

# 4. Merge hooks into settings.json
python3 - "$SETTINGS" <<'PYEOF'
import json, sys

path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)

hooks = cfg.setdefault("hooks", {})

# PreToolUse: block rm + block curl|bash
pre = hooks.setdefault("PreToolUse", [])
bash_entries = [e for e in pre if e.get("matcher") == "Bash"]
entry = bash_entries[0] if bash_entries else {"matcher": "Bash", "hooks": []}
if not bash_entries:
    pre.append(entry)

existing = {h["command"] for h in entry["hooks"]}
for cmd in [
    "python3 ~/.claude/hooks/block_rm.py",
    "python3 ~/.claude/hooks/block_pipe_to_shell.py",
]:
    if cmd not in existing:
        entry["hooks"].append({"type": "command", "command": cmd})

# PostToolUse: detect prompt injection
post = hooks.setdefault("PostToolUse", [])
inject_cmd = "python3 ~/.claude/hooks/detect_prompt_injection.py"
already = any(
    h["command"] == inject_cmd
    for e in post for h in e.get("hooks", [])
)
if not already:
    post.append({
        "matcher": ".*",
        "hooks": [{"type": "command", "command": inject_cmd}]
    })

with open(path, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")

print("✅ settings.json updated")
PYEOF

echo ""
echo "✅ Done! Restart Claude Code for hooks to take effect."
echo ""
echo "Hooks installed:"
echo "  PreToolUse  (Bash) → block_rm.py              blocks 'rm' commands"
echo "  PreToolUse  (Bash) → block_pipe_to_shell.py   blocks curl/wget | bash"
echo "  PostToolUse (web)  → detect_prompt_injection.py  detects prompt injection"
