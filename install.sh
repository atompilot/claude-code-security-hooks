#!/usr/bin/env bash
# Claude Code Security Hooks — Installer
set -euo pipefail

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS="$HOME/.claude/settings.json"

echo "🔒 Installing Claude Code Security Hooks..."

# 1. Create hooks directory
mkdir -p "$HOOKS_DIR"

# 2. Copy hook scripts
cp block_rm.py "$HOOKS_DIR/block_rm.py"
cp block_pipe_to_shell.py "$HOOKS_DIR/block_pipe_to_shell.py"
cp detect_prompt_injection.py "$HOOKS_DIR/detect_prompt_injection.py"
chmod +x "$HOOKS_DIR/block_rm.py" "$HOOKS_DIR/block_pipe_to_shell.py" "$HOOKS_DIR/detect_prompt_injection.py"
echo "✅ Hook scripts installed to $HOOKS_DIR"

# 3. Backup settings.json
if [ -f "$SETTINGS" ]; then
    BACKUP="$SETTINGS.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$SETTINGS" "$BACKUP"
    echo "✅ Backed up settings to $BACKUP"
else
    echo '{}' > "$SETTINGS"
fi

# 4. Inject hooks into settings.json using Python (avoids jq dependency)
python3 - "$SETTINGS" <<'PYEOF'
import json, sys

path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)

hooks = cfg.setdefault("hooks", {})

# PreToolUse: block rm + block curl|bash (attach to existing Bash matcher if present)
pre = hooks.setdefault("PreToolUse", [])
bash_matchers = [e for e in pre if e.get("matcher") == "Bash"]
if bash_matchers:
    entry = bash_matchers[0]
else:
    entry = {"matcher": "Bash", "hooks": []}
    pre.append(entry)

existing_cmds = {h["command"] for h in entry["hooks"]}
for cmd in [
    "python3 ~/.claude/hooks/block_rm.py",
    "python3 ~/.claude/hooks/block_pipe_to_shell.py",
]:
    if cmd not in existing_cmds:
        entry["hooks"].append({"type": "command", "command": cmd})

# PostToolUse: detect prompt injection
post = hooks.setdefault("PostToolUse", [])
inject_cmd = "python3 ~/.claude/hooks/detect_prompt_injection.py"
already = any(
    h["command"] == inject_cmd
    for e in post
    for h in e.get("hooks", [])
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
echo "  PreToolUse  (Bash)  → block_rm.py             — blocks 'rm' commands"
echo "  PreToolUse  (Bash)  → block_pipe_to_shell.py  — blocks curl/wget | bash"
echo "  PostToolUse (all)   → detect_prompt_injection.py — detects prompt injection in tool responses"
