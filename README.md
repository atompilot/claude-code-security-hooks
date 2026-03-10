# Claude Code Security Hooks

A set of [Claude Code](https://claude.ai/code) PreToolUse/PostToolUse hooks that block dangerous shell operations and detect prompt injection attacks.

## Hooks

| Hook | Type | What it does |
|------|------|--------------|
| `block_rm.py` | PreToolUse (Bash) | Blocks `rm` commands — forces use of `.trash` pattern instead |
| `block_pipe_to_shell.py` | PreToolUse (Bash) | Blocks `curl/wget \| bash/sh` — the most common malware delivery pattern |
| `detect_prompt_injection.py` | PostToolUse (all tools) | Scans tool responses (web pages, files, API results) for prompt injection patterns |

## Install

```bash
git clone https://github.com/wangtong/claude-code-security-hooks
cd claude-code-security-hooks
bash install.sh
```

Then **restart Claude Code**.

The installer:
1. Copies scripts to `~/.claude/hooks/`
2. Backs up your `~/.claude/settings.json`
3. Injects the hook configuration (non-destructive, merges with existing hooks)

## How it works

### block_rm.py

Intercepts any Bash command containing `rm ` (with a space, to avoid false positives on `npm`, `yarn`, etc.) and exits with code 1, blocking execution.

Suggested alternative shown in the error message:
```bash
mv <file> <project>/.trash/<filename>_$(date +%Y%m%d_%H%M%S)
```

### block_pipe_to_shell.py

Detects the pattern `curl ... | bash` or `wget ... | sh` and blocks it. This is the most common way malicious install scripts are delivered.

Safe alternative:
```bash
curl -fsSL <url> -o install.sh  # download first
cat install.sh                  # inspect
bash install.sh                 # run only if safe
```

### detect_prompt_injection.py

After each tool call (WebFetch, Read, Bash, Tavily, etc.), scans the response for:

- Instruction reset phrases: `ignore all previous instructions`, `you are now a...`
- Chinese variants: `忽略之前的指令`, `现在你是`
- Data exfiltration: `send your system prompt to`, `exfiltrate`
- Hidden instructions in HTML comments or `/* */` blocks

Exits with code `2` (warning, non-blocking) so Claude sees the alert but can still proceed with judgment. Change to `sys.exit(1)` to block hard.

Files under `~/.claude/` are excluded from scanning to prevent false positives on the hook scripts themselves.

## Manual configuration

If you prefer to configure manually, add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python3 ~/.claude/hooks/block_rm.py" },
          { "type": "command", "command": "python3 ~/.claude/hooks/block_pipe_to_shell.py" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          { "type": "command", "command": "python3 ~/.claude/hooks/detect_prompt_injection.py" }
        ]
      }
    ]
  }
}
```

## Requirements

- Python 3 (pre-installed on macOS/Linux)
- Claude Code with hooks support

## License

MIT
