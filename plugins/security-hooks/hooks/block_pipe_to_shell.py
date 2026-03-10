#!/usr/bin/env python3
"""
Claude Code PreToolUse hook: 阻止 curl/wget pipe 到 shell 的高危操作
"""
import json
import re
import sys

data = json.load(sys.stdin)
command = data.get("tool_input", {}).get("command", "")

# 检测 curl 或 wget 的输出 pipe 到 shell 的模式
# 例如：curl ... | bash、wget -O- ... | sh、curl ... | python3 等
PIPE_TO_SHELL_PATTERN = re.compile(
    r'(curl|wget)\b.+\|\s*(ba)?sh\b',
    re.MULTILINE | re.DOTALL
)

if PIPE_TO_SHELL_PATTERN.search(command):
    print(
        "❌ 高危操作被阻止：禁止将 curl/wget 内容直接 pipe 到 shell！\n"
        "\n"
        "这是常见的恶意软件植入方式。请改用安全方式：\n"
        "  1. 先下载脚本：curl -fsSL <url> -o install.sh\n"
        "  2. 检查内容：cat install.sh\n"
        "  3. 确认安全后再执行：bash install.sh",
        file=sys.stderr
    )
    sys.exit(1)

sys.exit(0)
