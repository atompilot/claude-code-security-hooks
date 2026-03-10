#!/usr/bin/env python3
"""
Claude Code PreToolUse hook: 阻止 rm 命令，强制使用 .trash 方式
"""
import json
import re
import sys

data = json.load(sys.stdin)
command = data.get("tool_input", {}).get("command", "")

# 检测 rm 模式：行首 rm、管道后 rm、&& 后 rm、; 后 rm 等
# 要求 rm 后跟空格，避免误匹配 npm、yarn、pnpm 等内部逻辑
if re.search(r'(?:^|[;&|]\s*)\s*rm\s+', command, re.MULTILINE):
    print(
        "❌ 禁止使用 rm 命令！\n"
        "请使用 .trash 方式移动文件：\n"
        "  mv <file> <project>/.trash/<filename>_$(date +%Y%m%d_%H%M%S)",
        file=sys.stderr
    )
    sys.exit(1)

sys.exit(0)
