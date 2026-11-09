# -*- coding: utf-8 -*-
"""文档链接完整性：SKILL.md / README / 自研 reference 里的相对链接必须真实存在。

范围说明：dae-openwrt/references 是上游官方文档镜像，内部 wiki 链接按上游原样保留，不在检查范围。
"""

import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LINK_RE = re.compile(r"\]\((?!https?://)(?!mailto:)([^)#]+)")


def _checked_md_files():
    yield os.path.join(REPO, "README.md")
    for skill in ("singbox-openwrt", "dae-openwrt"):
        base = os.path.join(REPO, "skills", skill)
        yield os.path.join(base, "SKILL.md")
        refs = os.path.join(base, "references")
        if os.path.isdir(refs):
            for name in sorted(os.listdir(refs)):
                if name.endswith(".md"):
                    yield os.path.join(refs, name)


class TestDocLinks(unittest.TestCase):
    def test_all_relative_links_resolve(self):
        broken = []
        for path in _checked_md_files():
            base = os.path.dirname(path)
            with open(path, encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    for m in LINK_RE.finditer(line):
                        target = m.group(1).strip()
                        full = os.path.normpath(os.path.join(base, target))
                        if not os.path.exists(full):
                            broken.append(f"{os.path.relpath(path, REPO)}:{lineno} -> {target}")
        self.assertEqual(broken, [], "存在断链:\n" + "\n".join(broken))

    def test_no_deprecated_script_names_or_typos(self):
        """防呆测试：确保所有 .md / .py / .sh 中绝不残留废弃脚本名或命令行拼写笔误。"""
        forbidden_rules = [
            (re.compile(r"setup_openwrt_firewall\.sh"), "已更名为 setup_openwrt_network.sh"),
            (re.compile(r"diagnose\s+dns\.sh"), "下划线被误写为空格：应为 diagnose_dns.sh"),
            (re.compile(r"sub_parser\.py[^\n]*--format\s+dae"), "dae 格式订阅清洗应直接调用 sub_to_dae.py"),
            (re.compile(r"sub_parser\.py[^\n]*--(url|sub|max-nodes|out)\b"), "sub_parser.py 不存在 --url/--sub/--max-nodes/--out 参数"),
            (re.compile(r"\bdeploy_singbox\.(sh|ps1)\b"), "deploy_singbox 脚本已废弃移除"),
            (re.compile(r"\bsetup_openwrt_network\.ps1\b"), "setup_openwrt_network.ps1 已废弃移除"),
            (re.compile(r"\bprobe\.ps1\b"), "probe.ps1 已废弃移除"),
            (re.compile(r'gemini-up\\skills-gemini'), "严禁硬编码个人本地磁盘路径"),
        ]
        violations = []
        skip_dirs = {".git", ".deploy_key", "__pycache__"}
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                if file.endswith((".md", ".py", ".sh")):
                    full = os.path.join(root, file)
                    rel = os.path.relpath(full, REPO).replace("\\", "/")
                    # 排除本测试文件自身
                    if rel in ("tests/test_docs.py", "CHANGELOG.md", "HARDENING_REPORT.md", "docs/validation-report-x1pro.md"):
                        continue
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        for lineno, line in enumerate(f, 1):
                            for pat, reason in forbidden_rules:
                                if pat.search(line):
                                    violations.append(f"{rel}:{lineno} 发现禁词 [{pat.pattern}] -> {reason}")
        self.assertEqual(violations, [], "发现废弃脚本名或拼写错误:\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
