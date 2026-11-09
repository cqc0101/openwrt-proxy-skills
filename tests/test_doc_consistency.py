# -*- coding: utf-8 -*-
"""跨文档事实一致性守护。

背景：同一批版本事实（1.13/1.14 字段门控、24.10 包管理器、dae 的 must_direct 粒度）
会同时出现在 SKILL.md、architecture-and-schema.md 等处。
本测试锁定“关键事实在应当出现的地方都出现了”，改动文档时若丢掉事实会立刻失败。
"""

import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SB = os.path.join(REPO, "skills", "singbox-openwrt")
DAE = os.path.join(REPO, "skills", "dae-openwrt")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestSingboxVersionGatingDocs(unittest.TestCase):
    """1.13 专属字段 / 1.14 专属字段必须在精简架构文档与 SKILL 中同时可见。"""

    LEGACY = ["independent_cache", "store_rdrc", "download_detour"]
    MODERN = ["optimistic", "store_dns", "default_http_client"]
    DOCS = [
        os.path.join(SB, "SKILL.md"),
        os.path.join(SB, "references", "architecture-and-schema.md"),
    ]

    def test_legacy_fields_documented(self):
        for doc in self.DOCS:
            text = read(doc)
            with self.subTest(doc=os.path.relpath(doc, REPO)):
                for token in self.LEGACY:
                    self.assertIn(token, text, f"{os.path.basename(doc)} 缺少 1.13 字段 `{token}`")

    def test_modern_fields_documented(self):
        for doc in self.DOCS:
            text = read(doc)
            with self.subTest(doc=os.path.relpath(doc, REPO)):
                for token in self.MODERN:
                    self.assertIn(token, text, f"{os.path.basename(doc)} 缺少 1.14 字段 `{token}`")


class TestSingboxDefaults(unittest.TestCase):
    def test_workflow_default_is_fakeip(self):
        text = read(os.path.join(SB, "references", "architecture-and-schema.md"))
        self.assertIn("1.13 TUN FakeIP", text)
        self.assertIn("--dns-mode fakeip", text)

    def test_compat_matrix_keeps_2410_opkg_fact(self):
        """24.10 使用 opkg（apk 仅 main 分支）——这条曾被写错，必须留证。"""
        text = read(os.path.join(SB, "references", "architecture-and-schema.md"))
        self.assertIn("24.10", text)
        self.assertIn("opkg", text)
        self.assertIn("APK packages are *not* supported", text)


class TestDaeMustDirectGranularity(unittest.TestCase):
    """must_direct 只放行 DNS 流量这一粒度，口径必须一致。"""

    def test_scoped_rule_in_skill_and_guidelines(self):
        for path in (os.path.join(DAE, "SKILL.md"),
                     os.path.join(DAE, "references", "dae-rules-and-syntax.md")):
            text = read(path)
            with self.subTest(doc=os.path.basename(path)):
                self.assertIn("dport(53)", text, "应限定 DNS 端口，而非整进程 must_direct")
                self.assertIn("must_direct", text)


class TestDaeDocsFlattened(unittest.TestCase):
    """references 保持一级深度：不得出现 en/zh 等子目录文档树。"""

    def test_reference_depth(self):
        refs = os.path.join(DAE, "references")
        self.assertTrue(os.path.isdir(refs))
        for root, dirs, files in os.walk(refs):
            rel = os.path.relpath(root, refs)
            if rel == ".":
                continue
            self.fail(f"发现多级文档目录: references/{rel}，必须扁平收拢为一级")



    def test_skill_frontmatter_follows_agentskills_spec(self):
        for skill_dir, expected_name in ((SB, "singbox-openwrt"), (DAE, "dae-openwrt")):
            text = read(os.path.join(skill_dir, "SKILL.md"))
            self.assertTrue(text.startswith("---\n"), "SKILL.md 必须以 YAML frontmatter 开头")
            fm = text.split("---\n", 2)[1]
            self.assertIn(f"name: {expected_name}", fm)
            self.assertIn("description:", fm)
            self.assertIn("license: MIT", fm)
            self.assertIn("compatibility:", fm)


if __name__ == "__main__":
    unittest.main()
