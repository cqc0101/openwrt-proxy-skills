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


if __name__ == "__main__":
    unittest.main()
