# -*- coding: utf-8 -*-
"""结构与文档一致性：README 目录树、顶层条目、参考文档孤儿、README/SKILL 链接。

与 test_docs.py 的分工：
- test_docs.py：所有相对链接必须指向存在文件（防断链）
- 本文件：README 目录树必须与真实结构一致；顶层条目不得漏写；references 不得有孤儿文档
"""

import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", ".tmp", ".deploy_key", "__pycache__"}
# 顶层文件允许不写进目录树（README 的树只列目录与关键入口）
TREE_IGNORABLE = {"README.md", "CHANGELOG.md", "LICENSE", "NOTICE.md", ".gitignore", ".gitattributes"}

NODE_RE = re.compile(r"^((?:\u2502   |    )*)(?:\u251c\u2500\u2500 |\u2514\u2500\u2500 )(.+)$")


def scan_repo():
    files, dirs = set(), set()
    for root, ds, fs in os.walk(REPO):
        rel = os.path.relpath(root, REPO)
        parts = [] if rel == "." else rel.split(os.sep)
        if any(p in SKIP_DIRS for p in parts):
            ds[:] = []
            continue
        if parts:
            dirs.add("/".join(parts))
        for f in fs:
            files.add("/".join(parts + [f]))
    return files, dirs


def read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


def readme_tree_paths():
    text = read("README.md")
    m = re.search(r"## 目录结构\s*\n```\n(.*?)```", text, re.S)
    if not m:
        return None
    paths, stack = set(), []
    for line in m.group(1).splitlines():
        nm = NODE_RE.match(line.rstrip())
        if not nm:
            continue
        depth = len(nm.group(1)) // 4
        name = nm.group(2).split("#")[0].strip().rstrip("/")
        if not name:
            continue
        stack = stack[:depth]
        segs = stack + name.split("/")   # 支持 ".github/workflows/ci.yml" 这类复合名
        for k in range(1, len(segs) + 1):
            paths.add("/".join(segs[:k]))
        stack.append(name)
    return paths


def md_links():
    for path in scan_repo()[0]:
        if not path.endswith(".md"):
            continue
        base = os.path.dirname(path)
        for m in re.finditer(r"\]\((?!https?://)(?!mailto:)([^)#\s]+)", read(path)):
            yield path, os.path.normpath(os.path.join(base, m.group(1))).replace(os.sep, "/")


class TestStructureMatchesDocs(unittest.TestCase):
    def test_readme_tree_exists(self):
        self.assertIsNotNone(readme_tree_paths(), "README 缺少「## 目录结构」代码块")

    def test_tree_paths_all_exist(self):
        files, dirs = scan_repo()
        missing = sorted(p for p in readme_tree_paths() if p not in files and p not in dirs)
        self.assertEqual(missing, [], f"README 目录树指向不存在的路径: {missing}")

    def test_no_top_level_omitted(self):
        files, dirs = scan_repo()
        tree = readme_tree_paths()
        top = {p.split("/")[0] for p in files} | {p.split("/")[0] for p in dirs}
        untold = sorted(t for t in top if t not in tree and t not in TREE_IGNORABLE)
        self.assertEqual(untold, [], f"顶层条目未写入 README 目录树: {untold}")

    def test_no_orphan_reference_docs(self):
        files, _ = scan_repo()
        refs = {f for f in files if "/references/" in f and f.endswith(".md")}
        referenced = {target for _, target in md_links()}
        orphans = sorted(refs - referenced)
        self.assertEqual(orphans, [], f"references 下存在未被任何文档引用的孤儿文件: {orphans}")


if __name__ == "__main__":
    unittest.main()
