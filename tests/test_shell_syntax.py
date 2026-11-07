# -*- coding: utf-8 -*-
"""POSIX shell 语法检查（bash -n）。无可用 bash 时跳过（Windows 本地）。

同时校验：所有 .sh 必须使用 LF 行尾且无 BOM（CRLF 会毁掉传给路由器的脚本）。
"""

import os
import shutil
import subprocess
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _real_bash():
    candidates = []
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    # 常见 Git for Windows 安装路径（不在 PATH 上也能找到）
    for base in (r"C:\Program Files\Git\bin\bash.exe",
                 r"C:\Program Files\Git\usr\bin\bash.exe",
                 r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if os.path.exists(base):
            candidates.append(base)
    # scoop 安装的 git
    import glob
    for pattern in (r"C:\Software\scoop\apps\git\*\bin\bash.exe",
                    r"C:\Users\*\scoop\apps\git\*\bin\bash.exe"):
        candidates.extend(glob.glob(pattern))
    for bash in candidates:
        try:
            out = subprocess.run([bash, "--version"], capture_output=True, text=True, timeout=10).stdout
        except Exception:
            continue
        if "GNU bash" in out:
            return bash
    return None  # WindowsApps 的 WSL 存根之类


BASH = _real_bash()


def all_sh_files():
    for root, _dirs, files in os.walk(REPO):
        for name in files:
            if name.endswith(".sh"):
                yield os.path.join(root, name)


@unittest.skipIf(BASH is None, "未找到可用的 GNU bash")
class TestShellSyntax(unittest.TestCase):
    def test_bash_n_all_scripts(self):
        for path in all_sh_files():
            with self.subTest(script=os.path.relpath(path, REPO)):
                r = subprocess.run([BASH, "-n", path], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, f"bash -n 失败:\n{r.stderr}")


class TestLineEndings(unittest.TestCase):
    def test_no_crlf_no_bom(self):
        for root, _dirs, files in os.walk(REPO):
            if ".git" in root:
                continue
            for name in files:
                path = os.path.join(root, name)
                if not any(name.endswith(ext) for ext in (".sh", ".py", ".dae", ".json", ".md", ".ps1", ".yml", ".yaml")):
                    continue
                with self.subTest(file=os.path.relpath(path, REPO)):
                    with open(path, "rb") as f:
                        raw = f.read()
                    self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "发现 BOM")
                    self.assertNotIn(b"\r\n", raw, "发现 CRLF 行尾")


if __name__ == "__main__":
    unittest.main()
