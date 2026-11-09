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


class TestNoBashisms(unittest.TestCase):
    """纯 POSIX /bin/sh 规范守护：杜绝任何非标准 bashism 语法。"""
    PATTERNS = {
        "double_bracket": (r"(?<!\w)\[\[\s", "严禁使用 [[，必须使用 POSIX ["),
        "echo_flags": (r"(?<!\w)echo\s+-[enE]+\s", "严禁使用 echo -n 或 -e，必须使用 printf"),
        "function_kw": (r"^\s*function\s+\w+", "严禁使用 function 关键字，必须使用 name()"),
        "source_cmd": (r"^\s*source\s+", "严禁使用 source，必须使用 . "),
        "amp_redirect": (r"&>", "严禁使用 &>，必须使用 >... 2>&1"),
        "herestring": (r"<<<", "严禁使用 <<< herestring"),
        "bash_substr": (r"\$\{\w+:[0-9]+(:[0-9]+)?\}", "严禁使用 ${var:0:1} 切片"),
    }

    def test_skills_scripts_have_zero_bashisms(self):
        import re
        skills_dir = os.path.join(REPO, "skills")
        for root, _, files in os.walk(skills_dir):
            for name in files:
                if name.endswith(".sh"):
                    path = os.path.join(root, name)
                    rel = os.path.relpath(path, REPO)
                    with open(path, "r", encoding="utf-8") as f:
                        text = f.read()
                    for bname, (pat, msg) in self.PATTERNS.items():
                        m = re.search(pat, text, flags=re.MULTILINE)
                        self.assertIsNone(m, f"{rel} 发现 bashism '{bname}' ({m.group(0) if m else ''}): {msg}")


class TestLineEndings(unittest.TestCase):
    def test_no_crlf_no_bom(self):
        for root, _dirs, files in os.walk(REPO):
            # 跳过隐藏目录（.git、.tmp 等临时/元数据目录）
            rel_root = os.path.relpath(root, REPO)
            if any(part.startswith(".") for part in rel_root.split(os.sep)):
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
