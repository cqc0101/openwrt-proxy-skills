# -*- coding: utf-8 -*-
"""部署脚本静态守护：
1) 防止“远端检查写在本地”“SSH 选项漏配”这类回归；
2) 保证两个技能各自自包含时，双份共享脚本不会版本漂移。
"""

import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SINGBOX = os.path.join(REPO, "skills", "singbox-openwrt", "scripts")
DAE = os.path.join(REPO, "skills", "dae-openwrt", "scripts")

# 两个技能各存一份、内容必须一致的通用脚本（含自包含的 Python 解析副本）
SHARED_SCRIPTS = ["probe.sh", "probe.ps1", "doctor.sh", "optimize_network.sh",
                  "parse_node.py", "sub_parser.py"]


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestDeployShellScripts(unittest.TestCase):
    def test_firewall_script_has_strict_host_key(self):
        text = _read(os.path.join(SINGBOX, "setup_openwrt_firewall.sh"))
        ssh_lines = [l for l in text.splitlines() if "SSH_CMD=" in l and "ssh " in l]
        self.assertTrue(ssh_lines, "找不到 SSH_CMD 定义")
        for line in ssh_lines:
            self.assertIn("StrictHostKeyChecking=no", line,
                          "BatchMode=yes 下首次连接会被 host key 验证打断")

    def test_dae_sh_daed_check_runs_remotely(self):
        """command -v daed 只允许出现在远端 heredoc 里（本地电脑上没有 daed）。"""
        lines = _read(os.path.join(DAE, "deploy_dae.sh")).splitlines()

        remote_ranges = []
        i = 0
        while i < len(lines):
            if "<< 'EOF'" in lines[i]:
                start = i
                j = i + 1
                while j < len(lines) and lines[j].strip() != "EOF":
                    j += 1
                remote_ranges.append((start, j))
                i = j + 1
            else:
                i += 1

        daed_lines = [idx for idx, l in enumerate(lines) if "command -v daed" in l]
        self.assertTrue(daed_lines, "deploy_dae.sh 必须包含 daed 检测")
        for idx in daed_lines:
            self.assertTrue(
                any(s <= idx <= e for s, e in remote_ranges),
                f"第 {idx+1} 行的 daed 检测不在远端 heredoc 内，属于本地死判断:\n  {lines[idx].strip()}")

        self.assertIn("FAIL_ONLY_DAED", "\n".join(lines), "远端应输出 FAIL_ONLY_DAED 供本地捕获")

    def test_dae_ps1_distinguishes_daed(self):
        text = _read(os.path.join(DAE, "deploy_dae.ps1"))
        self.assertIn("command -v dae", text)
        self.assertIn("command -v daed", text)
        self.assertIn("支持边界", text)

    def test_deploy_scripts_no_echo_e(self):
        for path in (os.path.join(SINGBOX, "deploy_singbox.sh"),
                     os.path.join(DAE, "deploy_dae.sh")):
            with self.subTest(script=os.path.basename(path)):
                self.assertNotIn("echo -e", _read(path),
                                 "dash/busybox 下 echo -e 会打印字面 -e，请用 printf '%b\\n'")


class TestSharedScriptsConsistency(unittest.TestCase):
    """每个技能需自包含，因此共享脚本存两份；此测试防止两份内容漂移。

    唯一的允许差异是各文件顶部的「[共享脚本]」同步说明行（指向对方路径）。
    """

    def _normalized(self, path):
        return [l for l in _read(path).splitlines() if "[共享脚本]" not in l]

    def test_pairs_exist_and_match(self):
        for name in SHARED_SCRIPTS:
            a = os.path.join(SINGBOX, name)
            b = os.path.join(DAE, name)
            with self.subTest(script=name):
                self.assertTrue(os.path.exists(a), f"缺少 {a}")
                self.assertTrue(os.path.exists(b), f"缺少 {b}")
                la, lb = self._normalized(a), self._normalized(b)
                if la == lb:
                    continue
                for i, (x, y) in enumerate(zip(la, lb)):
                    if x != y:
                        self.fail(
                            f"{name} 两份内容不一致（第 {i+1} 行，已忽略同步说明行）：\n"
                            f"  singbox: {x}\n  dae    : {y}")
                self.fail(f"{name} 行数不一致：singbox {len(la)} 行 vs dae {len(lb)} 行")


if __name__ == "__main__":
    unittest.main()
