# -*- coding: utf-8 -*-
"""网络闭环与部署脚本静态守护：
1) 守护 setup_openwrt_network.sh 的安全规范（zone 动态解析、accept-new、MSS 钳制、filter_aaaa）；
2) 保证两个技能各自自包含时，双份共享脚本不会版本漂移。
"""

import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SINGBOX = os.path.join(REPO, "skills", "singbox-openwrt", "scripts")
DAE = os.path.join(REPO, "skills", "dae-openwrt", "scripts")

# 两个技能各存一份、内容必须一致的通用脚本（含自包含的 Python 解析副本）
SHARED_SCRIPTS = [
    "probe.sh",
    "doctor.sh",
    "parse_node.py",
    "sub_parser.py",
    "diagnose_dns.sh",
]


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestNetworkSetupScripts(unittest.TestCase):
    def test_network_scripts_cli_flags_not_misassigned(self):
        """防止 --bypass/--revert 错位赋值给 SSH_USER。"""
        for base in (SINGBOX, DAE):
            text = _read(os.path.join(base, "setup_openwrt_network.sh"))
            self.assertIn("while [ $# -gt 0 ]; do", text, "必须使用参数循环解析避免位置参数错位")
            self.assertIn("--revert)", text)
            self.assertNotIn('SSH_USER="${2:-root}"', text, "严禁将 $2 直接硬编码作为 SSH_USER")

    def test_singbox_network_script_security_and_features(self):
        text = _read(os.path.join(SINGBOX, "setup_openwrt_network.sh"))
        self.assertIn("StrictHostKeyChecking=accept-new", text, "SSH 模式必须使用 accept-new 首次自动接受且防篡改")
        self.assertIn("mtu_fix='1'", text, "必须开启 MSS 钳制")
        self.assertIn("filter_aaaa='1'", text, "必须开启 Dnsmasq filter_aaaa 过滤")
        self.assertIn("tun0", text, "必须包含 tun0 接口配置")
        self.assertNotIn("echo -e", text, "POSIX /bin/sh 严禁使用 echo -e")
        # 必须动态定位 lan zone，严禁写死 @zone[0]
        self.assertIn("uci get \"firewall.@zone[", text)
        self.assertIn("zone_name", text)

    def test_dae_network_script_security_and_features(self):
        text = _read(os.path.join(DAE, "setup_openwrt_network.sh"))
        self.assertIn("StrictHostKeyChecking=accept-new", text, "SSH 模式必须使用 accept-new")
        self.assertIn("flow_offloading='0'", text, "dae 必须关闭流量分载 Flow Offloading")
        self.assertIn("filter_aaaa='1'", text, "必须开启 Dnsmasq filter_aaaa 过滤")
        self.assertNotIn("echo -e", text, "POSIX /bin/sh 严禁使用 echo -e")

    def test_probe_reports_hardening_facts(self):
        """真机验证沉淀：probe 必须报告 nfqueue 缺失与 sing-box-tiny 安装建议。"""
        text = _read(os.path.join(SINGBOX, "probe.sh"))
        self.assertIn("nfqueue", text)
        self.assertIn("sing-box-tiny", text)
        self.assertIn("OUTPUT_JSON", text)

    def test_doctor_script_features(self):
        """doctor 脚本必须支持 JSON 模式与核心报错特征扫描。"""
        text = _read(os.path.join(SINGBOX, "doctor.sh"))
        self.assertIn("OUTPUT_JSON", text)
        self.assertIn("certificate", text)
        self.assertIn("out of memory", text)
        self.assertIn("bind: address already in use", text)

    def test_doctor_ruleset_regex_does_not_catch_bare_context_deadline(self):
        """防止普通的 Go 链接超时 (context deadline exceeded) 误报为规则集阻断。"""
        for base in (SINGBOX, DAE):
            text = _read(os.path.join(base, "doctor.sh"))
            self.assertNotIn("|context deadline exceeded\"", text, "严禁将裸 context deadline 作为独立分支误判规则集阻断")


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
