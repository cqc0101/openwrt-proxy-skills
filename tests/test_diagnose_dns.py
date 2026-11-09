# -*- coding: utf-8 -*-
"""DNS 深度诊断脚本与防污染体检单元测试。"""

import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SINGBOX_SCRIPTS = os.path.join(REPO, "skills", "singbox-openwrt", "scripts")
DAE_SCRIPTS = os.path.join(REPO, "skills", "dae-openwrt", "scripts")


class TestDnsDoctorScripts(unittest.TestCase):
    def test_scripts_exist_in_both_skills(self):
        for sdir, skill in [(SINGBOX_SCRIPTS, "singbox"), (DAE_SCRIPTS, "dae")]:
            sh_path = os.path.join(sdir, "diagnose_dns.sh")
            self.assertTrue(os.path.exists(sh_path), f"{skill} 缺少 diagnose_dns.sh")

    def test_posix_compliance_no_echo_e(self):
        for sdir in (SINGBOX_SCRIPTS, DAE_SCRIPTS):
            sh_path = os.path.join(sdir, "diagnose_dns.sh")
            with open(sh_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("echo -e", content, "dash/busybox 下 echo -e 会导致语法错误，必须使用 printf '%b\\n'")

    def test_diagnostic_steps_present(self):
        sh_path = os.path.join(SINGBOX_SCRIPTS, "diagnose_dns.sh")
        with open(sh_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("53 端口监听", content)
        self.assertIn("国内高频域名解析", content)
        self.assertIn("海外被墙域名防投毒", content)
        self.assertIn("IPv6 AAAA 污染黑洞", content)
        self.assertIn("局域网域名与内网主机名", content)

    def test_json_flag_support(self):
        sh_path = os.path.join(SINGBOX_SCRIPTS, "diagnose_dns.sh")
        with open(sh_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("-j", content)
        self.assertIn("--json", content)
        self.assertIn("OUTPUT_JSON", content)

    def test_known_poison_ip_database_present(self):
        sh_path = os.path.join(SINGBOX_SCRIPTS, "diagnose_dns.sh")
        with open(sh_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("KNOWN_POISON=", content, "必须内建典型 GFW 投毒 IP 特征库")
        self.assertIn("203.98.7.65", content)



    def test_dns_queries_have_strict_timeouts(self):
        sh_path = os.path.join(SINGBOX_SCRIPTS, "diagnose_dns.sh")
        with open(sh_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("+time=2 +tries=1", content, "dig 必须带超时参数防止死上游阻塞 120 秒")
        self.assertIn("timeout 3 nslookup", content, "nslookup 必须支持 timeout 包装防挂起")



    def test_ipv6_colon_not_stripped_by_awk(self):
        sh_path = os.path.join(SINGBOX_SCRIPTS, "diagnose_dns.sh")
        with open(sh_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn('sub(/[#:].*/, "", tok)', content, "严禁使用 [#:] 剥离冒号导致 IPv6 地址被截断")


if __name__ == "__main__":
    unittest.main()
