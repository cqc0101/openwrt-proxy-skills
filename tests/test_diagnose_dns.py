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


    def test_ipv6_awk_precision(self):
        """awk 提取 IPv6 时必须要求至少包含两个冒号或双冒号前缀/后缀，杜绝单冒号十六进制单词误报。"""
        for sdir in (SINGBOX_SCRIPTS, DAE_SCRIPTS):
            sh_path = os.path.join(sdir, "diagnose_dns.sh")
            with open(sh_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("tok ~ /:.*:/ || tok ~ /^::/ || tok ~ /::$/", content,
                          f"{sh_path} 缺少精确 IPv6 多冒号提取逻辑")



    def test_bracketed_ipv6_and_canary_unspecified_support(self):
        """diagnose_dns.sh 必须支持剥离带端口或裸方括号的 IPv6 地址，并在 Canary 阻断审计中识别 :: 未指定地址。"""
        for sdir in (SINGBOX_SCRIPTS, DAE_SCRIPTS):
            sh_path = os.path.join(sdir, "diagnose_dns.sh")
            with open(sh_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(r'sub(/^\[/, "", tok)', content, f"{sh_path} 缺少方括号前缀剥离")
            self.assertIn(r'sub(/\](:[0-9]+)?$/, "", tok)', content, f"{sh_path} 缺少方括号与端口后缀剥离")
            self.assertIn('"$CANARY_IP" = "::"', content, f"{sh_path} 缺少对 IPv6 未指定阻断地址 :: 的识别")


    def test_step4_aaaa_awk_regex_precision(self):
        """第 4 关 AAAA 响应提取正则必须包含多冒号精确匹配，杜绝宽泛单冒号单词误伤。"""
        for sdir in (SINGBOX_SCRIPTS, DAE_SCRIPTS):
            sh_path = os.path.join(sdir, "diagnose_dns.sh")
            with open(sh_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertEqual(content.count("tok ~ /:.*:/ || tok ~ /^::/ || tok ~ /::$/"), 2,
                             f"{sh_path} 存在未加固的宽泛 IPv6 正则")

    def test_query_ips_nslookup_fallback_not_short_circuited_by_server_address(self):
        """query_ips 检查 127.0.0.1 响应是否有效时不得使用恒匹配首行 Server Address 的 'Address.*:'，必须检查 Name:/answer:/NXDOMAIN。"""
        for sdir in (SINGBOX_SCRIPTS, DAE_SCRIPTS):
            sh_path = os.path.join(sdir, "diagnose_dns.sh")
            with open(sh_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn('grep -qE "Address.*:"', content)
            self.assertIn("Name:|answer:|NXDOMAIN|can't find", content)

if __name__ == "__main__":
    unittest.main()
