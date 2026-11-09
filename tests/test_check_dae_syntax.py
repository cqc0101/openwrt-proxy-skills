# -*- coding: utf-8 -*-
"""check_dae_syntax 单元测试：铁律检测必须既不漏报也不误报。"""

import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "dae-openwrt", "scripts"))

from check_dae_syntax import check_dae_syntax  # noqa: E402

GOOD = """global {
    lan_interface: br-lan
    wan_interface: auto
}
routing {
    pname(dnsmasq, odhcpd) && l4proto(udp) && dport(53) -> must_direct
    domain(geosite:cn) -> direct
    fallback: proxy
}
"""


def check(text):
    with tempfile.NamedTemporaryFile("w", suffix=".dae", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        return check_dae_syntax(path)
    finally:
        os.unlink(path)


class TestDaeChecker(unittest.TestCase):
    def test_template_passes(self):
        errors, warnings = check_dae_syntax(
            os.path.join(REPO, "skills", "dae-openwrt", "assets", "templates", "openwrt.dae"))
        self.assertEqual(errors, [], f"模板自身不应报错: {errors}")

    def test_openwrt_dae_has_canary_blocking(self):
        with open(os.path.join(REPO, "skills", "dae-openwrt", "assets", "templates", "openwrt.dae"), encoding="utf-8") as f:
            content = f.read()
        self.assertIn("use-application-dns.net", content)
        self.assertIn("mask.icloud.com", content)

    def test_missing_dnsmasq_protection_is_blocking(self):
        errors, _ = check("""
global { lan_interface: br-lan
    wan_interface: auto }
routing {
    pname(aria2c) -> must_direct
    fallback: proxy
}
""")
        self.assertTrue(any("dnsmasq" in e for e in errors))

    def test_dnsmasq_with_conditions_detected(self):
        errors, _ = check(GOOD)
        self.assertFalse(any("dnsmasq" in e for e in errors))

    def test_double_quote_flagged(self):
        errors, _ = check("""
global { lan_interface: br-lan
    wan_interface: auto }
routing {
    pname(dnsmasq) -> must_direct
    tcp_check_url: "http://cp.cloudflare.com"
}
""")
        self.assertTrue(any("单引号" in e for e in errors))

    def test_ext_quoted_allowed(self):
        errors, _ = check("""
global { lan_interface: br-lan
    wan_interface: auto }
routing {
    pname(dnsmasq) -> must_direct
    domain(ext:"geoip.dat:cn") -> direct
}
""")
        self.assertFalse(any("单引号" in e for e in errors))

    def test_response_loop_without_whitelist_blocked(self):
        errors, _ = check("""
global { lan_interface: br-lan
    wan_interface: auto }
routing { pname(dnsmasq) -> must_direct
    fallback: proxy }
dns {
    upstream { googledns: 'tcp+udp://dns.google:53' }
    routing {
        response {
            ip(geoip:private) && !qname(geosite:cn) -> googledns
            fallback: accept
        }
    }
}
""")
        self.assertTrue(any("白名单" in e or "死循环" in e for e in errors))

    def test_response_loop_with_whitelist_passes(self):
        errors, _ = check("""
global { lan_interface: br-lan
    wan_interface: auto }
routing { pname(dnsmasq) -> must_direct
    fallback: proxy }
dns {
    upstream { googledns: 'tcp+udp://dns.google:53' }
    routing {
        response {
            upstream(googledns) -> accept
            ip(geoip:private) && !qname(geosite:cn) -> googledns
            fallback: accept
        }
    }
}
""")
        self.assertEqual(errors, [], f"不应报错: {errors}")

    def test_multiple_negated_rules_warn(self):
        _, warnings = check("""
global { lan_interface: br-lan
    wan_interface: auto }
routing {
    pname(dnsmasq) -> must_direct
    !domain(geosite:a) -> proxy
    !domain(geosite:b) -> proxy
}
""")
        self.assertTrue(any("取反" in w for w in warnings))

    def test_missing_interfaces_warn(self):
        _, warnings = check("""
routing { pname(dnsmasq) -> must_direct }
""")
        self.assertTrue(any("lan_interface" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
