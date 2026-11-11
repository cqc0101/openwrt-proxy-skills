# -*- coding: utf-8 -*-
"""模块化积木 (assets/mixins/) 格式与安全约束守护。"""

import json
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIXINS_DIR = os.path.join(REPO, "skills", "singbox-openwrt", "assets", "mixins")


class TestModularMixins(unittest.TestCase):
    def test_all_mixins_exist_and_valid_json(self):
        expected_files = [
            "inbound_tun.json",
            "experimental.json",
            "dns_base.json",
            "route_base.json",
            "outbounds_base.json",
        ]
        for name in expected_files:
            path = os.path.join(MIXINS_DIR, name)
            self.assertTrue(os.path.exists(path), f"缺少 mixin 文件: {name}")
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIsInstance(data, (dict, list), f"{name} 不是合法的 JSON 对象或数组")

    def test_inbound_tun_mixin_contract(self):
        path = os.path.join(MIXINS_DIR, "inbound_tun.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        inbounds = data.get("inbounds", [])
        self.assertTrue(len(inbounds) > 0, "inbound_tun.json 必须包含至少一个 inbound")
        tun = inbounds[0]
        self.assertEqual(tun.get("type"), "tun")
        self.assertEqual(tun.get("interface_name"), "tun0")
        self.assertTrue(tun.get("auto_route"))

    def test_experimental_mixin_flash_protection(self):
        path = os.path.join(MIXINS_DIR, "experimental.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        exp = data.get("experimental", {})
        cache_file = exp.get("cache_file", {})
        self.assertTrue(cache_file.get("enabled"))
        self.assertEqual(cache_file.get("path"), "/tmp/sing-box-cache.db", "闪存保护：cache_file 必须挂在 /tmp 内存盘")
        clash_api = exp.get("clash_api", {})
        self.assertEqual(clash_api.get("external_controller"), "0.0.0.0:9090")

    def test_dns_base_mixin_canary_and_loop_prevention(self):
        path = os.path.join(MIXINS_DIR, "dns_base.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        dns = data.get("dns", data)
        self.assertEqual(dns.get("strategy"), "ipv4_only")
        rules = dns.get("rules", [])
        rules_str = json.dumps(rules)
        self.assertIn("use-application-dns.net", rules_str, "DNS 规则必须阻断 Firefox DoH Canary 域名")
        self.assertIn("mask.icloud.com", rules_str, "DNS 规则必须阻断 Apple Private Relay")
        self.assertIn("reject", rules_str)

    def test_route_base_mixin_anti_loop(self):
        path = os.path.join(MIXINS_DIR, "route_base.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        route = data.get("route", data)
        self.assertTrue(route.get("auto_detect_interface"))
        self.assertEqual(route.get("default_domain_resolver"), "alidns")
        rules = route.get("rules", [])
        rules_str = json.dumps(rules)
        self.assertIn("hijack-dns", rules_str, "路由规则必须显式劫持 DNS")
        self.assertIn("sniff", rules_str, "路由首部必须嗅探流量")
        self.assertNotIn("privatedomain.lan", rules_str, "严禁残留个人设备特定域名")

    def test_dns_base_has_no_nonstandard_preferred_by(self):
        path = os.path.join(MIXINS_DIR, "dns_base.json")
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("preferred_by", raw, "dns.rules 严禁包含非标字段 preferred_by")
        self.assertNotIn("privatedomain.lan", raw, "dns.rules 严禁残留个人设备特定域名")



    def test_compose_from_mixins_matches_all_templates(self):
        """确保 auto_config.compose_from_mixins() 动态合成结果与 assets/templates/ 下的 4 个基准模板 100% 一致，彻底消除双数据源漂移。"""
        import sys
        scripts_dir = os.path.join(REPO, "skills", "singbox-openwrt", "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from auto_config import compose_from_mixins
        templates_dir = os.path.join(REPO, "skills", "singbox-openwrt", "assets", "templates")
        for ver in ("1.13", "1.14"):
            for mode in ("fakeip", "realip"):
                with self.subTest(version=ver, mode=mode):
                    composed = compose_from_mixins(version=ver, dns_mode=mode)
                    tpl_path = os.path.join(templates_dir, f"openwrt-{ver}-tun-{mode}.json")
                    with open(tpl_path, "r", encoding="utf-8") as tf:
                        tpl_data = json.load(tf)
                    self.assertEqual(composed, tpl_data)


if __name__ == "__main__":
    unittest.main()
