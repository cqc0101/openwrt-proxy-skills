# -*- coding: utf-8 -*-
"""模板不变量测试：任何模板改动破坏这些断言都会立刻被抓到。"""

import json
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(REPO, "skills", "singbox-openwrt", "assets", "templates")

VERSIONS = ("1.13", "1.14")
MODES = ("fakeip", "realip")


def load(version, mode):
    path = os.path.join(TEMPLATES, f"openwrt-{version}-tun-{mode}.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestAllTemplates(unittest.TestCase):
    def test_four_templates_exist_and_parse(self):
        for v in VERSIONS:
            for m in MODES:
                self.assertIsInstance(load(v, m), dict, f"{v}/{m} 无法解析为 JSON 对象")

    def test_openwrt_hardening_fields(self):
        for v in VERSIONS:
            for m in MODES:
                cfg = load(v, m)
                with self.subTest(version=v, mode=m):
                    # 闪存保护：cache_file.path 必须指向 /tmp
                    self.assertEqual(cfg["experimental"]["cache_file"]["path"],
                                     "/tmp/sing-box-cache.db")
                    # 防环 + 防死锁
                    self.assertIs(cfg["route"]["auto_detect_interface"], True)
                    self.assertEqual(cfg["route"]["default_domain_resolver"], "alidns")
                    # Clash API 局域网控制
                    self.assertEqual(cfg["experimental"]["clash_api"]["external_controller"],
                                     "0.0.0.0:9090")

    def test_tun_ipv4_only_and_no_deprecated_stack(self):
        for v in VERSIONS:
            for m in MODES:
                cfg = load(v, m)
                with self.subTest(version=v, mode=m):
                    tun = [i for i in cfg["inbounds"] if i.get("type") == "tun"][0]
                    self.assertEqual(tun["address"], "172.19.0.1/30")
                    # IPv4 纯净原则：不给 TUN 配 IPv6
                    self.assertNotIn("inet6_address", tun)
                    # 1.15 起废弃，模板必须不携带
                    self.assertNotIn("stack", tun)

    def test_dns_ipv4_only(self):
        for v in VERSIONS:
            for m in MODES:
                self.assertEqual(load(v, m)["dns"]["strategy"], "ipv4_only")

    def test_route_rule_order_sniff_then_hijack(self):
        for v in VERSIONS:
            for m in MODES:
                rules = load(v, m)["route"]["rules"]
                with self.subTest(version=v, mode=m):
                    self.assertEqual(rules[0]["action"], "sniff")
                    self.assertEqual(rules[1]["action"], "hijack-dns")
                    sub = rules[1].get("rules", [])
                    self.assertTrue(any(r.get("protocol") == "dns" for r in sub))
                    self.assertTrue(any(r.get("port") == 53 for r in sub))


class TestVersionGating(unittest.TestCase):
    def test_113_fields(self):
        for m in MODES:
            cfg = load("1.13", m)
            with self.subTest(mode=m):
                self.assertIn("independent_cache", cfg["dns"])
                self.assertNotIn("optimistic", cfg["dns"])
                self.assertIn("store_rdrc", cfg["experimental"]["cache_file"])
                self.assertNotIn("store_dns", cfg["experimental"]["cache_file"])
                for rs in cfg["route"]["rule_set"]:
                    self.assertNotIn("download_detour", rs,
                                     "直连下载无需 download_detour；显式 direct 会在启动期触发 empty direct outbound 崩溃")
                self.assertNotIn("http_clients", cfg)
                self.assertNotIn("default_http_client", cfg["route"])

    def test_114_fields(self):
        for m in MODES:
            cfg = load("1.14", m)
            with self.subTest(mode=m):
                self.assertIn("optimistic", cfg["dns"])
                self.assertNotIn("independent_cache", cfg["dns"])
                self.assertIn("store_dns", cfg["experimental"]["cache_file"])
                self.assertNotIn("store_rdrc", cfg["experimental"]["cache_file"])
                for rs in cfg["route"]["rule_set"]:
                    self.assertNotIn("download_detour", rs)
                self.assertIn("http_clients", cfg)
                self.assertEqual(cfg["route"]["default_http_client"], "direct-client")
                # 规则集必须经由显式 http_client 下载；但 detour 不得指向 direct（启动期崩溃）
                tags = {c["tag"] for c in cfg["http_clients"]}
                self.assertIn("direct-client", tags)
                for client in cfg["http_clients"]:
                    self.assertNotIn("detour", client,
                                     "http_client 的 detour 指向 direct 会在启动期触发 empty direct outbound 崩溃")


class TestFakeIPVsRealIP(unittest.TestCase):
    def test_fakeip_structure(self):
        for v in VERSIONS:
            cfg = load(v, "fakeip")
            with self.subTest(version=v):
                tags = [s.get("tag") for s in cfg["dns"]["servers"]]
                self.assertIn("fakeip-dns", tags)
                self.assertIs(cfg["experimental"]["cache_file"]["store_fakeip"], True)
                self.assertNotIn("reverse_mapping", cfg["dns"])
                # A/AAAA 必须路由到 fakeip-dns
                self.assertTrue(any(
                    r.get("server") == "fakeip-dns" and "A" in r.get("query_type", [])
                    for r in cfg["dns"]["rules"]))

    def test_realip_structure(self):
        for v in VERSIONS:
            cfg = load(v, "realip")
            with self.subTest(version=v):
                tags = [s.get("tag") for s in cfg["dns"]["servers"]]
                self.assertNotIn("fakeip-dns", tags)
                self.assertIs(cfg["dns"]["reverse_mapping"], True)
                self.assertNotIn("store_fakeip", cfg["experimental"]["cache_file"])
                self.assertFalse(any(
                    r.get("server") == "fakeip-dns" for r in cfg["dns"]["rules"]))


class TestNoDanglingReferences(unittest.TestCase):
    def test_all_references_resolve(self):
        for v in VERSIONS:
            for m in MODES:
                cfg = load(v, m)
                with self.subTest(version=v, mode=m):
                    out_tags = {o.get("tag") for o in cfg["outbounds"]}
                    rs_tags = {r.get("tag") for r in cfg["route"]["rule_set"]}
                    dns_tags = {s.get("tag") for s in cfg["dns"]["servers"]}

                    for idx, r in enumerate(cfg["route"]["rules"]):
                        if r.get("outbound"):
                            self.assertIn(r["outbound"], out_tags, f"route.rules[{idx}] 悬空")
                        for rs in (r.get("rule_set") or [] if isinstance(r.get("rule_set"), list) else [r.get("rule_set")]):
                            if rs:
                                self.assertIn(rs, rs_tags, f"route.rules[{idx}] 规则集悬空: {rs}")
                    for o in cfg["outbounds"]:
                        if o.get("type") in ("selector", "urltest"):
                            for so in o["outbounds"]:
                                self.assertIn(so, out_tags, f"{o.get('tag')} 引用悬空: {so}")
                    for dr in cfg["dns"]["rules"]:
                        if dr.get("server"):
                            self.assertIn(dr["server"], dns_tags, f"dns server 悬空: {dr['server']}")
                    self.assertIn(cfg["dns"]["final"], dns_tags)
                    self.assertIn(cfg["route"]["default_domain_resolver"], dns_tags)
                    self.assertIn(cfg["route"]["final"], out_tags)


if __name__ == "__main__":
    unittest.main()
