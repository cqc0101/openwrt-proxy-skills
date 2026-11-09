# -*- coding: utf-8 -*-
"""check_config 单元测试：审计器必须抓住常见事故。"""

import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "singbox-openwrt", "scripts"))

from check_config import check_config_obj, check_singbox_config  # noqa: E402

TEMPLATES = os.path.join(REPO, "skills", "singbox-openwrt", "assets", "templates")


def run(cfg):
    return check_config_obj(cfg)


class TestDanglingRefs(unittest.TestCase):
    def test_dangling_outbound(self):
        errs, _ = run({
            "route": {"rules": [{"action": "route", "outbound": "ghost"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("悬空" in e for e in errs))

    def test_dangling_ruleset(self):
        errs, _ = run({
            "route": {"rules": [{"rule_set": "ghost", "action": "route", "outbound": "direct"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("规则集" in e for e in errs))

    def test_dangling_dns_server(self):
        errs, _ = run({
            "dns": {"rules": [{"action": "route", "server": "ghost"}], "servers": [
                {"tag": "alidns", "type": "udp", "server": "223.5.5.5"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("DNS server" in e for e in errs))

    def test_dangling_dns_detour(self):
        errs, _ = run({
            "dns": {"servers": [{"tag": "g", "type": "https", "server": "8.8.8.8", "detour": "ghost"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("dns.servers[0]" in e and "detour" in e for e in errs))

    def test_dangling_outbound_detour(self):
        errs, _ = run({
            "outbounds": [{"type": "shadowsocks", "tag": "s", "server": "1.1.1.1", "server_port": 8388,
                           "method": "aes-128-gcm", "password": "p", "detour": "ghost"}],
        })
        self.assertTrue(any("outbound[0]" in e and "detour" in e for e in errs))


class TestFieldGates(unittest.TestCase):
    def test_network_ws_blocked(self):
        errs, _ = run({
            "outbounds": [{"type": "vless", "tag": "n", "server": "1.2.3.4",
                           "server_port": 443, "uuid": "u", "network": "ws"}],
        })
        self.assertTrue(any("network" in e for e in errs))

    def test_network_tcp_ok(self):
        errs, _ = run({
            "outbounds": [{"type": "vless", "tag": "n", "server": "1.2.3.4",
                           "server_port": 443, "uuid": "u", "network": "tcp"}],
        })
        self.assertFalse(any("network" in e for e in errs))

    def test_version_mix_warning(self):
        _, warns = run({
            "dns": {"independent_cache": True, "optimistic": True},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("版本混用" in w for w in warns))

    def test_deprecated_tun_stack_warn(self):
        _, warns = run({
            "inbounds": [{"type": "tun", "tag": "t", "address": "172.19.0.1/30", "stack": "mixed"}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("stack" in w for w in warns))

    def test_http_client_detour_direct_blocked(self):
        errs, _ = run({
            "http_clients": [{"tag": "c", "detour": "direct"}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("empty direct" in e for e in errs))

    def test_download_detour_direct_blocked(self):
        errs, _ = run({
            "route": {"rule_set": [{"tag": "r", "download_detour": "direct"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("empty direct" in e for e in errs))

    def test_auto_detect_default_interface_conflict_warned(self):
        _, warns = run({
            "route": {"auto_detect_interface": True, "default_interface": "eth0"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("配置冲突" in w for w in warns))

    def test_cache_path_warning(self):
        _, warns = run({
            "experimental": {"cache_file": {"enabled": True, "path": "/etc/foo.db"}},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("闪存" in w for w in warns))


class TestTemplatesPass(unittest.TestCase):
    def test_all_templates_have_zero_errors(self):
        for v in ("1.13", "1.14"):
            for m in ("fakeip", "realip"):
                with self.subTest(version=v, mode=m):
                    errs, _ = check_singbox_config(
                        os.path.join(TEMPLATES, f"openwrt-{v}-tun-{m}.json"))
                    self.assertEqual(errs, [], f"{v}/{m} 不应有阻断错误: {errs}")


class TestFuzzAndEdgeCases(unittest.TestCase):
    def test_malformed_and_none_blocks_do_not_crash(self):
        cases = [
            {},
            None,
            "not_a_dict",
            {"dns": None},
            {"route": None},
            {"outbounds": None},
            {"inbounds": None},
            {"dns": {"servers": [None, "invalid_item"]}},
            {"outbounds": [None, {"tag": "t", "type": "selector", "outbounds": None}]},
            {"route": {"rules": [None, {"outbound": None, "rule_set": None}]}},
            {"http_clients": [None, {"tag": "hc", "detour": "direct"}]},
            {"route": {"rule_set": [None, {"tag": "rs", "download_detour": "direct"}]}},
        ]
        for c in cases:
            with self.subTest(case=repr(c)[:30]):
                errs, warns = check_config_obj(c)
                self.assertIsInstance(errs, list)
                self.assertIsInstance(warns, list)

    def test_domain_resolver_with_domain_server_blocked(self):
        cfg = {
            "dns": {"servers": [{"tag": "my-resolver", "type": "udp", "server": "dns.alidns.com"}]},
            "route": {"default_domain_resolver": "my-resolver"}
        }
        errs, _ = check_config_obj(cfg)
        self.assertTrue(any("致命递归死锁" in e for e in errs), "引导 DNS 自身地址为域名必须被阻断")


if __name__ == "__main__":
    unittest.main()
