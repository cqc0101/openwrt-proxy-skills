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


class TestAuditHardeningCheckConfig(unittest.TestCase):
    def test_duplicate_outbound_tags_blocked(self):
        errs, _ = run({
            "outbounds": [
                {"type": "direct", "tag": "dup"},
                {"type": "block", "tag": "dup"},
            ]
        })
        self.assertTrue(any("重复标签" in e for e in errs))

    def test_dangling_route_final_blocked(self):
        errs, _ = run({
            "route": {"final": "non-existent-final"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("route.final" in e for e in errs))

    def test_dangling_selector_default_and_empty_outbounds_blocked(self):
        errs1, _ = run({
            "outbounds": [
                {"type": "selector", "tag": "proxy", "outbounds": ["direct"], "default": "missing"},
                {"type": "direct", "tag": "direct"},
            ]
        })
        self.assertTrue(any("default" in e for e in errs1))

        errs2, _ = run({
            "outbounds": [{"type": "urltest", "tag": "auto", "outbounds": []}]
        })
        self.assertTrue(any("空策略组" in e for e in errs2))

    def test_nested_logical_ruleset_dangling_blocked(self):
        errs, _ = run({
            "route": {
                "rules": [{
                    "type": "logical",
                    "mode": "and",
                    "rules": [{"rule_set": "ghost-rs"}],
                    "action": "route",
                    "outbound": "direct",
                }]
            },
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("ghost-rs" in e for e in errs))

    def test_domain_resolver_with_colon_port_or_url_blocked(self):
        for bad_srv in ("dns.alidns.com:53", "https://dns.alidns.com/dns-query"):
            errs, _ = run({
                "dns": {"servers": [{"tag": "r", "type": "udp", "server": bad_srv}]},
                "route": {"default_domain_resolver": "r"},
            })
            self.assertTrue(any("致命递归死锁" in e for e in errs), f"未拦截非 IP 引导地址: {bad_srv}")


    def test_unsupported_outbound_transport_and_invalid_port_blocked(self):
        errs1, _ = run({
            "outbounds": [{
                "type": "vless",
                "tag": "bad-trans",
                "server": "1.2.3.4",
                "server_port": 443,
                "uuid": "u",
                "transport": {"type": "xhttp"},
            }]
        })
        self.assertTrue(any("非法传输层" in e for e in errs1), errs1)

        errs2, _ = run({
            "outbounds": [{
                "type": "trojan",
                "tag": "bad-port",
                "server": "1.2.3.4",
                "server_port": 70000,
                "password": "p",
            }]
        })
        self.assertTrue(any("非法端口" in e for e in errs2), errs2)



    def test_self_referencing_dns_domain_resolver_and_incomplete_reality_blocked(self):
        errs1, _ = run({
            "dns": {"servers": [{"tag": "alidns", "type": "udp", "server": "223.5.5.5", "domain_resolver": "alidns"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("自环死锁" in e for e in errs1), errs1)

        errs2, _ = run({
            "outbounds": [{
                "type": "vless",
                "tag": "bad-reality",
                "server": "1.2.3.4",
                "server_port": 443,
                "uuid": "u",
                "tls": {"enabled": True, "server_name": "example.com", "reality": {"enabled": True, "public_key": ""}},
            }]
        })
        self.assertTrue(any("Reality 配置残缺" in e for e in errs2), errs2)

    def test_deprecated_shadowsocks_cipher_blocked(self):
        errs, _ = run({
            "outbounds": [{
                "type": "shadowsocks",
                "tag": "ss-old",
                "server": "1.2.3.4",
                "server_port": 8388,
                "method": "aes-256-cfb",
                "password": "pwd",
            }]
        })
        self.assertTrue(any("废弃加密" in e for e in errs), errs)



    def test_invalid_tun_address_cidr_and_urltest_default_blocked(self):
        errs1, _ = run({
            "inbounds": [{"type": "tun", "tag": "tun-in", "address": "172.19.0.1"}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("缺少 CIDR 掩码前缀" in e for e in errs1), errs1)

        errs2, _ = run({
            "outbounds": [
                {"type": "urltest", "tag": "auto", "outbounds": ["direct"], "default": "direct"},
                {"type": "direct", "tag": "direct"},
            ]
        })
        self.assertTrue(any("不支持 'default' 字段" in e for e in errs2), errs2)



    def test_incomplete_proxy_outbound_and_dangling_outbound_domain_resolver_blocked(self):
        errs1, _ = run({
            "outbounds": [
                {"type": "vless", "tag": "incomplete-vless"},
                {"type": "direct", "tag": "direct"},
            ]
        })
        self.assertTrue(any("缺少有效的 server" in e for e in errs1), errs1)
        self.assertTrue(any("缺少 server_port" in e for e in errs1), errs1)
        self.assertTrue(any("缺少有效的 uuid" in e for e in errs1), errs1)

        errs2, _ = run({
            "dns": {"servers": [{"tag": "alidns", "type": "udp", "server": ""}]},
            "outbounds": [{
                "type": "trojan", "tag": "t1", "server": "a.com", "server_port": 443,
                "password": "pw", "domain_resolver": "ghost-dns"
            }],
        })
        self.assertTrue(any("缺少有效的 server 地址" in e for e in errs2), errs2)
        self.assertTrue(any("ghost-dns" in e for e in errs2), errs2)



    def test_multi_hop_dns_and_outbound_detour_cycles_blocked(self):
        """验证 check_config.py 能够拦截多跳 DNS domain_resolver 循环 (A->B->A) 与 outbound detour 循环。"""
        with open(os.path.join(TEMPLATES, "openwrt-1.13-tun-fakeip.json"), "r", encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["dns"]["servers"].append({"tag": "dns-a", "type": "https", "server": "a.com", "domain_resolver": "dns-b"})
        cfg["dns"]["servers"].append({"tag": "dns-b", "type": "https", "server": "b.com", "domain_resolver": "dns-a"})
        cfg["outbounds"].append({"tag": "ob-a", "type": "vless", "server": "1.1.1.1", "server_port": 443, "uuid": "u1", "detour": "ob-b"})
        cfg["outbounds"].append({"tag": "ob-b", "type": "vless", "server": "2.2.2.2", "server_port": 443, "uuid": "u2", "detour": "ob-a"})
        for ob in cfg["outbounds"]:
            if ob.get("tag") == "proxy":
                ob["outbounds"] = ["auto"]
            elif ob.get("tag") == "auto":
                ob["outbounds"] = ["proxy"]
        errors, _ = check_config_obj(cfg)
        self.assertTrue(any("循环死锁" in e for e in errors), f"未拦截多跳 DNS domain_resolver 循环: {errors}")
        self.assertTrue(any("detour 存在多跳循环引用" in e for e in errors), f"未拦截多跳 outbound detour 循环: {errors}")
        self.assertTrue(any("策略组" in e and "循环引用" in e for e in errors), f"未拦截策略组 selector/urltest 互相引用环路: {errors}")


    def test_tuic_outbound_missing_password_blocked(self):
        """TUIC 出站缺少 password 必须被 check_config 静态拦截。"""
        errs, _ = run({
            "outbounds": [{
                "type": "tuic", "tag": "tuic-nopass", "server": "1.2.3.4", "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000", "password": "",
            }]
        })
        self.assertTrue(any("缺少有效的 password" in e for e in errs), errs)

    def test_domain_dns_server_without_any_resolver_blocked(self):
        """域名型 DNS Server (如 DoH/DoT) 既无自身 domain_resolver 也无 route.default_domain_resolver 时必须被拦截。"""
        errs, _ = run({
            "dns": {
                "servers": [
                    {"tag": "google-dot", "type": "tls", "server": "dns.google"}
                ]
            },
            "route": {"auto_detect_interface": True},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        })
        self.assertTrue(any("既未指定 domain_resolver" in e for e in errs), errs)

    def test_dict_form_route_default_domain_resolver_supported(self):
        """验证 route.default_domain_resolver 为字典格式 {"server": "..."} 时不会触发 TypeError: unhashable type: 'dict'。"""
        errs, _ = run({
            "route": {"default_domain_resolver": {"server": "ghost-dns"}, "auto_detect_interface": True},
            "dns": {"servers": [{"tag": "alidns", "type": "udp", "server": "223.5.5.5"}]},
            "inbounds": [],
            "outbounds": [{"tag": "direct", "type": "direct"}],
        })
        self.assertTrue(any("ghost-dns" in e for e in errs), errs)


    def test_domain_resolver_pointing_to_fakeip_blocked_and_outbound_domain_resolver_honored(self):
        """验证 default_domain_resolver / domain_resolver 指向 fakeip 服务器时被拦截，且 outbound 自身 domain_resolver 被 Bootstrap 检查识别。"""
        errs, _ = run({
            "route": {"default_domain_resolver": "fakeip-dns", "auto_detect_interface": True},
            "dns": {"servers": [
                {"tag": "alidns", "type": "udp", "server": "223.5.5.5"},
                {"tag": "fakeip-dns", "type": "fakeip", "inet4_range": "198.18.0.0/15"},
                {"tag": "remote-dns", "type": "https", "server": "dns.google", "domain_resolver": "fakeip-dns"},
            ]},
            "inbounds": [],
            "outbounds": [
                {"tag": "direct", "type": "direct"},
                {"tag": "n1", "type": "vless", "server": "node.example.com", "server_port": 443, "uuid": "u-1", "domain_resolver": "fakeip-dns"},
            ],
        })
        self.assertEqual(sum(1 for e in errs if "FakeIP" in e), 3, errs)

        # Outbound with valid domain_resolver should not trigger Bootstrap DNS warning even when route.default_domain_resolver is empty dict
        errs2, warns2 = run({
            "route": {"default_domain_resolver": {}, "auto_detect_interface": True, "rules": [{"action": "sniff"}, {"action": "hijack-dns"}]},
            "dns": {"servers": [{"tag": "alidns", "type": "udp", "server": "223.5.5.5"}]},
            "inbounds": [],
            "outbounds": [
                {"tag": "direct", "type": "direct"},
                {"tag": "n1", "type": "vless", "server": "node.example.com", "server_port": 443, "uuid": "u-1", "domain_resolver": "alidns"},
            ],
        })
        self.assertEqual(errs2, [])
        self.assertFalse(any("启动死锁隐患" in w for w in warns2), warns2)


    def test_heterogeneous_type_injection_fuzz_and_hy2_server_ports_validation(self):
        """R7-01: 验证异构 JSON 类型 (list/dict/int/bool) 注入任意引用字段时零崩溃 (不抛 TypeError)，且拦截非法 hysteria2 server_ports。"""
        fuzz_payloads = [
            {"route": {"default_domain_resolver": ["alidns"]}},
            {"route": {"default_domain_resolver": {"server": ["alidns"]}}},
            {"route": {"default_http_client": ["client"]}},
            {"route": {"final": ["proxy"]}},
            {"route": {"rules": [{"outbound": ["proxy"], "rule_set": [["rs1"], 123]}]}},
            {"route": {"rules": [{"outbound": {"bad": 1}, "rule_set": 999}]}},
            {"dns": {"final": {"tag": "dns"}, "rules": [{"server": ["alidns"], "rule_set": [{"a": 1}]}]}},
            {"dns": {"servers": [{"tag": ["t1"], "detour": ["direct"], "domain_resolver": ["alidns"]}]}},
            {"outbounds": [{"tag": ["ob1"], "type": "selector", "outbounds": [["a"]], "default": ["a"], "detour": ["b"], "domain_resolver": ["c"]}]},
            {"http_clients": [{"tag": ["hc"], "detour": ["direct"]}]},
            {"route": {"rule_set": [{"tag": ["rs"], "download_detour": ["direct"]}]}},
            {"outbounds": [{"tag": "hy2", "type": "hysteria2", "server": "1.1.1.1", "server_port": 443, "password": "p", "server_ports": ["50000:20000", 123]}]},
            {"inbounds": [{"type": "tun", "address": 12345}]},
        ]
        for idx, payload in enumerate(fuzz_payloads):
            errs, _ = run(payload)
            self.assertTrue(len(errs) > 0, f"Fuzz case {idx} 应产生阻断错误但返回空: {payload}")


    def test_dns_server_port_and_inbound_listen_port_range_validated(self):
        """验证 dns.servers[].server_port 与 inbounds[].listen_port 越界或布尔值被静态拦截。"""
        errs, _ = run({
            "route": {"default_domain_resolver": "alidns", "auto_detect_interface": True},
            "dns": {"servers": [{"tag": "alidns", "type": "udp", "server": "223.5.5.5", "server_port": 99999}]},
            "inbounds": [{"type": "mixed", "tag": "in-1", "listen_port": 0}],
            "outbounds": [{"tag": "direct", "type": "direct"}],
        })
        self.assertEqual(sum(1 for e in errs if "[非法端口]" in e), 2, errs)

if __name__ == "__main__":
    unittest.main()
