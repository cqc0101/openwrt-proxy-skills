# -*- coding: utf-8 -*-
"""auto_config 单元与端到端测试：版本比较、模板选择、节点注入、生成后自校验。"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "skills", "singbox-openwrt", "scripts")
sys.path.insert(0, SCRIPTS)

import auto_config  # noqa: E402
from auto_config import version_ge, build_config, apply_cdn_mirror  # noqa: E402


class TestVersionGe(unittest.TestCase):
    def test_edges(self):
        self.assertTrue(version_ge("1.14", 1, 14))
        self.assertTrue(version_ge("1.20", 1, 14))   # 1.20 不能误判为 < 1.14
        self.assertTrue(version_ge("2.0", 1, 14))
        self.assertFalse(version_ge("1.13", 1, 14))
        self.assertFalse(version_ge("1.2", 1, 14))
        self.assertFalse(version_ge("bogus", 1, 14))


class TestTemplateSelection(unittest.TestCase):
    def test_missing_template_hard_fails(self):
        with self.assertRaises(SystemExit) as ctx:
            build_config(version="1.15", dns_mode="realip")
        self.assertEqual(ctx.exception.code, 2)

    def test_realip_is_really_realip(self):
        cfg = build_config(version="1.13", dns_mode="realip", mirror="direct")
        tags = [s.get("tag") for s in cfg["dns"]["servers"]]
        self.assertNotIn("fakeip-dns", tags)
        self.assertIs(cfg["dns"]["reverse_mapping"], True)

    def test_fakeip_is_really_fakeip(self):
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct")
        tags = [s.get("tag") for s in cfg["dns"]["servers"]]
        self.assertIn("fakeip-dns", tags)
        tun = [i for i in cfg["inbounds"] if i.get("type") == "tun"][0]
        self.assertFalse(tun.get("auto_redirect", False))


class TestNodeInjection(unittest.TestCase):
    def test_placeholder_removed_and_selectors_rewired(self):
        cfg = build_config(
            version="1.13", dns_mode="fakeip", mirror="direct",
            node_uris=["trojan://pw@5.6.7.8:443?sni=b.com#JP-01",
                       "trojan://pw@1.2.3.4:443?sni=c.com#US-02"],
        )
        tags = [o.get("tag") for o in cfg["outbounds"]]
        self.assertNotIn("US-Node", tags)          # 假占位节点必须被清除
        self.assertIn("JP-01", tags)
        self.assertIn("US-02", tags)
        proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
        auto = next(o for o in cfg["outbounds"] if o["tag"] == "auto")
        self.assertIn("JP-01", proxy["outbounds"])
        self.assertIn("US-02", proxy["outbounds"])
        self.assertEqual(sorted(auto["outbounds"]), sorted(["JP-01", "US-02"]))

    def test_duplicate_tags_renamed(self):
        cfg = build_config(
            version="1.13", dns_mode="fakeip", mirror="direct",
            node_uris=["trojan://pw@5.6.7.8:443?sni=b.com#DUP",
                       "trojan://pw@1.2.3.4:443?sni=c.com#DUP"],
        )
        tags = [o.get("tag") for o in cfg["outbounds"]]
        self.assertIn("DUP", tags)
        self.assertIn("DUP-1", tags)


    def test_wan_iface_replaces_auto_detect(self):
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct", wan_iface="pppoe-wan")
        self.assertNotIn("auto_detect_interface", cfg["route"])
        self.assertEqual(cfg["route"]["default_interface"], "pppoe-wan")

    def test_no_wan_iface_keeps_auto_detect(self):
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct")
        self.assertIs(cfg["route"]["auto_detect_interface"], True)
        self.assertNotIn("default_interface", cfg["route"])


class TestReservedTags(unittest.TestCase):
    """机场节点若命名成 direct/auto/proxy 等保留名，必须避让重命名，否则会被去重丢弃且选择器引用错对象。"""

    def test_node_named_direct_renamed(self):
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct",
                           node_uris=["trojan://pw@1.2.3.4:443?sni=a.com#direct"])
        tags = [o.get("tag") for o in cfg["outbounds"]]
        self.assertIn("direct-node", tags)
        self.assertIn("direct", tags)  # 内置 direct 仍保留
        auto = next(o for o in cfg["outbounds"] if o["tag"] == "auto")
        self.assertEqual(auto["outbounds"], ["direct-node"])

    def test_node_named_auto_not_self_referencing(self):
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct",
                           node_uris=["trojan://pw@1.2.3.4:443?sni=a.com#auto"])
        auto = next(o for o in cfg["outbounds"] if o["tag"] == "auto")
        self.assertNotIn("auto", auto["outbounds"])
        self.assertIn("auto-node", auto["outbounds"])


class TestCdnMirror(unittest.TestCase):
    def test_jsdelivr_rewrite(self):
        cfg = {"route": {"rule_set": [
            {"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"}]}}
        out = apply_cdn_mirror(cfg, "jsdelivr")
        self.assertEqual(out["route"]["rule_set"][0]["url"],
                         "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs")

    def test_direct_noop(self):
        cfg = {"route": {"rule_set": [{"url": "https://raw.githubusercontent.com/x/y/z/w.srs"}]}}
        self.assertEqual(apply_cdn_mirror(cfg, "direct"), cfg)


class TestEndToEndAndSelfCheck(unittest.TestCase):
    """CLI 端到端：生成 → 内置静态审计零错误 → 输出合法 JSON。"""

    def test_cli_generates_and_self_validates(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "config.json")
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "utf-8"
            for version, mode in (("1.13", "fakeip"), ("1.13", "realip"), ("1.14", "fakeip"), ("1.14", "realip")):
                with self.subTest(version=version, mode=mode):
                    r = subprocess.run(
                        [sys.executable, os.path.join(SCRIPTS, "auto_config.py"),
                         "--version", version, "--dns-mode", mode,
                         "--node", "trojan://pw@5.6.7.8:443?sni=b.com#JP-01",
                         "--mirror", "direct", "--out", out],
                        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=SCRIPTS)
                    self.assertEqual(r.returncode, 0, f"{version}/{mode} 失败:\n{r.stderr}\n{r.stdout}")
                    with open(out, encoding="utf-8") as f:
                        cfg = json.load(f)
                    self.assertIn("JP-01", [o.get("tag") for o in cfg["outbounds"]])

    def test_cli_invalid_node_ignored_but_still_succeeds(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "config.json")
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "utf-8"
            r = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "auto_config.py"),
                 "--version", "1.13", "--dns-mode", "fakeip",
                 "--node", "not-a-uri",
                 "--node", "trojan://pw@5.6.7.8:443?sni=b.com#GOOD",
                 "--mirror", "direct", "--out", out],
                capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=SCRIPTS)
            self.assertEqual(r.returncode, 0)
            with open(out, encoding="utf-8") as f:
                cfg = json.load(f)
            tags = [o.get("tag") for o in cfg["outbounds"]]
            self.assertIn("GOOD", tags)


class TestCustomDnsUpstreams(unittest.TestCase):
    def test_dns_cn_presets(self):
        cfg_ali = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_cn="alidns")
        ali_server = next(s for s in cfg_ali["dns"]["servers"] if s.get("tag") == "alidns")
        self.assertEqual(ali_server["server"], "223.5.5.5")
        self.assertEqual(ali_server["type"], "udp")

        cfg_dnspod = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_cn="dnspod")
        dnspod_server = next(s for s in cfg_dnspod["dns"]["servers"] if s.get("tag") == "alidns")
        self.assertEqual(dnspod_server["server"], "119.29.29.29")
        self.assertEqual(dnspod_server["type"], "udp")

        cfg_114 = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_cn="114")
        server_114 = next(s for s in cfg_114["dns"]["servers"] if s.get("tag") == "alidns")
        self.assertEqual(server_114["server"], "114.114.114.114")

    def test_dns_cn_custom_ip_and_doh(self):
        cfg_custom = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_cn="180.76.76.76")
        s_custom = next(s for s in cfg_custom["dns"]["servers"] if s.get("tag") == "alidns")
        self.assertEqual(s_custom["server"], "180.76.76.76")
        self.assertEqual(s_custom["type"], "udp")

        cfg_doh = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_cn="https://dns.alidns.com/dns-query")
        s_doh = next(s for s in cfg_doh["dns"]["servers"] if s.get("tag") == "alidns")
        self.assertEqual(s_doh["server"], "dns.alidns.com")
        self.assertEqual(s_doh["type"], "https")

    def test_dns_remote_presets_and_doh(self):
        cfg_cf = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_remote="cloudflare")
        s_cf = next(s for s in cfg_cf["dns"]["servers"] if s.get("tag") == "google-dns")
        self.assertEqual(s_cf["server"], "1.1.1.1")
        self.assertEqual(s_cf["type"], "https")
        self.assertEqual(s_cf["detour"], "proxy")

        cfg_quad9 = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_remote="quad9")
        s_quad9 = next(s for s in cfg_quad9["dns"]["servers"] if s.get("tag") == "google-dns")
        self.assertEqual(s_quad9["server"], "9.9.9.9")
        self.assertEqual(s_quad9["type"], "https")
        self.assertEqual(s_quad9["detour"], "proxy")

        cfg_doh = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_remote="https://1.1.1.1:8443/custom-query")
        s_doh = next(s for s in cfg_doh["dns"]["servers"] if s.get("tag") == "google-dns")
        self.assertEqual(s_doh["server"], "1.1.1.1")
        self.assertEqual(s_doh["type"], "https")
        self.assertEqual(s_doh["server_port"], 8443)
        self.assertEqual(s_doh["path"], "/custom-query")
        self.assertEqual(s_doh["detour"], "proxy")

        cfg_udp = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_remote="208.67.222.222")
        s_udp = next(s for s in cfg_udp["dns"]["servers"] if s.get("tag") == "google-dns")
        self.assertEqual(s_udp["server"], "208.67.222.222")
        self.assertEqual(s_udp["type"], "udp")
        self.assertEqual(s_udp["detour"], "proxy")


class TestBootstrapDns(unittest.TestCase):
    def test_node_domain_injected_to_dns_and_route(self):
        cfg = build_config(
            version="1.14", dns_mode="fakeip", mirror="direct",
            node_uris=["trojan://pw@hk.example.com:443?sni=hk.example.com#HK-01"]
        )
        dns_rules = cfg["dns"]["rules"]
        matched_dns = [r for r in dns_rules if "hk.example.com" in r.get("domain", [])]
        self.assertTrue(matched_dns, "dns.rules 未发现节点域名直连规则")
        self.assertEqual(matched_dns[0]["server"], "alidns")

        route_rules = cfg["route"]["rules"]
        matched_route = [r for r in route_rules if "hk.example.com" in r.get("domain", [])]
        self.assertTrue(matched_route, "route.rules 未发现节点域名直连规则")
        self.assertEqual(matched_route[0]["outbound"], "direct")

        node_ob = next(o for o in cfg["outbounds"] if o["tag"] == "HK-01")
        self.assertEqual(node_ob.get("domain_resolver"), "alidns")


class TestBypassTopology(unittest.TestCase):
    def test_bypass_with_main_router_ip(self):
        cfg = build_config(
            version="1.14", dns_mode="fakeip", mirror="direct",
            topology="bypass", main_router_ip="192.168.1.1"
        )
        route_rules = cfg["route"]["rules"]
        direct_rules = [r for r in route_rules if "192.168.1.1/32" in r.get("ip_cidr", [])]
        self.assertTrue(direct_rules, "旁路由模式下未找到主路由 IP 的直连放行规则")
        self.assertEqual(direct_rules[0]["outbound"], "direct")


class TestCanaryDomainRejection(unittest.TestCase):
    def test_generated_config_retains_canary_blocking(self):
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct")
        dns_rules = cfg["dns"]["rules"]
        canary_dns = [r for r in dns_rules if r.get("action") == "reject" and "use-application-dns.net" in r.get("domain", [])]
        self.assertTrue(canary_dns, "生成配置中必须包含 DoH Canary 阻断规则")

        route_rules = cfg["route"]["rules"]
        canary_route = [r for r in route_rules if r.get("action") == "reject" and "mask.icloud.com" in r.get("domain", [])]
        self.assertTrue(canary_route, "生成配置中必须包含 Apple Private Relay Canary 阻断规则")


class TestAuditHardeningAutoConfig(unittest.TestCase):
    def test_dns_cn_doh_passes_check_config_and_cli(self):
        from check_config import check_config_obj
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_cn="https://dns.alidns.com/dns-query")
        errs, _ = check_config_obj(cfg)
        self.assertEqual(errs, [], f"dns_cn DoH 配置不应触发引导死锁错误: {errs}")
        self.assertEqual(cfg["route"]["default_domain_resolver"], "bootstrap-dns")

    def test_cli_fails_when_all_nodes_invalid(self):
        r = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "auto_config.py"),
             "--version", "1.14", "--node", "not-a-valid-uri", "--mirror", "direct"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=SCRIPTS
        )
        self.assertNotEqual(r.returncode, 0, "所有 --node 均无效时必须非 0 退出，防止静默下发假节点")

    def test_tag_dedup_no_collision_with_existing_suffixed_tag(self):
        cfg = build_config(
            version="1.14", dns_mode="fakeip", mirror="direct",
            node_uris=[
                "trojan://p@1.1.1.1:443#HK",
                "trojan://p@2.2.2.2:443#HK-1",
                "trojan://p@3.3.3.3:443#HK",
            ]
        )
        tags = [o["tag"] for o in cfg["outbounds"] if o["type"] == "trojan"]
        self.assertEqual(len(tags), len(set(tags)), f"出站标签发生碰撞: {tags}")


    def test_bypass_ipv6_and_invalid_main_router_ip_rejected(self):
        cfg_v6 = build_config(version="1.14", dns_mode="fakeip", topology="bypass", main_router_ip="fd00::1")
        cidrs = [r.get("ip_cidr") for r in cfg_v6["route"]["rules"] if r.get("ip_cidr")]
        self.assertIn(["fd00::1/128"], cidrs)
        with self.assertRaises(ValueError):
            build_config(version="1.14", dns_mode="fakeip", topology="bypass", main_router_ip="not-an-ip")



    def test_dns_ip_port_and_tls_quic_schemes_supported(self):
        from check_config import check_config_obj
        # AdGuardHome / SmartDNS local port cascading (127.0.0.1:5335) must not inject false domain_resolver
        cfg_adg = build_config(version="1.14", dns_mode="fakeip", mirror="direct", dns_cn="127.0.0.1:5335")
        ali = next(s for s in cfg_adg["dns"]["servers"] if s["tag"] == "alidns")
        self.assertEqual(ali["server"], "127.0.0.1")
        self.assertEqual(ali["server_port"], 5335)
        self.assertNotIn("domain_resolver", ali)
        errs, _ = check_config_obj(cfg_adg)
        self.assertEqual(errs, [])

        # DoT (tls://) and DoQ (quic://) schemes
        cfg_dot = build_config(
            version="1.14", dns_mode="fakeip", mirror="direct",
            dns_cn="tls://dns.alidns.com:853", dns_remote="quic://dns.adguard-dns.com"
        )
        ali_dot = next(s for s in cfg_dot["dns"]["servers"] if s["tag"] == "alidns")
        self.assertEqual(ali_dot["type"], "tls")
        self.assertEqual(ali_dot["server"], "dns.alidns.com")
        self.assertEqual(ali_dot["server_port"], 853)
        self.assertEqual(ali_dot["domain_resolver"], "bootstrap-dns")
        rem_doq = next(s for s in cfg_dot["dns"]["servers"] if s["tag"] == "google-dns")
        self.assertEqual(rem_doq["type"], "quic")
        self.assertEqual(rem_doq["server"], "dns.adguard-dns.com")
        errs2, _ = check_config_obj(cfg_dot)
        self.assertEqual(errs2, [])

    def test_invalid_wan_iface_and_nonpositive_max_nodes_rejected(self):
        with self.assertRaises(ValueError):
            build_config(version="1.14", dns_mode="fakeip", wan_iface="-oProxyCommand=bad")
        with self.assertRaises(ValueError):
            build_config(version="1.14", dns_mode="fakeip", wan_iface="eth0; reboot")
        with self.assertRaises(ValueError):
            build_config(version="1.14", dns_mode="fakeip", max_nodes=0)

    def test_canary_and_ads_precede_clash_global_mode_in_dns_rules(self):
        cfg = build_config(version="1.14", dns_mode="fakeip", mirror="direct")
        rules = cfg["dns"]["rules"]
        idx_canary = next(i for i, r in enumerate(rules) if "use-application-dns.net" in r.get("domain", []))
        idx_global = next(i for i, r in enumerate(rules) if r.get("clash_mode") == "Global")
        self.assertLess(idx_canary, idx_global, "Canary 域名阻断必须位于 clash_mode: Global 之前")



    def test_deprecated_ss_cipher_isolated_in_auto_config(self):
        cfg = build_config(
            version="1.14", dns_mode="fakeip", mirror="direct",
            node_uris=[
                "ss://aes-256-cfb:pass@1.2.3.4:8388#OldCFB",
                "trojan://pw@5.6.7.8:443?sni=b.com#GoodTrojan",
            ],
            strict_nodes=True,
        )
        tags = [o.get("tag") for o in cfg["outbounds"]]
        self.assertNotIn("OldCFB", tags)
        self.assertIn("GoodTrojan", tags)


if __name__ == "__main__":
    unittest.main()
