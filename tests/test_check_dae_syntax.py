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


    def test_double_quoted_node_with_fragment_flagged(self):
        errors, _ = check("""
global {
    lan_interface: br-lan
    wan_interface: auto
}
node {
    my_node: "trojan://pw@1.2.3.4:443#MyTag"
}
routing {
    pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct
}
""")
        self.assertTrue(any("单引号" in e for e in errors), f"带 #fragment 的双引号节点未被拦截: {errors}")

    def test_openwrt_dae_has_dns_request_canary_rejection(self):
        """验证 openwrt.dae 将无前缀 Canary 域名拦截置于 routing.domain 中，且 check_dae_syntax 拦截 qname 无前缀裸域名 (addQName 崩溃陷阱)。"""
        with open(os.path.join(REPO, "skills", "dae-openwrt", "assets", "templates", "openwrt.dae"), encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("qname('use-application-dns.net'", content)
        self.assertIn("domain(suffix: use-application-dns.net, suffix: mask.icloud.com, suffix: mask-h2.icloud.com) -> block", content)
        errs, warns = check("""
global { lan_interface: br-lan\n wan_interface: auto }
dns {
    upstream { alidns: 'udp://223.5.5.5:53' }
    routing {
        request {
            qname('use-application-dns.net', 'mask.icloud.com') -> reject
            qname(geosite:category-ads-all) -> reject
            fallback: alidns
        }
    }
}
routing { pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct\n fallback: direct }
""")
        self.assertTrue(any("addQName" in e for e in errs), errs)
        self.assertTrue(any("category-ads-all" in w for w in warns), warns)
        # 验证带逗号的正则量词 '{1,2}'、括号 '(foo|bar)' 及合法前缀 domain:/regexp: 不会触发误报
        ok_errs, _ = check(r'''
global { lan_interface: br-lan
 wan_interface: auto }
dns {
    upstream { alidns: 'udp://223.5.5.5:53' }
    routing {
        request {
            qname(domain: google.com, regexp: '^(foo|bar)\.com$', regex: '^a{1,2}\.com$') -> alidns
            fallback: alidns
        }
    }
}
routing { pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct
 fallback: direct }
''')
        self.assertEqual(ok_errs, [], f"合法 qname 规则不应误报: {ok_errs}")


    def test_unbalanced_single_quote_flagged(self):
        cfg = (
            "global { lan_interface: br-lan\n wan_interface: auto }\n"
            "node { 'bad': 'trojan://pa'ss@1.2.3.4:443' }\n"
            "routing { pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct }\n"
        )
        errors, _ = check(cfg)
        self.assertTrue(any("未配对闭合的单引号" in e for e in errors), errors)



    def test_unbalanced_curly_braces_flagged(self):
        cfg = (
            "global { lan_interface: br-lan\n wan_interface: auto }\n"
            "routing {\n"
            "  pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct\n"
        )
        errors, _ = check(cfg)
        self.assertTrue(any("未闭合的左花括号" in e for e in errors), errors)



    def test_selector_double_quotes_and_empty_node_pool_warned(self):
        cfg = (
            "global { lan_interface: br-lan\n wan_interface: auto }\n"
            "subscription {}\n"
            "node {}\n"
            "routing {\n"
            '  pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct\n'
            '  domain("google.com") -> proxy\n'
            "}\n"
        )
        errors, warnings = check(cfg)
        self.assertTrue(any("单引号" in e for e in errors), errors)
        self.assertTrue(any("空节点池" in w for w in warnings), warnings)



    def test_dangling_dae_group_and_dns_upstream_blocked(self):
        cfg = '''
global {
    lan_interface: br-lan
    wan_interface: auto
}
dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
    }
    routing {
        request {
            qname(geosite:cn) -> alidns
            fallback: ghost_dns
        }
    }
}
group {
    proxy {
        policy: min_moving_avg
    }
}
routing {
    pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct
    domain(geosite:google) -> ghost_group
    fallback: proxy
}
'''
        errors, _ = check(cfg)
        self.assertTrue(any("ghost_group" in e for e in errors), errors)
        self.assertTrue(any("ghost_dns" in e for e in errors), errors)



    def test_single_quoted_group_and_upstream_targets_checked(self):
        """验证 check_dae_syntax.py 对单引号包裹的策略组与 DNS 上游引用执行准确的悬空检测与匹配。"""
        content = """
global {
    lan_interface: br-lan
    wan_interface: auto
}
node {
    'n1': 'vless://uuid@1.1.1.1:443#n1'
}
group {
    'my-proxy' {
        policy: min_moving_avg
    }
}
dns {
    upstream {
        'ali-dns': 'udp://223.5.5.5:53'
    }
    routing {
        request {
            qname(geosite:cn) -> ali-dns
            fallback: 'non-existent-dns'
        }
    }
}
routing {
    pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct
    domain(geosite:google) -> my-proxy
    fallback: 'non-existent-group'
}
"""
        errors, _ = check(content)
        self.assertTrue(any("non-existent-group" in e for e in errors), f"应拦截悬空的单引号策略组: {errors}")
        self.assertFalse(any("my-proxy" in e for e in errors), f"不应误报已定义的单引号策略组: {errors}")
        self.assertTrue(any("non-existent-dns" in e for e in errors), f"应拦截悬空的单引号 DNS 上游: {errors}")
        self.assertFalse(any("ali-dns" in e for e in errors), f"不应误报已定义的单引号 DNS 上游: {errors}")


    def test_routing_to_defined_node_is_valid(self):
        """dae 路由规则直接指向 node {} 中已定义的独立节点应判定为合法，不报悬空策略组错误。"""
        cfg = (
            "global { lan_interface: br-lan\n wan_interface: auto }\n"
            "node { 'my_vps': 'vless://u@1.1.1.1:443?security=none#my_vps' }\n"
            "group { proxy { policy: min_moving_avg } }\n"
            "routing {\n"
            "  pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct\n"
            "  domain('netflix.com') -> my_vps\n"
            "  domain('google.com') -> proxy\n"
            "}\n"
        )
        errors, _ = check(cfg)
        self.assertFalse(any("悬空" in e for e in errors), errors)

    def test_arrow_inside_quotes_and_inline_multi_groups_upstreams_and_bare_node(self):
        """引号内的 '->' 不应被误判为路由目标；单行多 group/upstream 定义与无键名裸节点 #Tag 引用均应被正确识别。"""
        cfg = (
            "global { lan_interface: br-lan\n wan_interface: auto }\n"
            "node {\n"
            "  'hk_2': 'vless://u@1.1.1.1:443?sec=none#It\\'s#1'\n"
            "  'vless://u@2.2.2.2:443?sec=none#MyBareNode'\n"
            "}\n"
            "group { proxy { policy: min_moving_avg } ai { policy: random } }\n"
            "dns {\n"
            "  upstream { alidns: 'udp://223.5.5.5:53' googledns: 'tcp://8.8.8.8:53' }\n"
            "  routing { request { qname(geosite:cn) -> alidns\n qname(geosite:google) -> googledns\n fallback: alidns } }\n"
            "}\n"
            "routing {\n"
            "  pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct\n"
            "  domain('test->not_an_outbound.com') -> proxy\n"
            "  domain('openai.com') -> ai\n"
            "  domain('netflix.com') -> MyBareNode\n"
            "  fallback: proxy\n"
            "}\n"
        )
        errors, _ = check(cfg)
        self.assertEqual(errors, [], f"不应产生误报: {errors}")

    def test_uri_and_regex_tokens_do_not_pollute_defined_sets_and_quoted_fallback_ignored(self):
        """验证 node/upstream URI 内部的协议名/域名片段及 group 内正则不会污染合法出站/上游集合，且引号内 fallback: 不触发误报。"""
        cfg = """
global {
    lan_interface: br-lan
    wan_interface: auto
}
node {
    my_node: 'vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&sni=test.com#my_node'
}
group {
    proxy {
        filter: name(regex: '^HK0{1,2}$')
        policy: min_moving_avg
    }
}
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
    }
    routing {
        request {
            qname(keyword: 'fallback: fake_ups') -> alidns
            qname(geosite:cn) -> udp
            fallback: com
        }
    }
}
routing {
    pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct
    domain(keyword: 'fallback: fake_grp') -> proxy
    domain(geosite:google) -> vless
    fallback: HK0
}
"""
        errors, _ = check(cfg)
        self.assertFalse(any("fake_grp" in e for e in errors), errors)
        self.assertFalse(any("fake_ups" in e for e in errors), errors)
        self.assertTrue(any("'vless'" in e for e in errors), errors)
        self.assertTrue(any("'HK0'" in e for e in errors), errors)
        self.assertTrue(any("'udp'" in e for e in errors), errors)
        self.assertTrue(any("'com'" in e for e in errors), errors)


    def test_hyphen_in_dnsmasq_or_response_rules_and_escaped_backslash_before_quote(self):
        """验证 dnsmasq / response 规则条件含连字符 '-' 时不误报，且以转义反斜杠 '\\' 结尾的字符串不误报单引号未闭合。"""
        cfg = r'''
global {
    lan_interface: br-lan
    wan_interface: auto
}
node {
    'my_node': 'trojan://pass\\@1.2.3.4:443?sni=a.com#my_node'
}
dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
        googledns: 'tcp+udp://8.8.8.8:53'
    }
    routing {
        request {
            qname(geosite:cn) -> alidns
            fallback: googledns
        }
        response {
            upstream(googledns) -> accept
            ip(geoip:private) && !qname(geosite:cn-private) -> googledns
            fallback: accept
        }
    }
}
routing {
    pname(dnsmasq, sing-box) && l4proto(udp) && dport(53-5353) -> must_direct
    domain(keyword: 'has "double" quote inside single quote') -> my_node
    fallback: my_node
}
'''
        errors, _ = check(cfg)
        self.assertEqual(errors, [], f"合法配置不应触发误报: {errors}")


    def test_quoted_upstream_in_response_relookup_without_whitelist_blocked(self):
        """R7-04: response 块中私网重查指向单引号包裹的上游名 (如 -> 'googledns') 且缺少前置 accept 白名单时必须被拦截。"""
        cfg = '''
global { lan_interface: br-lan
 wan_interface: auto }
node { n1: 'vless://u@1.1.1.1:443?security=none#n1' }
group { proxy { policy: min_moving_avg } }
dns {
    upstream { alidns: 'udp://223.5.5.5:53'
 googledns: 'tcp+udp://8.8.8.8:53' }
    routing {
        request { fallback: alidns }
        response {
            ip(geoip:private) -> 'googledns'
            fallback: accept
        }
    }
}
routing {
    pname(dnsmasq) && l4proto(udp) && dport(53) -> must_direct
    fallback: proxy
}
'''
        errors, _ = check(cfg)
        self.assertTrue(any("DNS 投毒死循环高危" in e for e in errors), errors)


    def test_response_block_with_regex_brace_quantifier_not_truncated(self):
        """验证 response 块内含正则量词 '{1,2}' 时不会被 [^}]* 提前截断而漏检私网重查死循环。"""
        cfg = r'''
global { lan_interface: br-lan
 wan_interface: auto }
node { n1: 'vless://u@1.1.1.1:443?security=none#n1' }
group { proxy { policy: min_moving_avg } }
dns {
    upstream { alidns: 'udp://223.5.5.5:53'
 googledns: 'tcp+udp://8.8.8.8:53' }
    routing {
        request { fallback: alidns }
        response {
            qname(regex: '^a{1,2}\.com$') && ip(geoip:private) -> googledns
            fallback: accept
        }
    }
}
routing { pname(dnsmasq) -> must_direct
 fallback: proxy }
'''
        errors, _ = check(cfg)
        self.assertTrue(any("DNS 投毒死循环高危" in e for e in errors), errors)

if __name__ == "__main__":
    unittest.main()
