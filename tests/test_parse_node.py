# -*- coding: utf-8 -*-
"""parse_node 单元测试：节点 URI → sing-box outbound 的正确性与字段合法性。"""

import base64
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "singbox-openwrt", "scripts"))

from parse_node import (  # noqa: E402
    parse_uri, parse_vless, parse_trojan, parse_hysteria2, parse_shadowsocks, parse_vmess,
    _split_host_port, _b64_decode,
)


class TestVLESS(unittest.TestCase):
    def test_reality(self):
        ob = parse_uri("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
                       "?security=reality&sni=www.microsoft.com&pbk=PK&sid=abcd&fp=chrome&flow=xtls-rprx-vision#US")
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(ob["flow"], "xtls-rprx-vision")
        self.assertEqual(ob["tls"]["server_name"], "www.microsoft.com")
        self.assertIs(ob["tls"]["reality"]["enabled"], True)
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PK")
        self.assertEqual(ob["tls"]["reality"]["short_id"], "abcd")
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "chrome")

    def test_tls_ws_transport_not_network(self):
        ob = parse_uri("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
                       "?security=tls&type=ws&path=%2Fws&host=a.com&sni=a.com#HK")
        # network 绝不能是 ws
        self.assertNotEqual(ob.get("network"), "ws")
        self.assertEqual(ob.get("network"), None)
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/ws")
        self.assertEqual(ob["transport"]["headers"]["Host"], "a.com")
        self.assertEqual(ob["tls"]["server_name"], "a.com")
        self.assertIs(ob["tls"]["insecure"], False)

    def test_grpc_transport(self):
        ob = parse_vless("vless://u@1.2.3.4:443?security=tls&type=grpc&serviceName=gsvc#G")
        self.assertEqual(ob["transport"]["type"], "grpc")
        self.assertEqual(ob["transport"]["service_name"], "gsvc")

    def test_udp_network(self):
        ob = parse_vless("vless://u@1.2.3.4:443?type=udp#U")
        self.assertEqual(ob["network"], "udp")


class TestTrojan(unittest.TestCase):
    def test_basic(self):
        ob = parse_trojan("trojan://pw@5.6.7.8:443?sni=b.com#JP")
        self.assertEqual(ob["type"], "trojan")
        self.assertEqual(ob["password"], "pw")
        self.assertEqual(ob["tls"]["server_name"], "b.com")
        self.assertIs(ob["tls"]["insecure"], False)

    def test_ws_and_insecure(self):
        ob = parse_trojan("trojan://pw@5.6.7.8:443?sni=b.com&allowInsecure=1&type=ws&path=%2Ft&host=h.com#JP")
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/t")
        self.assertEqual(ob["transport"]["headers"]["Host"], "h.com")
        self.assertIs(ob["tls"]["insecure"], True)


class TestHysteria2(unittest.TestCase):
    def test_basic(self):
        ob = parse_hysteria2("hysteria2://pw2@9.9.9.9:3456?sni=c.com&insecure=0#HK")
        self.assertEqual(ob["password"], "pw2")
        self.assertEqual(ob["tls"]["server_name"], "c.com")
        self.assertIs(ob["tls"]["insecure"], False)

    def test_obfs(self):
        ob = parse_hysteria2("hysteria2://pw2@9.9.9.9:3456?sni=c.com&obfs=salamander&obfs-password=op#HK")
        self.assertEqual(ob["obfs"]["type"], "salamander")
        self.assertEqual(ob["obfs"]["password"], "op")


class TestShadowsocks(unittest.TestCase):
    def test_plain_userpass(self):
        ob = parse_shadowsocks("ss://aes-256-gcm:pass@1.1.1.1:8388#SS")
        self.assertEqual(ob["method"], "aes-256-gcm")
        self.assertEqual(ob["password"], "pass")

    def test_base64_userpass(self):
        import base64
        b64 = base64.b64encode(b"aes-128-gcm:pw2").decode()
        ob = parse_shadowsocks(f"ss://{b64}@2.2.2.2:8388#SS2")
        self.assertEqual(ob["method"], "aes-128-gcm")
        self.assertEqual(ob["password"], "pw2")

    def test_whole_base64(self):
        import base64
        b64 = base64.b64encode(b"chacha20-ietf-poly1305:pw3@3.3.3.3:8389").decode()
        ob = parse_shadowsocks(f"ss://{b64}#SS3")
        self.assertEqual(ob["server"], "3.3.3.3")
        self.assertEqual(ob["server_port"], 8389)

    def test_ipv6_base64_userinfo(self):
        import base64
        b64 = base64.b64encode(b"aes-128-gcm:pw2").decode().rstrip("=")
        ob = parse_shadowsocks(f"ss://{b64}@[240e:123:456::1]:8388#SS6")
        self.assertEqual(ob["server"], "240e:123:456::1")
        self.assertEqual(ob["server_port"], 8388)

    def test_ipv6_whole_base64(self):
        import base64
        b64 = base64.b64encode(b"chacha20:pw@[240e:123:456::1]:8389").decode()
        ob = parse_shadowsocks(f"ss://{b64}#SS7")
        self.assertEqual(ob["server"], "240e:123:456::1")
        self.assertEqual(ob["server_port"], 8389)

    def test_whole_base64_with_inner_tag(self):
        import base64
        b64 = base64.b64encode(b"aes-256-gcm:pass123@1.2.3.4:8388#InnerTag").decode()
        ob = parse_shadowsocks(f"ss://{b64}")
        self.assertEqual(ob["server"], "1.2.3.4")
        self.assertEqual(ob["server_port"], 8388)
        self.assertEqual(ob["tag"], "InnerTag")

    def test_whole_base64_with_query_and_inner_tag(self):
        import base64
        b64 = base64.b64encode(b"aes-256-gcm:pass123@1.2.3.4:8388/?plugin=obfs#InnerTag").decode()
        ob = parse_shadowsocks(f"ss://{b64}")
        self.assertEqual(ob["server"], "1.2.3.4")
        self.assertEqual(ob["server_port"], 8388)
        self.assertEqual(ob["tag"], "InnerTag")

    def test_urlsafe_userinfo_supported(self):
        # 末字节 0x3F('?') 作为 3 字节组的第三字节 → 低 6 位全 1 → urlsafe 字符 '_'
        raw = b"aes-256-gcm:pw?"
        b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertIn("_", b64, "测试样本应含 urlsafe 特殊字符")
        ob = parse_shadowsocks(f"ss://{b64}@1.1.1.1:8388#U")
        self.assertEqual(ob["method"], "aes-256-gcm")
        self.assertEqual(ob["password"], "pw?")
        self.assertEqual(ob["server"], "1.1.1.1")

    def test_urlsafe_userinfo_rejected_cleanly(self):
        # urlsafe 字母表解出非 UTF-8 字节时应干净报错，而不是静默产出坏字节
        raw = b"aes-256-gcm:pa\xff"
        b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertTrue("-" in b64 or "_" in b64)
        with self.assertRaises(UnicodeDecodeError):
            parse_shadowsocks(f"ss://{b64}@1.1.1.1:8388#U")


class TestIPv6Hosts(unittest.TestCase):
    def test_vless_ipv6(self):
        ob = parse_uri("vless://u@[240e:123:456::1]:443?security=tls&sni=a.com#V6")
        self.assertEqual(ob["server"], "240e:123:456::1")
        self.assertEqual(ob["server_port"], 443)

    def test_trojan_ipv6(self):
        ob = parse_trojan("trojan://pw@[240e:123:456::1]:8443?sni=b.com#T6")
        self.assertEqual(ob["server"], "240e:123:456::1")
        self.assertEqual(ob["server_port"], 8443)

    def test_hysteria2_ipv6(self):
        ob = parse_hysteria2("hysteria2://pw@[240e:123:456::1]:3456?sni=c.com#H6")
        self.assertEqual(ob["server"], "240e:123:456::1")
        self.assertEqual(ob["server_port"], 3456)


class TestVMess(unittest.TestCase):
    def test_v2rayn_json_ws(self):
        import base64, json
        vm = {"v": "2", "ps": "SG", "add": "8.8.8.8", "port": "80", "id": "u2", "aid": "0",
              "scy": "auto", "net": "ws", "type": "none", "host": "h.com", "path": "/ws",
              "tls": "tls", "sni": "s.com"}
        ob = parse_vmess("vmess://" + base64.b64encode(json.dumps(vm).encode()).decode())
        self.assertEqual(ob["uuid"], "u2")
        self.assertEqual(ob["alter_id"], 0)
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/ws")
        self.assertEqual(ob["transport"]["headers"]["Host"], "h.com")
        self.assertEqual(ob["tls"]["server_name"], "s.com")

    def test_vmess_with_native_fragment(self):
        """vmess://BASE64#节点名 —— fragment 必须剥离，否则 base64 解码被污染"""
        import base64, json
        vm = {"v": "2", "ps": "香港01", "add": "1.1.1.1", "port": "443", "id": "u",
              "aid": "0", "scy": "auto", "net": "tcp", "type": "none"}
        b64 = base64.b64encode(json.dumps(vm).encode()).decode()
        ob = parse_vmess(f"vmess://{b64}#香港01")
        self.assertEqual(ob["tag"], "香港01")
        self.assertEqual(ob["server"], "1.1.1.1")
        # 无 padding + fragment 的组合
        b64_nopad = b64.rstrip("=")
        ob2 = parse_vmess(f"vmess://{b64_nopad}#节点")
        self.assertEqual(ob2["server"], "1.1.1.1")


class TestDispatch(unittest.TestCase):
    def test_unknown_scheme_raises(self):
        with self.assertRaises(ValueError):
            parse_uri("ftp://example.com")

    def test_hy2_alias(self):
        ob = parse_uri("hy2://pw@1.2.3.4:443?sni=x.com#A")
        self.assertEqual(ob["type"], "hysteria2")

    def test_colon_password_formats(self):
        ob_hy2 = parse_uri("hy2://:secret@1.2.3.4:443#H")
        self.assertEqual(ob_hy2["password"], "secret")
        ob_tr = parse_uri("trojan://:secret2@1.2.3.4:443#T")
        self.assertEqual(ob_tr["password"], "secret2")


class TestSplitHostPortAndB64(unittest.TestCase):
    def test_b64_gbk_tolerance(self):
        # 验证包含中文 GB18030 / GBK 编码的 Base64 字符串能平滑解码
        text_gbk = "aes-128-gcm:密码测试".encode("gb18030")
        b64 = base64.b64encode(text_gbk).decode("ascii")
        res = _b64_decode(b64)
        self.assertIn("aes-128-gcm:", res)

    def test_split_host_port_edge_cases(self):
        # 1. 缺端口
        s, p = _split_host_port("example.com")
        self.assertEqual(s, "example.com")
        self.assertEqual(p, 443)

        # 2. 非数字端口容错
        s, p = _split_host_port("example.com:invalid_port", default_port=8080)
        self.assertEqual(s, "example.com")
        self.assertEqual(p, 8080)

        # 3. 裸 IPv6
        s, p = _split_host_port("2001:db8::1")
        self.assertEqual(s, "2001:db8::1")
        self.assertEqual(p, 443)

        # 4. 方括号 IPv6 带端口
        s, p = _split_host_port("[2001:db8::1]:8443")
        self.assertEqual(s, "2001:db8::1")
        self.assertEqual(p, 8443)

        # 5. 方括号 IPv6 无端口
        s, p = _split_host_port("[2001:db8::1]")
        self.assertEqual(s, "2001:db8::1")
        self.assertEqual(p, 443)

        # 6. 带 URL 参数和 fragment
        s, p = _split_host_port("node.com:8888?param=1#tag")
        self.assertEqual(s, "node.com")
        self.assertEqual(p, 8888)


if __name__ == "__main__":
    unittest.main()
