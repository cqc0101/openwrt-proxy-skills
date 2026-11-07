# -*- coding: utf-8 -*-
"""sub_parser 单元测试：订阅清洗、Clash 转换、dae 导出语法的正确性。"""

import base64
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "singbox-openwrt", "scripts"))

from sub_parser import (  # noqa: E402
    parse_source, parse_subscription_text, parse_clash_proxy,
    filter_nodes, to_dae_nodes, safe_b64decode,
)


class TestSafeB64(unittest.TestCase):
    def test_padding_and_urlsafe(self):
        self.assertIn("vless://", safe_b64decode(base64.urlsafe_b64encode(b"vless://x").decode()))


class TestParseSubscriptionText(unittest.TestCase):
    def test_multiline_uris_with_comments(self):
        text = """
# 机场信息
vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=a.com&pbk=PK&sid=1#A
trojan://pw@5.6.7.8:443?sni=b.com#B
"""
        nodes = parse_subscription_text(text)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0]["type"], "vless")
        self.assertEqual(nodes[1]["type"], "trojan")

    def test_base64_wrapped_subscription(self):
        inner = "trojan://pw@5.6.7.8:443?sni=b.com#B\nss://aes-128-gcm:pw@1.1.1.1:8388#S"
        nodes = parse_subscription_text(base64.b64encode(inner.encode()).decode())
        self.assertEqual(len(nodes), 2)


class TestFilterNodes(unittest.TestCase):
    def test_excludes_ad_noise(self):
        nodes = [
            {"type": "trojan", "tag": "香港 01", "server": "1.1.1.1", "server_port": 443},
            {"type": "trojan", "tag": "剩余流量: 100GB", "server": "2.2.2.2", "server_port": 443},
            {"type": "trojan", "tag": "官网更新", "server": "3.3.3.3", "server_port": 443},
        ]
        clean = filter_nodes(nodes, max_nodes=15)
        self.assertEqual(len(clean), 1)
        self.assertEqual(clean[0]["tag"], "香港-01")

    def test_dedup_and_quote_sanitize(self):
        nodes = [
            {"type": "trojan", "tag": "HK'01", "server": "1.1.1.1", "server_port": 443},
            {"type": "trojan", "tag": "HK'01", "server": "1.1.1.1", "server_port": 443},
        ]
        clean = filter_nodes(nodes, max_nodes=15)
        self.assertEqual(len(clean), 2)
        for n in clean:
            self.assertNotIn("'", n["tag"])
        self.assertNotEqual(clean[0]["tag"], clean[1]["tag"])

    def test_max_nodes_cap(self):
        nodes = [{"type": "trojan", "tag": f"N{i}", "server": "1.1.1.1", "server_port": 443} for i in range(30)]
        self.assertEqual(len(filter_nodes(nodes, max_nodes=5)), 5)


class TestClashProxy(unittest.TestCase):
    def test_vless_ws_goes_to_transport(self):
        ob = parse_clash_proxy({
            "name": "HK-WS", "type": "vless", "server": "1.2.3.4", "port": 443,
            "uuid": "u", "network": "ws", "tls": True, "servername": "s.com",
            "ws-opts": {"path": "/ws", "headers": {"Host": "h.com"}},
        })
        self.assertNotEqual(ob.get("network"), "ws")
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/ws")
        self.assertEqual(ob["transport"]["headers"]["Host"], "h.com")
        self.assertEqual(ob["tls"]["server_name"], "s.com")

    def test_vless_reality(self):
        ob = parse_clash_proxy({
            "name": "US-R", "type": "vless", "server": "1.2.3.4", "port": 443,
            "uuid": "u", "flow": "xtls-rprx-vision",
            "reality-opts": {"public-key": "PK", "short-id": "12"},
            "client-fingerprint": "chrome",
        })
        self.assertIs(ob["tls"]["reality"]["enabled"], True)
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PK")
        self.assertEqual(ob["flow"], "xtls-rprx-vision")

    def test_vmess_grpc(self):
        ob = parse_clash_proxy({
            "name": "SG-G", "type": "vmess", "server": "1.2.3.4", "port": 443,
            "uuid": "u", "network": "grpc",
            "grpc-opts": {"grpc-service-name": "svc"},
        })
        self.assertEqual(ob["transport"]["type"], "grpc")
        self.assertEqual(ob["transport"]["service_name"], "svc")


class TestToDaeNodes(unittest.TestCase):
    def _lines(self, nodes):
        return [l for l in to_dae_nodes(nodes).splitlines() if l.strip().startswith("'")]

    def test_vmess_is_valid_v2rayn_base64_json(self):
        nodes = [{"type": "vmess", "tag": "SG", "server": "8.8.8.8", "server_port": 80,
                  "uuid": "u2", "security": "auto", "alter_id": 0,
                  "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "h.com"}},
                  "tls": {"enabled": True, "server_name": "s.com"}}]
        line = self._lines(nodes)[0]
        payload = line.split("'")[3].replace("vmess://", "")
        d = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)).decode())
        self.assertEqual(d["v"], "2")
        self.assertEqual(d["net"], "ws")
        self.assertEqual(d["path"], "/ws")
        self.assertEqual(d["host"], "h.com")
        self.assertEqual(d["tls"], "tls")

    def test_vless_tls_keeps_sni(self):
        nodes = [{"type": "vless", "tag": "US", "server": "1.2.3.4", "server_port": 443,
                  "uuid": "u", "tls": {"enabled": True, "server_name": "a.com"}}]
        uri = self._lines(nodes)[0].split("'")[3]
        self.assertIn("security=tls", uri)
        self.assertIn("sni=a.com", uri)

    def test_tags_sanitized_and_quoted(self):
        nodes = [
            {"type": "trojan", "tag": "JP'01", "server": "5.6.7.8", "server_port": 443,
             "password": "pw", "tls": {"enabled": True, "server_name": "b.com"}},
        ]
        line = self._lines(nodes)[0]
        self.assertNotIn("JP'01", line)
        self.assertTrue(line.startswith("  'JP-01': 'trojan://"))

    def test_hy2_insecure_flag(self):
        nodes = [{"type": "hysteria2", "tag": "HK", "server": "9.9.9.9", "server_port": 3456,
                  "password": "pw", "tls": {"enabled": True, "server_name": "c.com", "insecure": True}}]
        uri = self._lines(nodes)[0].split("'")[3]
        self.assertIn("insecure=1", uri)


class TestToDaeNodesIPv6(unittest.TestCase):
    V6 = "240e:123:456::1"

    def _uri(self, node):
        lines = [l for l in to_dae_nodes([node]).splitlines() if l.strip().startswith("'")]
        return lines[0].split("'")[3]

    def test_hysteria2_brackets(self):
        uri = self._uri({"type": "hysteria2", "tag": "H6", "server": self.V6,
                         "server_port": 3456, "password": "pw",
                         "tls": {"enabled": True, "server_name": self.V6}})
        self.assertIn("pw@[240e:123:456::1]:3456", uri)
        self.assertIn("sni=240e:123:456::1", uri)   # 查询参数里的 sni 不带方括号

    def test_shadowsocks_brackets(self):
        uri = self._uri({"type": "shadowsocks", "tag": "S6", "server": self.V6,
                         "server_port": 8388, "method": "aes-128-gcm", "password": "pw"})
        self.assertIn("@[240e:123:456::1]:8388", uri)

    def test_vless_brackets(self):
        uri = self._uri({"type": "vless", "tag": "V6", "server": self.V6,
                         "server_port": 443, "uuid": "u",
                         "tls": {"enabled": True, "server_name": self.V6}})
        self.assertIn("u@[240e:123:456::1]:443", uri)
        self.assertIn("sni=240e:123:456::1", uri)

    def test_trojan_brackets(self):
        uri = self._uri({"type": "trojan", "tag": "T6", "server": self.V6,
                         "server_port": 443, "password": "pw",
                         "tls": {"enabled": True, "server_name": "a.com"}})
        self.assertIn("pw@[240e:123:456::1]:443", uri)

    def test_domain_not_bracketed(self):
        uri = self._uri({"type": "trojan", "tag": "T", "server": "example.com",
                         "server_port": 443, "password": "pw",
                         "tls": {"enabled": True, "server_name": "example.com"}})
        self.assertIn("pw@example.com:443", uri)
        self.assertNotIn("[example.com]", uri)


class TestParseSource(unittest.TestCase):
    def test_file_source(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("trojan://pw@5.6.7.8:443?sni=b.com#B\n")
            path = f.name
        try:
            nodes = parse_source(path, max_nodes=10)
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0]["type"], "trojan")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
