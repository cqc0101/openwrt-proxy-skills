# -*- coding: utf-8 -*-
"""sub_parser 单元测试：订阅清洗、Clash 转换、dae 导出语法的正确性。"""

import base64
import gzip
import json
import os
import sys
import unittest
import zlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "singbox-openwrt", "scripts"))

from sub_parser import (  # noqa: E402
    parse_source, parse_subscription_text, parse_clash_proxy,
    filter_nodes, to_dae_nodes, safe_b64decode, _decompress,
    extract_node_domains, HAS_YAML,
)


class TestDecompress(unittest.TestCase):
    """订阅响应可能是 gzip/deflate 压缩（urllib 不会自动解压）。"""

    def test_gzip_by_magic(self):
        raw = b"trojan://pw@1.1.1.1:443#A"
        gz = gzip.compress(raw)
        self.assertEqual(_decompress(gz, ""), raw)
        self.assertEqual(_decompress(gz, "gzip"), raw)

    def test_deflate(self):
        raw = b"vless://uuid@2.2.2.2:443#B"
        z = zlib.compress(raw)
        self.assertEqual(_decompress(z, "deflate"), raw)

    def test_plain_passthrough(self):
        raw = b"plain subscription text"
        self.assertEqual(_decompress(raw, ""), raw)


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

    def test_vless_reality_sni_from_top_level_servername(self):
        """Reality 的 SNI 在顶层 servername，reality-opts 里只有 key/short-id 时不能回退成 IP。"""
        ob = parse_clash_proxy({
            "name": "US-R", "type": "vless", "server": "1.2.3.4", "port": 443,
            "uuid": "u", "tls": True, "servername": "www.microsoft.com",
            "reality-opts": {"public-key": "PK", "short-id": "12"},
            "client-fingerprint": "chrome",
        })
        self.assertEqual(ob["tls"]["server_name"], "www.microsoft.com")
        self.assertIs(ob["tls"]["reality"]["enabled"], True)

    def test_trojan_sni_servername_fallback(self):
        ob = parse_clash_proxy({
            "name": "T", "type": "trojan", "server": "1.2.3.4", "port": 443,
            "password": "p", "servername": "a.com",
        })
        self.assertEqual(ob["tls"]["server_name"], "a.com")

    def test_trojan_ws_and_grpc(self):
        ob_ws = parse_clash_proxy({
            "name": "T-WS", "type": "trojan", "server": "1.2.3.4", "port": 443,
            "password": "p", "network": "ws", "ws-opts": {"path": "/tws"},
        })
        self.assertEqual(ob_ws["transport"]["type"], "ws")
        self.assertEqual(ob_ws["transport"]["path"], "/tws")

        ob_grpc = parse_clash_proxy({
            "name": "T-G", "type": "trojan", "server": "1.2.3.4", "port": 443,
            "password": "p", "network": "grpc", "grpc-opts": {"grpc-service-name": "tsvc"},
        })
        self.assertEqual(ob_grpc["transport"]["type"], "grpc")
        self.assertEqual(ob_grpc["transport"]["service_name"], "tsvc")

    def test_hysteria2_auth_and_obfs(self):
        ob = parse_clash_proxy({
            "name": "H2", "type": "hysteria2", "server": "1.2.3.4", "port": 443,
            "auth": "myauth", "obfs": "salamander", "obfs-password": "opw",
        })
        self.assertEqual(ob["password"], "myauth")
        self.assertEqual(ob["obfs"]["type"], "salamander")
        self.assertEqual(ob["obfs"]["password"], "opw")

    def test_vmess_grpc_keeps_service_name(self):
        nodes = [{"type": "vmess", "tag": "G", "server": "1.1.1.1", "server_port": 443,
                  "uuid": "u", "security": "auto", "alter_id": 0,
                  "transport": {"type": "grpc", "service_name": "svc"},
                  "tls": {"enabled": True, "server_name": "s.com"}}]
        line = [l for l in to_dae_nodes(nodes).splitlines() if l.strip().startswith("'")][0]
        payload = line.split("'")[3].replace("vmess://", "")
        d = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)).decode())
        self.assertEqual(d["net"], "grpc")
        self.assertEqual(d["path"], "svc")

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

    def test_single_quote_in_password_escaped(self):
        nodes = [{"type": "hysteria2", "tag": "HK", "server": "9.9.9.9", "server_port": 3456,
                  "password": "pass'word", "tls": {"enabled": True, "server_name": "c.com"}}]
        line = self._lines(nodes)[0]
        self.assertEqual(line.count("'"), 4, f"内部单引号未正确转义打断语法: {line}")
        self.assertIn("pass%27word", line)

    def test_vless_plaintext_no_tls(self):
        nodes = [{"type": "vless", "tag": "PLAIN", "server": "1.2.3.4", "server_port": 80,
                  "uuid": "u-plain"}]
        uri = self._lines(nodes)[0].split("'")[3]
        self.assertIn("security=none", uri)
        self.assertNotIn("security=tls", uri)

    def test_vless_and_trojan_ws_grpc_preserved_in_dae(self):
        nodes = [
            {
                "type": "vless", "tag": "VWS", "server": "1.2.3.4", "server_port": 443, "uuid": "u-1",
                "tls": {"enabled": True, "server_name": "ws.example.com"},
                "transport": {"type": "ws", "path": "/vless-ws", "headers": {"Host": "cdn.example.com"}},
            },
            {
                "type": "trojan", "tag": "TGRPC", "server": "5.6.7.8", "server_port": 443, "password": "pw",
                "tls": {"enabled": True, "server_name": "grpc.example.com"},
                "transport": {"type": "grpc", "service_name": "tr-Stream"},
            },
        ]
        lines = self._lines(nodes)
        vless_uri = lines[0].split("'")[3]
        trojan_uri = lines[1].split("'")[3]
        self.assertIn("type=ws", vless_uri)
        self.assertIn("path=/vless-ws", vless_uri)
        self.assertIn("host=cdn.example.com", vless_uri)
        self.assertIn("type=grpc", trojan_uri)
        self.assertIn("serviceName=tr-Stream", trojan_uri)


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


class TestExtractNodeDomains(unittest.TestCase):
    def test_extract_node_domains(self):
        nodes = [
            {"tag": "N1", "server": "1.2.3.4", "server_port": 443},
            {"tag": "N2", "server": "hk.example.com", "server_port": 443},
            {"tag": "N3", "server": "240e:123:456::1", "server_port": 443},
            {"tag": "N4", "server": "jp.example.org", "server_port": 443},
            {"tag": "N5", "server": "hk.example.com", "server_port": 8443},
        ]
        domains = extract_node_domains(nodes)
        self.assertEqual(domains, ["hk.example.com", "jp.example.org"])


class TestSubParserFuzzAndEdgeCases(unittest.TestCase):
    def test_clash_proxy_edge_cases_do_not_crash(self):
        cases = [
            {},
            None,
            "not_a_dict",
            {"type": "unknown"},
            {"type": "vless", "server": ""},
            {"type": "vless", "server": "1.2.3.4", "port": "not_an_int"},
            {"type": "trojan", "server": "1.2.3.4", "port": None},
            {"type": "ss", "server": "1.2.3.4", "port": "9999"},
        ]
        for c in cases:
            with self.subTest(case=repr(c)[:30]):
                res = parse_clash_proxy(c)
                self.assertIsInstance(res, dict)

    def test_subscription_text_fuzz_do_not_crash(self):
        fuzz_samples = [
            "",
            "   \n\t  \r\n",
            "# comment line only\n# second comment",
            "just random garbage text\nwith non-uri strings\n12345",
            "vmess://e30=",  # empty dict {}
            "vmess://bm90X2pzb24=",  # 'not_json'
            "vless://",
            "trojan://",
            "ss://",
        ]
        for s in fuzz_samples:
            with self.subTest(sample=repr(s)[:30]):
                res = parse_subscription_text(s)
                self.assertIsInstance(res, list)

    def test_to_dae_nodes_skips_broken_nodes(self):
        broken_nodes = [
            {"type": "vless", "tag": "bad1", "server": None, "server_port": 443},
            {"type": "trojan", "tag": "bad2", "server": "1.2.3.4", "server_port": None},
            {"type": "hysteria2", "tag": "good", "server": "5.6.7.8", "server_port": 34589, "password": "pw"},
        ]
        out = to_dae_nodes(broken_nodes)
        self.assertIn("'good'", out)
        self.assertNotIn("'bad1'", out)
        self.assertNotIn("'bad2'", out)


class TestAuditHardeningSubParser(unittest.TestCase):
    def test_urlsafe_b64_chinese_subscription_not_corrupted(self):
        sub_raw = (
            "vless://uuid@1.2.3.4:443#新加坡-01\n"
            "trojan://pw@5.6.7.8:443#新加坡-02\n"
            "trojan://pw@8.8.8.8:443#新加坡-03\n"
            "trojan://pw@9.9.9.9:443#新加坡-04"
        )
        b64_url = base64.urlsafe_b64encode(sub_raw.encode("utf-8")).decode("ascii")
        nodes = parse_subscription_text(b64_url)
        self.assertEqual(len(nodes), 4)
        self.assertEqual(nodes[0]["tag"], "新加坡-01")

    def test_filter_nodes_no_secondary_collision(self):
        nodes = [
            {"type": "trojan", "tag": "HK", "server": "1.1.1.1", "server_port": 443, "password": "p"},
            {"type": "trojan", "tag": "HK", "server": "2.2.2.2", "server_port": 443, "password": "p"},
            {"type": "trojan", "tag": "HK 2", "server": "3.3.3.3", "server_port": 443, "password": "p"},
        ]
        cleaned = filter_nodes(nodes)
        tags = [n["tag"] for n in cleaned]
        self.assertEqual(len(tags), len(set(tags)), f"存在重复标签碰撞: {tags}")

    def test_to_dae_nodes_escapes_special_chars_in_password(self):
        nodes = [{
            "type": "trojan", "tag": "TestTr", "server": "1.2.3.4",
            "server_port": 443, "password": "p@ss#word?1",
            "tls": {"enabled": True, "server_name": "a.com"}
        }]
        out = to_dae_nodes(nodes)
        self.assertIn("trojan://p%40ss%23word%3F1@1.2.3.4:443", out)

    @unittest.skipIf(not HAS_YAML, "PyYAML 未安装，跳过 Clash YAML 解析测试")
    def test_clash_yaml_single_bad_node_isolated(self):
        yaml_sub = """
proxies:
  - name: Good-Node-1
    type: trojan
    server: 1.2.3.4
    port: 443
    password: secret
  - name: Bad-VMess
    type: vmess
    server: 2.3.4.5
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: null
  - name: Good-Node-2
    type: trojan
    server: 5.6.7.8
    port: 443
    password: secret
"""
        nodes = parse_subscription_text(yaml_sub)
        self.assertGreaterEqual(len(nodes), 2)

    def test_decompress_size_limit(self):
        payload = gzip.compress(b"A" * 2048)
        with self.assertRaises(ValueError):
            _decompress(payload, "gzip", max_bytes=512)

if __name__ == "__main__":
    unittest.main()
