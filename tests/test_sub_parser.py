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


    def test_clash_tuic_anytls_hy2_ports_httpupgrade_and_reject_xhttp(self):
        hy2_ob = parse_clash_proxy({
            "name": "HY2-Hop", "type": "hysteria2", "server": "1.2.3.4", "port": 443,
            "password": "pw", "ports": "20000-40000", "alpn": ["h3"],
        })
        self.assertEqual(hy2_ob["server_ports"], ["20000:40000"])
        self.assertEqual(hy2_ob["tls"]["alpn"], ["h3"])

        tuic_ob = parse_clash_proxy({
            "name": "TUIC-Node", "type": "tuic", "server": "2.3.4.5", "port": 8443,
            "uuid": "u-1", "password": "p-1", "congestion-controller": "bbr", "alpn": ["h3"],
        })
        self.assertEqual(tuic_ob["type"], "tuic")
        self.assertEqual(tuic_ob["uuid"], "u-1")
        self.assertEqual(tuic_ob["tls"]["alpn"], ["h3"])

        anytls_ob = parse_clash_proxy({
            "name": "ANY-Node", "type": "anytls", "server": "3.4.5.6", "port": 443,
            "password": "pw", "smux": {"enabled": True, "protocol": "h2mux"},
        })
        self.assertEqual(anytls_ob["type"], "anytls")
        self.assertEqual(anytls_ob["multiplex"], {"enabled": True, "protocol": "h2mux"})

        hu_ob = parse_clash_proxy({
            "name": "VLESS-HU", "type": "vless", "server": "4.5.6.7", "port": 443,
            "uuid": "u-2", "tls": True, "network": "httpupgrade",
            "httpupgrade-opts": {"path": "/hu", "host": "hu.example.com"},
        })
        self.assertEqual(hu_ob["transport"], {"type": "httpupgrade", "path": "/hu", "host": "hu.example.com"})

        # xhttp/splithttp 等不支持传输层必须返回空字典丢弃，严禁静默生成裸 TCP
        bad_ob = parse_clash_proxy({
            "name": "VLESS-XHTTP", "type": "vless", "server": "4.5.6.7", "port": 443,
            "uuid": "u-2", "tls": True, "network": "xhttp",
        })
        self.assertEqual(bad_ob, {})

        dae_out = to_dae_nodes([tuic_ob, anytls_ob, hu_ob])
        self.assertIn("tuic://u-1:p-1@2.3.4.5:8443", dae_out)
        self.assertIn("anytls://pw@3.4.5.6:443", dae_out)
        self.assertIn("type=httpupgrade&path=/hu&host=hu.example.com", dae_out)



    def test_to_dae_nodes_preserves_alpn_and_hy2_mport(self):
        from parse_node import parse_uri
        from sub_parser import to_dae_nodes
        n1 = parse_uri("hysteria2://pw@example.com:443?sni=example.com&mport=20000-30000&alpn=h3#Hy2-Hop")
        n2 = parse_uri("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&sni=example.com&alpn=h2,http/1.1#VLESS-ALPN")
        dae_out = to_dae_nodes([n1, n2])
        self.assertIn("mport=20000-30000", dae_out)
        self.assertIn("alpn=h3", dae_out)
        self.assertIn("alpn=h2,http%2F1.1", dae_out)



    def test_clash_ss_plugin_and_reality_missing_pbk_filtered(self):
        from sub_parser import parse_clash_proxy, to_dae_nodes
        ob_obfs = parse_clash_proxy({
            "name": "SS-Obfs",
            "type": "ss",
            "server": "example.com",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "secret",
            "plugin": "obfs",
            "plugin-opts": {"mode": "tls", "host": "cloudflare.com"},
        })
        self.assertEqual(ob_obfs["plugin"], "obfs-local")
        self.assertEqual(ob_obfs["plugin_opts"], "obfs=tls;obfs-host=cloudflare.com")
        self.assertIn("plugin=obfs-local", to_dae_nodes([ob_obfs]))

        # Unsupported SS plugin must be rejected, not silently downgraded
        self.assertEqual(parse_clash_proxy({
            "name": "SS-ShadowTLS",
            "type": "ss",
            "server": "example.com",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "secret",
            "plugin": "shadow-tls",
        }), {})

        # Reality without public-key must be rejected
        self.assertEqual(parse_clash_proxy({
            "name": "Bad-Reality",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "reality-opts": {"short-id": "1234"},
        }), {})



    def test_vmess_to_dae_preserves_httpupgrade_host_alpn_and_insecure(self):
        vm_node = {
            "type": "vmess",
            "tag": "VM-HU",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "security": "auto",
            "alter_id": 0,
            "transport": {"type": "httpupgrade", "path": "/hu", "host": "hu.example.com"},
            "tls": {"enabled": True, "server_name": "sni.example.com", "alpn": ["h2", "http/1.1"], "insecure": True},
        }
        dae_out = to_dae_nodes([vm_node])
        line = [l for l in dae_out.splitlines() if l.strip().startswith("'")][0]
        payload = line.split("'")[3].replace("vmess://", "")
        decoded = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8"))
        self.assertEqual(decoded["host"], "hu.example.com")
        self.assertEqual(decoded["alpn"], "h2,http/1.1")
        self.assertEqual(decoded["allowInsecure"], 1)

    def test_clash_out_of_range_port_filtered_and_invalid_max_nodes_rejected(self):
        self.assertEqual(parse_clash_proxy({
            "name": "BadPort", "type": "trojan", "server": "1.2.3.4", "port": 70000, "password": "p"
        }), {})
        with self.assertRaises(ValueError):
            filter_nodes([], max_nodes=0)

    def test_pure_python_clash_yaml_parser_with_anchors(self):
        from sub_parser import parse_clash_yaml_pure_python, parse_subscription_text
        yaml_text = """
pr_common: &pr_common
  type: vless
  cipher: auto
  tls: true
  skip-cert-verify: true

pr_trojan: &pr_trojan {type: trojan, password: trojan_pass, udp: true}

proxies:
  - name: "HK-VLESS"
    <<: *pr_common
    server: 198.51.100.1
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
  - {name: "SG-Trojan", <<: *pr_trojan, server: 198.51.100.2, port: 8443}
"""
        raw_list = parse_clash_yaml_pure_python(yaml_text)
        self.assertEqual(len(raw_list), 2)
        self.assertEqual(raw_list[0]["type"], "vless")
        self.assertEqual(raw_list[0]["tls"], True)
        self.assertEqual(raw_list[1]["type"], "trojan")
        self.assertEqual(raw_list[1]["password"], "trojan_pass")

        # 端到端测试 parse_subscription_text
        nodes = parse_subscription_text(yaml_text)
        self.assertEqual(len(nodes), 2)
        tags = [n["tag"] for n in nodes]
        self.assertIn("HK-VLESS", tags)
        self.assertIn("SG-Trojan", tags)



    def test_pure_python_yaml_nested_flow_multiline_list_comments_and_b64_yaml(self):
        from sub_parser import parse_clash_yaml_pure_python, parse_subscription_text
        yaml_complex = '''
common_ws: &common_ws {type: vless, port: 8443, tls: true, network: ws}

proxies:
  # 1. 内联嵌套字典 (ws-opts -> headers -> Host) + 锚点 + 显式字段覆盖锚点默认端口 + 行内注释
  - {name: "HK,Inline-WS", <<: *common_ws, server: 1.2.3.4, port: 443, uuid: u-1, servername: ws.a.com, alpn: [h2, http/1.1], ws-opts: {path: /ws, headers: {Host: cdn.a.com}}} # inline comment
  # 2. 多级缩进块字典 (ws-opts -> headers -> Host) + 多行 YAML 列表 (alpn) + null 容错
  - name: "SG-Block-WS" # comment
    type: vmess
    server: 5.6.7.8 # server comment
    port: 443
    uuid: u-2
    alterId: null
    cipher: auto
    tls: true
    servername: sni.b.com
    alpn:
      - h2
      - http/1.1
    network: ws
    ws-opts:
      path: /v2ws
      headers:
        Host: host.b.com
  # 3. 含废弃加密的 SS 节点应被自动过滤隔离，不影响正常节点
  - {name: "Old-SS-CFB", type: ss, server: 9.9.9.9, port: 8388, cipher: aes-256-cfb, password: pw}
'''
        raw_items = parse_clash_yaml_pure_python(yaml_complex)
        self.assertEqual(len(raw_items), 3)
        self.assertEqual(raw_items[0]["name"], "HK,Inline-WS")
        self.assertEqual(raw_items[0]["port"], 443)  # 显式字段不被 <<: *common_ws 覆盖为 8443
        self.assertEqual(raw_items[0]["ws-opts"]["headers"]["Host"], "cdn.a.com")
        self.assertEqual(raw_items[0]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(raw_items[1]["ws-opts"]["headers"]["Host"], "host.b.com")
        self.assertEqual(raw_items[1]["alpn"], ["h2", "http/1.1"])
        self.assertIsNone(raw_items[1]["alterId"])

        # Base64 包裹的 Clash YAML 订阅端到端解析
        b64_yaml = base64.b64encode(yaml_complex.encode("utf-8")).decode("ascii")
        nodes = parse_subscription_text(b64_yaml)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0]["transport"]["headers"]["Host"], "cdn.a.com")
        self.assertEqual(nodes[1]["transport"]["headers"]["Host"], "host.b.com")


if __name__ == "__main__":
    unittest.main()
