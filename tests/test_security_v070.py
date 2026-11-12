# -*- coding: utf-8 -*-
"""v0.7.0 安全边界与一致性回归测试：
1) SSRF 全链路防护（IP/域名/IPv4-mapped IPv6/CGNAT/重定向逐跳/最大跳数/URL 凭据脱敏）
2) SSH 参数注入与严格主机密钥校验（key_path/timeout/OPENWRT_STRICT_SSH/OPENWRT_KNOWN_HOSTS）
3) Shell --dry-run 演练模式、SSH_KEY 前导连字符拦截与 doctor.sh 日志凭据脱敏
"""

import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SINGBOX_SCRIPTS = os.path.join(REPO, "skills", "singbox-openwrt", "scripts")
DAE_SCRIPTS = os.path.join(REPO, "skills", "dae-openwrt", "scripts")

for p in (SINGBOX_SCRIPTS, DAE_SCRIPTS):
    if p not in sys.path:
        sys.path.insert(0, p)

import sub_parser
import auto_config
import sub_to_dae


class TestSsrfAndRedaction(unittest.TestCase):
    def test_blocked_ssrf_urls_rejected(self):
        blocked_urls = [
            "http://127.0.0.1:8080/sub",
            "http://localhost/sub",
            "http://sub.localhost/sub",
            "http://router.local/sub",
            "http://metadata.internal/sub",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/sub",
            "http://172.16.0.1/sub",
            "http://192.168.1.1/sub",
            "http://100.64.0.1/sub",
            "http://0.0.0.0/sub",
            "http://[::1]/sub",
            "http://[::ffff:127.0.0.1]/sub",
            "http://[64:ff9b::127.0.0.1]/sub",
            "http://127.0.0.1\\@example.com/sub",
            "file:///etc/passwd",
            "ftp://example.com/sub",
        ]
        for u in blocked_urls:
            with self.subTest(url=u):
                with self.assertRaises(ValueError):
                    sub_parser.parse_source(u)

    def test_dns_resolution_to_private_ip_blocked(self):
        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.10.1", 443)),
        ]
        with mock.patch("sub_parser.socket.getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(ValueError) as ctx:
                sub_parser.fetch_subscription("https://evil.example.com/sub?token=super_secret_123")
        self.assertIn("SSRF", str(ctx.exception))
        self.assertNotIn("super_secret_123", str(ctx.exception))

    def test_redirect_to_private_ip_and_excess_redirects_blocked(self):
        handler = sub_parser._SafeRedirectHandler(allow_private=False, max_redirects=2)
        req = urllib.request.Request("https://public.example.com/sub")

        with self.assertRaises((ValueError, urllib.error.URLError)):
            handler.redirect_request(req, None, 302, "Found", {}, "http://127.0.0.1:9090/configs")

        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch("sub_parser.socket.getaddrinfo", return_value=fake_public):
            r1 = handler.redirect_request(req, None, 302, "Found", {}, "https://cdn1.example.com/sub")
            self.assertIsNotNone(r1)
            r2 = handler.redirect_request(r1, None, 302, "Found", {}, "https://cdn2.example.com/sub")
            self.assertIsNotNone(r2)
            with self.assertRaises(urllib.error.URLError):
                handler.redirect_request(r2, None, 302, "Found", {}, "https://cdn3.example.com/sub")

    def test_error_message_redacts_token_and_userinfo(self):
        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch("sub_parser.socket.getaddrinfo", return_value=fake_public), \
             mock.patch("sub_parser.urllib.request.OpenerDirector.open", side_effect=OSError("network down")):
            with self.assertRaises(RuntimeError) as ctx:
                sub_parser.fetch_subscription("https://alice:my_pass@sub.example.com/api?token=SECRET_XYZ&flag=1")
        msg = str(ctx.exception)
        self.assertNotIn("my_pass", msg)
        self.assertNotIn("SECRET_XYZ", msg)
        self.assertIn("sub.example.com", msg)

    def test_multiline_text_starting_with_http_not_treated_as_url(self):
        txt = "http://not-a-url-line\nvless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#V1\n"
        nodes = sub_parser.parse_source(txt)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["tag"], "V1")


class TestSshAndShellSecurity(unittest.TestCase):
    def test_ssh_key_path_and_timeout_validation_and_strict_mode(self):
        for fn in (auto_config.detect_remote_version, sub_to_dae.detect_remote_dae_version):
            with self.assertRaises(ValueError):
                fn("192.168.1.1", key_path="-oProxyCommand=id")
            with self.assertRaises(ValueError):
                fn("192.168.1.1", key_path="/nonexistent/id_ed25519_test")
            with self.assertRaises(ValueError):
                fn("192.168.1.1", timeout=0)
            with self.assertRaises(ValueError):
                fn("192.168.1.1", timeout=True)

        with mock.patch.dict(os.environ, {"OPENWRT_STRICT_SSH": "1"}), \
             mock.patch("auto_config.subprocess.run") as m_run:
            m_run.return_value = mock.Mock(stdout="sing-box version 1.14.0\n", stderr="", returncode=0)
            v, _ = auto_config.detect_remote_version("192.168.1.1")
            self.assertEqual(v, "1.14")
            cmd = m_run.call_args[0][0]
            self.assertIn("StrictHostKeyChecking=yes", cmd)
            self.assertIn("BatchMode=yes", cmd)

    def test_setup_network_dry_run_and_ssh_key_dash_guard(self):
        for base in (SINGBOX_SCRIPTS, DAE_SCRIPTS):
            sh_path = os.path.join(base, "setup_openwrt_network.sh")
            r_dry = subprocess.run(
                ["sh", sh_path, "--dry-run"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertEqual(r_dry.returncode, 0, r_dry.stderr)
            self.assertIn("[DRY-RUN]", r_dry.stdout)
            r_dry_ipv6 = subprocess.run(
                ["sh", sh_path, "--keep-ipv6", "--dry-run"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertEqual(r_dry_ipv6.returncode, 0, r_dry_ipv6.stderr)
            self.assertIn("action=normal, keep_ipv6=1", r_dry_ipv6.stdout)

            r_bad_key = subprocess.run(
                ["sh", sh_path, "192.168.1.1", "-i", "-oProxyCommand=id"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertNotEqual(r_bad_key.returncode, 0)
            self.assertIn("非法的 SSH 密钥路径", r_bad_key.stdout + r_bad_key.stderr)

    def test_doctor_redacts_sensitive_tokens_in_logs(self):
        doc_path = os.path.join(DAE_SCRIPTS, "doctor.sh")
        sh_snippet = (
            'logread() { echo "ERR dae fetch https://u1:p1@sub.example.com/sub?token=TOPSECRET123&flag=clash&api_key=API_SEC_77 password=MY_DB_PASS node=trojan://TROJAN_SECRET_99@1.2.3.4:443"; }; '
            '_doc="$1"; shift; . "$_doc"'
        )
        if True:
            res = subprocess.run(
                ["sh", "-c", sh_snippet, "sh", doc_path, "dae", "--json"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertIn(res.returncode, (0, 1, 2), res.stderr)
            self.assertIn("recent_logs", res.stdout)
            self.assertNotIn("TOPSECRET123", res.stdout)
            self.assertNotIn("MY_DB_PASS", res.stdout)
            self.assertNotIn("u1:p1", res.stdout)
            self.assertNotIn("TROJAN_SECRET_99", res.stdout)
            self.assertNotIn("API_SEC_77", res.stdout)
            self.assertIn("flag=clash", res.stdout)



    def test_redact_text_urls_and_invalid_port(self):
        from sub_parser import redact_url, redact_text_urls, _validate_remote_url
        # Expanded query key substring matching (e.g., api_key, sub_token, jwt_token)
        u = "https://sub.example.com/api?api_key=MY_KEY_123&sub_token=SUB_TOK_456&jwt=JWT_789&flag=clash"
        red = redact_url(u)
        self.assertNotIn("MY_KEY_123", red)
        self.assertNotIn("SUB_TOK_456", red)
        self.assertNotIn("JWT_789", red)
        self.assertIn("flag=clash", red)
        # Embedded redirected URL inside error text
        err_msg = "HTTP Error 403: Forbidden at https://cdn.example.org/dl?access_token=REDIRECT_SECRET_999"
        red_err = redact_text_urls(err_msg)
        self.assertNotIn("REDIRECT_SECRET_999", red_err)
        self.assertIn("access_token=***REDACTED***", red_err)
        # Invalid port out of range should raise ValueError with redacted URL
        with self.assertRaises(ValueError) as ctx:
            _validate_remote_url("https://sub.example.com:99999/sub?token=PORT_SECRET_111", allow_private=True)
        self.assertNotIn("PORT_SECRET_111", str(ctx.exception))



    def test_cross_origin_proxy_authorization_case_insensitive_stripping(self):
        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        handler = sub_parser._SafeRedirectHandler(allow_private=False, max_redirects=3)
        req = urllib.request.Request(
            "https://origin.example.com/sub",
            headers={
                "Authorization": "Bearer secret1",
                "Proxy-Authorization": "Basic secret2",
                "Cookie": "session=secret3",
            },
        )
        with mock.patch("sub_parser.socket.getaddrinfo", return_value=fake_public):
            new_req = handler.redirect_request(req, None, 302, "Found", {}, "https://cdn.other.org/sub")
        lower_hdrs = {k.lower() for k in new_req.headers.keys()} | {k.lower() for k in new_req.unredirected_hdrs.keys()}
        self.assertNotIn("authorization", lower_hdrs)
        self.assertNotIn("proxy-authorization", lower_hdrs)
        self.assertNotIn("cookie", lower_hdrs)



    def test_auto_config_build_config_propagates_ssrf_error(self):
        with self.assertRaises(ValueError) as ctx:
            auto_config.build_config(
                sub_source="http://127.0.0.1:8080/sub?token=SUB_SEC_888",
                node_uris=["vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#V1"],
            )
        self.assertIn("SSRF", str(ctx.exception))
        self.assertNotIn("SUB_SEC_888", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
