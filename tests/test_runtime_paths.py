"""Node editing and client checks: no production devices or real credentials."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

R = Path(__file__).resolve().parents[1]
S = R / "skills/dae-openwrt/scripts"

def load(name):
    spec = importlib.util.spec_from_file_location(name, S / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

link = load("node_link")
checks = load("check_path")
syntax = load("check_dae_syntax")

class NodeLinks(unittest.TestCase):
    def test_fragment_ipv6_and_encoded_credentials_survive(self):
        original = "vless://test%40user@[2001:db8::1]:443?security=reality&x=a%26b&fp=&fp=old#test%20node"
        updated = link.update_query(original, {"fp": "chrome"})
        u = urlsplit(updated)
        self.assertEqual(u.netloc, urlsplit(original).netloc)
        self.assertEqual(u.fragment, "test%20node")
        self.assertEqual(parse_qs(u.query)["fp"], ["chrome"])
        self.assertEqual(parse_qs(u.query)["x"], ["a&b"])

    def test_controls_and_unsupported_schemes_rejected(self):
        for value in ("vless://test@example.invalid:443\n", "https://example.invalid/"):
            with self.assertRaises(ValueError):
                link.update_query(value, {"fp": "chrome"})

    def test_cli_does_not_overwrite_or_print_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "input"
            output = Path(d) / "output"
            source.write_text("vless://fixture-only@example.invalid:443#node", encoding="utf8")
            cmd = [sys.executable, str(S / "node_link.py"), str(source), str(output), "--set", "fp=chrome"]
            first = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(first.returncode, 0)
            saved = output.read_bytes()
            second = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes(), saved)
            self.assertNotIn("fixture-only", first.stdout + first.stderr + second.stdout + second.stderr)

    def test_reality_fingerprint_must_be_in_query(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.dae"
            base = (R / "skills/dae-openwrt/assets/templates/openwrt.dae").read_text(encoding="utf8")
            for query, fragment, missing in [("", "node&fp=chrome", True), ("&fp=", "node", True), ("&fp=chrome", "node", False)]:
                uri = "vless://test@example.invalid:443?security=reality&sni=example.invalid&pbk=fixture" + query + "#" + fragment
                p.write_text(base.replace("node {", "node {\n    fixture: '" + uri + "'"), encoding="utf8")
                errors, warnings = syntax.check_dae_syntax(str(p))
                self.assertEqual(any("Reality 指纹缺失" in e for e in errors), missing)
                self.assertNotIn("vless://", " ".join(errors))

class ClientChecks(unittest.TestCase):
    def test_success_records_path_without_claiming_node_health(self):
        completed = subprocess.CompletedProcess([], 0, "204 192.0.2.2 198.51.100.2 0 0 0.4", "")
        with patch.object(checks.subprocess, "run", return_value=completed) as run:
            r = checks.run_check("https://example.invalid/", "192.0.2.2", ["example.invalid=198.51.100.2"])
        self.assertTrue(r["success"])
        self.assertEqual(r["dns_mode"], "explicit_answer")
        self.assertFalse(r["dns_server_verified"])
        args = run.call_args.args[0]
        self.assertIn("--resolve", args)
        self.assertIn("--max-filesize", args)
        self.assertIn("--noproxy", args)
        self.assertNotIn("--insecure", args)

    def test_other_host_answer_does_not_claim_explicit_resolution(self):
        with patch.object(checks.subprocess, "run", side_effect=OSError):
            r = checks.run_check("https://example.invalid/", "eth0", ["other.invalid=192.0.2.1"])
        self.assertEqual(r["dns_mode"], "system_resolver")
        self.assertEqual(r["status"], "tool_error")

    def test_tool_failure_is_not_node_failure(self):
        for code in (2, 3, 4, 48):
            with patch.object(checks.subprocess, "run", return_value=subprocess.CompletedProcess([], code, "", "private details")):
                r = checks.run_check("https://example.invalid/", "eth0")
            self.assertEqual(r["status"], "tool_error")
            self.assertNotIn("private details", json.dumps(r))

    def test_timeout_does_not_mean_permanent_node_failure(self):
        with patch.object(checks.subprocess, "run", return_value=subprocess.CompletedProcess([], 28, "000 192.0.2.2 198.51.100.2 0 0 5", "")):
            r = checks.run_check("https://example.invalid/", "eth0")
        self.assertEqual(r["status"], "request_failed")
        self.assertFalse(r["success"])

    def test_inputs_and_traffic_are_bounded(self):
        for url in ("http://example.invalid", "https://secret@example.invalid", "https://example.invalid:22"):
            with self.assertRaises(ValueError):
                checks.run_check(url, "eth0")
        with self.assertRaises(ValueError):
            checks.run_check("https://example.invalid", "eth0", timeout=300)
        with self.assertRaises(ValueError):
            checks.run_check("https://example.invalid", "eth0", ["example.invalid=--bad"])

    def test_shared_copies_match(self):
        for name in ("node_link.py", "check_path.py"):
            self.assertEqual((S / name).read_bytes(), (R / "skills/singbox-openwrt/scripts" / name).read_bytes())
