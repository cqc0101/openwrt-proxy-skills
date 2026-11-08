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
                        capture_output=True, text=True, env=env, cwd=SCRIPTS)
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
                capture_output=True, text=True, env=env, cwd=SCRIPTS)
            self.assertEqual(r.returncode, 0)
            with open(out, encoding="utf-8") as f:
                cfg = json.load(f)
            tags = [o.get("tag") for o in cfg["outbounds"]]
            self.assertIn("GOOD", tags)


if __name__ == "__main__":
    unittest.main()
