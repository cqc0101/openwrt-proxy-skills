# -*- coding: utf-8 -*-
"""dae 技能自包含性验证：不依赖 singbox 目录也能完成订阅解析与节点导出。

用子进程隔离 sys.path，确保测试走的是 skills/dae-openwrt/scripts 内的本地副本，
而不是同进程中已加载的 singbox 模块。
"""

import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAE_SCRIPTS = os.path.join(REPO, "skills", "dae-openwrt", "scripts")


class TestDaeSelfContained(unittest.TestCase):
    def test_local_copies_exist(self):
        for name in ("parse_node.py", "sub_parser.py"):
            self.assertTrue(os.path.exists(os.path.join(DAE_SCRIPTS, name)),
                            f"dae 技能缺少自包含副本 {name}")

    def test_local_parser_works_without_sibling(self):
        code = (
            "import sys, tempfile, os\n"
            f"sys.path.insert(0, r'{DAE_SCRIPTS}')\n"
            "from sub_parser import parse_source, to_dae_nodes\n"
            "with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8') as f:\n"
            "    f.write('trojan://pw@5.6.7.8:443?sni=b.com#JP\\n'); p = f.name\n"
            "nodes = parse_source(p, max_nodes=5)\n"
            "out = to_dae_nodes(nodes)\n"
            "assert len(nodes) == 1, nodes\n"
            "assert 'trojan://pw@5.6.7.8:443' in out, out\n"
            "os.unlink(p)\n"
            "print('SELF_CONTAINED_OK')\n"
        )
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=DAE_SCRIPTS)
        self.assertEqual(r.returncode, 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}")
        self.assertIn("SELF_CONTAINED_OK", r.stdout)

    def test_sub_to_dae_full_config_generation_and_self_check(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            sub_file = os.path.join(td, "sub.txt")
            out_dae = os.path.join(td, "config.dae")
            with open(sub_file, "w", encoding="utf-8") as f:
                f.write("trojan://pw@5.6.7.8:443?sni=b.com&type=ws&path=/ws&host=b.com#JP-WS\n")
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "utf-8"
            r = subprocess.run(
                [sys.executable, os.path.join(DAE_SCRIPTS, "sub_to_dae.py"),
                 sub_file, "--full", "--lan-iface", "br-lan", "--out", out_dae],
                capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=DAE_SCRIPTS
            )
            self.assertEqual(r.returncode, 0, f"sub_to_dae --full 失败:\n{r.stderr}\n{r.stdout}")
            with open(out_dae, "r", encoding="utf-8") as f:
                dae_text = f.read()
            self.assertIn("global {", dae_text)
            self.assertIn("routing {", dae_text)
            self.assertIn("JP-WS: 'trojan://", dae_text)
            self.assertIn("type=ws&path=/ws&host=b.com", dae_text)

    def test_sub_to_dae_bypass_topology_injects_main_router_direct(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            sub_file = os.path.join(td, "sub.txt")
            out_dae = os.path.join(td, "config.dae")
            with open(sub_file, "w", encoding="utf-8") as f:
                f.write("tuic://u-1:p-1@9.9.9.9:8443?sni=a.com&alpn=h3#TUIC-01\n")
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "utf-8"
            r = subprocess.run(
                [sys.executable, os.path.join(DAE_SCRIPTS, "sub_to_dae.py"),
                 sub_file, "--full", "--topology", "bypass", "--main-router-ip", "192.168.1.1", "--out", out_dae],
                capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=DAE_SCRIPTS
            )
            self.assertEqual(r.returncode, 0, f"sub_to_dae bypass 失败:\n{r.stderr}")
            with open(out_dae, "r", encoding="utf-8") as f:
                dae_text = f.read()
            self.assertIn("dip(192.168.1.1) -> direct", dae_text)
            self.assertIn("tuic://u-1:p-1@9.9.9.9:8443", dae_text)

    def test_sub_to_dae_ram_adaptive_map_size(self):
        import sys
        if DAE_SCRIPTS not in sys.path:
            sys.path.insert(0, DAE_SCRIPTS)
        from sub_to_dae import build_full_dae_config
        nodes = [{"type": "trojan", "tag": "T1", "server": "1.2.3.4", "server_port": 443, "password": "pw", "tls": {"enabled": True, "server_name": "example.com"}}]
        cfg_128 = build_full_dae_config(nodes, ram_mb=128)
        self.assertIn("bpf_conn_state_map_size: 32768", cfg_128)
        cfg_256 = build_full_dae_config(nodes, ram_mb=256)
        self.assertIn("bpf_conn_state_map_size: 65536", cfg_256)

    def test_sub_to_dae_ipv6_bypass_quoted_and_invalid_iface_rejected(self):
        if DAE_SCRIPTS not in sys.path:
            sys.path.insert(0, DAE_SCRIPTS)
        from sub_to_dae import build_full_dae_config
        nodes = [{"type": "trojan", "tag": "T1", "server": "1.2.3.4", "server_port": 443, "password": "pw", "tls": {"enabled": True, "server_name": "example.com"}}]
        cfg_v6 = build_full_dae_config(nodes, topology="bypass", main_router_ip="fd00::1")
        self.assertIn("dip('fd00::1') -> direct", cfg_v6)
        with self.assertRaises(ValueError):
            build_full_dae_config(nodes, lan_iface="br-lan; reboot")

    def test_sub_to_dae_legacy_vs_modern_version_compatibility(self):
        """验证新旧版本 dae 兼容：legacy (<= v1.0.0) 自动剥离 5 个 v2.x 专属字段并通过静态审计；modern 保留全部字段。"""
        import tempfile
        from unittest import mock
        if DAE_SCRIPTS not in sys.path:
            sys.path.insert(0, DAE_SCRIPTS)
        from sub_to_dae import (
            MODERN_ONLY_DAE_KEYS,
            build_full_dae_config,
            dae_version_ge,
            detect_remote_dae_version,
        )
        from check_dae_syntax import check_dae_syntax

        self.assertFalse(dae_version_ge("0.8.0", 1, 1))
        self.assertFalse(dae_version_ge("v1.0.0-r1", 1, 1))
        self.assertTrue(dae_version_ge("v1.1.0", 1, 1))
        self.assertTrue(dae_version_ge("2.1.1", 1, 1))

        nodes = [{"type": "trojan", "tag": "T1", "server": "1.2.3.4", "server_port": 443, "password": "pw", "tls": {"enabled": True, "server_name": "example.com"}}]
        cfg_modern = build_full_dae_config(nodes, dae_version="modern")
        cfg_legacy = build_full_dae_config(nodes, dae_version="legacy")

        for k in MODERN_ONLY_DAE_KEYS:
            self.assertIn(f"{k}:", cfg_modern)
            self.assertNotIn(f"{k}:", cfg_legacy)

        with tempfile.NamedTemporaryFile("w", suffix=".dae", delete=False, encoding="utf-8") as tf:
            tf.write(cfg_legacy)
            p_leg = tf.name
        try:
            errs, warns = check_dae_syntax(p_leg)
            self.assertEqual(errs, [], f"legacy 模式配置不应产生审计错误: {errs}")
            self.assertEqual(warns, [], f"legacy 模式配置不应产生审计警告: {warns}")
        finally:
            if os.path.exists(p_leg):
                os.remove(p_leg)

        with mock.patch("sub_to_dae.subprocess.run") as m_run:
            m_run.return_value = mock.Mock(stdout="dae version 1.0.0-r1\n", stderr="", returncode=0)
            mode, raw = detect_remote_dae_version("192.168.1.1")
            self.assertEqual(mode, "legacy")
            self.assertIn("1.0.0-r1", raw)

            m_run.return_value = mock.Mock(stdout="dae version v2.1.1\n", stderr="", returncode=0)
            mode2, raw2 = detect_remote_dae_version("192.168.1.1")
            self.assertEqual(mode2, "modern")
            self.assertIn("v2.1.1", raw2)

            # 验证包含 GLIBC_2.34 或 IP 的非版本错误输出不会被误判为合法 dae 版本
            m_run.return_value = mock.Mock(stdout="sh: /usr/bin/dae: libc.so.6: version `GLIBC_2.34' not found\n", stderr="", returncode=1)
            mode3, _ = detect_remote_dae_version("192.168.1.1")
            self.assertEqual(mode3, "modern")


if __name__ == "__main__":
    unittest.main()
