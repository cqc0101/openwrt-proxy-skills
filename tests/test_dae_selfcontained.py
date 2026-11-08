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
                           capture_output=True, text=True, env=env, cwd=DAE_SCRIPTS)
        self.assertEqual(r.returncode, 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}")
        self.assertIn("SELF_CONTAINED_OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
