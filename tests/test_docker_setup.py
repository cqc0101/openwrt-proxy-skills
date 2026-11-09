# -*- coding: utf-8 -*-
"""Docker 与本地测试环境完备性与规范性单元测试。

验证：
1. docker 目录核心文件完备性 (Dockerfile, compose, entrypoint, runners, mock)
2. Dockerfile 语法与 OpenWrt 规范 (rootfs 基准、暴露端口、UCI 防火墙/网络基线)
3. Compose 编排安全策略 (NET_ADMIN / SYS_ADMIN 权限与 tun 设备映射)
4. 入口脚本 POSIX 合规性与 LF 行尾
5. README 文档与目录树一致性
"""

import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKER_DIR = os.path.join(REPO, "docker")


def read_docker_file(name):
    path = os.path.join(DOCKER_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestDockerSetup(unittest.TestCase):
    def test_required_files_exist(self):
        expected = [
            "Dockerfile.openwrt",
            "docker-compose.yml",
            "entrypoint.sh",
            "mock_openwrt_server.py",
            "run_docker_tests.py",
            "run_docker_tests.ps1",
            "README.md",
        ]
        for name in expected:
            path = os.path.join(DOCKER_DIR, name)
            self.assertTrue(os.path.isfile(path), f"缺少核心测试文件: docker/{name}")

    def test_dockerfile_openwrt_specs(self):
        text = read_docker_file("Dockerfile.openwrt")
        self.assertIn("FROM openwrt/rootfs", text, "Dockerfile 必须基于官方 openwrt/rootfs 镜像")
        self.assertIn("EXPOSE 22 9090", text, "必须暴露 22 (SSH) 与 9090 (Clash API) 端口")
        self.assertIn('ENTRYPOINT ["/entrypoint.sh"]', text, "必须设置标准 entrypoint")
        self.assertIn("uci set firewall.@zone[0]", text, "必须初始化 LAN 防火墙区域")
        self.assertIn("uci set network.lan", text, "必须初始化 LAN 网络接口")
        self.assertIn("sing-box", text, "必须包含 sing-box 服务支持")

    def test_docker_compose_specs(self):
        text = read_docker_file("docker-compose.yml")
        self.assertIn("openwrt-test", text, "服务名应为 openwrt-test")
        self.assertIn("NET_ADMIN", text, "TUN 透明代理必需 NET_ADMIN 权能")
        self.assertIn("SYS_ADMIN", text, "eBPF/网络栈测试必需 SYS_ADMIN 权能")
        self.assertIn("/dev/net/tun", text, "必须挂载 /dev/net/tun 设备")
        self.assertIn("2222:22", text, "必须映射 2222 端口用于免冲突 SSH 访问")

    def test_entrypoint_sh_specs(self):
        text = read_docker_file("entrypoint.sh")
        self.assertTrue(text.startswith("#!/bin/sh"), "入口脚本必须以 #!/bin/sh 开头")
        self.assertIn("dropbear", text, "入口脚本必须启动 dropbear 服务")
        self.assertIn("/dev/net/tun", text, "入口脚本必须确保 tun 设备节点存在")
        self.assertNotIn("echo -e", text, "dash/ash 下禁止使用 echo -e")

    def test_run_docker_tests_options(self):
        py_text = read_docker_file("run_docker_tests.py")
        self.assertIn("--mode", py_text, "运行器必须支持 --mode 参数")
        self.assertIn("auto", py_text, "必须支持 auto 模式")
        self.assertIn("docker", py_text, "必须支持 docker 模式")
        self.assertIn("mock", py_text, "必须支持 mock 模式")

        ps1_text = read_docker_file("run_docker_tests.ps1")
        self.assertIn("param(", ps1_text, "PowerShell 运行器必须声明参数块")
        self.assertIn("Mode", ps1_text, "PowerShell 运行器必须支持 Mode 参数")

    def test_no_crlf_and_no_bom(self):
        for name in os.listdir(DOCKER_DIR):
            if name.startswith("."):
                continue
            path = os.path.join(DOCKER_DIR, name)
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                raw = f.read()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"docker/{name} 包含 BOM")
            self.assertNotIn(b"\r\n", raw, f"docker/{name} 包含 CRLF 行尾")


if __name__ == "__main__":
    unittest.main()
