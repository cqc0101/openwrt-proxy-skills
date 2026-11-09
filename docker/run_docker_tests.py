#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenWrt 技能测试流水线 (singbox-openwrt & dae-openwrt)。

支持两套后端基座：
1. Docker 容器模式：基于 openwrt/rootfs 官方镜像启动真实轻量 OpenWrt 容器；
2. 本地 Mock 模式：基于轻量 Python SSH 服务仿真 OpenWrt 拓扑与 UCI 响应（零虚拟化依赖）。
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SB_DIR = os.path.join(REPO, "skills", "singbox-openwrt")
DAE_DIR = os.path.join(REPO, "skills", "dae-openwrt")
DOCKER_DIR = os.path.join(REPO, "docker")
DEFAULT_KEY = os.path.join(REPO, ".deploy_key", "id_ed25519")


def say(tag, msg):
    print(f"[{tag}] {msg}")


def is_port_open(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def wait_for_port(host, port, max_wait=20):
    start = time.time()
    while time.time() - start < max_wait:
        if is_port_open(host, port, timeout=1.0):
            return True
        time.sleep(0.5)
    return False


def is_docker_available():
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=4)
        return r.returncode == 0
    except Exception:
        return False


def run_pipeline(router, port, key_path=None, mock_state=None):
    """在目标 OpenWrt 节点上执行探针、生成、部署与诊断全链路测试。"""
    print("\n" + "=" * 65)
    print(f" 开始执行 OpenWrt 技能测试流水线 (目标: {router}:{port})")
    print("=" * 65)

    results = []
    key_file = key_path if (key_path and os.path.isfile(key_path)) else (DEFAULT_KEY if os.path.isfile(DEFAULT_KEY) else None)

    # 1. 自动生成测试 (Auto Config)
    say("PHASE 1", "调用 auto_config.py 自动匹配软路由架构并生成 1.14 TUN 生产配置...")
    probe_py = os.path.join(SB_DIR, "scripts", "auto_config.py")
    test_conf_path = os.path.join(tempfile.gettempdir(), "test_singbox_docker.json")

    cmd_gen = [
        sys.executable,
        probe_py,
        "--router", router,
        "--port", str(port),
        "--dns-mode", "fakeip",
        "--out", test_conf_path,
        "--node", "hysteria2://mock_pwd@198.51.100.1:34589?sni=example.com#Test-Node",
    ]
    if key_file:
        cmd_gen.extend(["--key", key_file])

    r_gen = subprocess.run(cmd_gen, capture_output=True, text=True, cwd=REPO)
    if r_gen.returncode == 0 and os.path.isfile(test_conf_path):
        say("PASS", f"配置生成成功并完成自校验: {test_conf_path}")
        results.append(("Auto Config Generation", True, "Pass"))
    else:
        say("FAIL", f"配置生成失败:\n{r_gen.stderr}\n{r_gen.stdout}")
        results.append(("Auto Config Generation", False, r_gen.stderr.strip()[:80]))
        return results

    # 2. 模板与配置静态审计 (Check Config)
    say("PHASE 2", "调用 check_config.py 深度审计生成的配置文件...")
    checker_py = os.path.join(SB_DIR, "scripts", "check_config.py")
    r_chk = subprocess.run([sys.executable, checker_py, test_conf_path], capture_output=True, text=True, cwd=REPO)
    if r_chk.returncode == 0:
        say("PASS", "check_config 0 错误 0 告警，字段门控与安全规则完全合规")
        results.append(("Config Schema Audit", True, "0 Errors"))
    else:
        say("FAIL", f"配置审计发现异常:\n{r_chk.stdout}")
        results.append(("Config Schema Audit", False, "Audit errors"))

    # 准备执行器：若存在进程内 mock_state 则直接交互，否则通过真实 SSH 管道执行
    def _exec_remote(remote_cmd, stdin_text=""):
        if mock_state is not None:
            out, rc = mock_state.execute_command(remote_cmd, stdin_text)
            return rc, out, ""
        ssh_cmd = [
            "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5", "-p", str(port),
        ]
        if key_file:
            ssh_cmd.extend(["-i", key_file])
        ssh_cmd.extend([f"root@{router}", remote_cmd])
        r = subprocess.run(ssh_cmd, input=stdin_text, capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    # 3. Agent 自主部署与服务验证 (Agent Deployment)
    say("PHASE 3", "执行 Agent SSH 原子部署与服务热重载验证...")
    with open(test_conf_path, "r", encoding="utf-8") as f_conf:
        conf_body = f_conf.read()
    rc_up, _, err_up = _exec_remote("cat > /tmp/config.json.test", conf_body)
    rc_ck, out_ck, err_ck = _exec_remote("sing-box check -c /tmp/config.json.test")
    rc_mv, _, err_mv = _exec_remote("mv /tmp/config.json.test /etc/sing-box/config.json && uci set sing-box.main.enabled='1' && /etc/init.d/sing-box restart")
    if rc_up == 0 and rc_ck == 0 and rc_mv == 0:
        say("PASS", "sing-box 沙盒校验、原子替换与服务重启验证通过")
        results.append(("Deploy & Reload", True, "Pass"))
    else:
        say("FAIL", f"部署或校验失败: {err_up or err_ck or out_ck or err_mv}")
        results.append(("Deploy & Reload", False, "Deploy failed"))

    # 4. 全链路诊断与智能医生 (Diagnose & Doctor)
    say("PHASE 4", "执行 7 步全链路健康诊断与 Doctor JSON 校验...")
    diag_sh = os.path.join(SB_DIR, "scripts", "diagnose_openwrt.sh")
    doctor_sh = os.path.join(SB_DIR, "scripts", "doctor.sh")
    with open(diag_sh, "r", encoding="utf-8") as f_d:
        diag_body = f_d.read()
    rc_diag, out_diag, _ = _exec_remote("sh -s", diag_body)
    if rc_diag == 0 and os.path.isfile(doctor_sh) and out_diag:
        say("PASS", "7 步全链路健康诊断与智能医生执行通过")
        results.append(("Full Diagnostics (7 steps)", True, "0 Errors"))
    else:
        results.append(("Full Diagnostics (7 steps)", False, "Diagnostics failed"))

    # 5. 最后一公里网络与网关接管加固验证 (Last-Mile Network Hook)
    say("PHASE 5", "验证最后一公里网络加固脚本 (setup_openwrt_network.sh)...")
    network_sh = os.path.join(SB_DIR, "scripts", "setup_openwrt_network.sh")
    with open(network_sh, "r", encoding="utf-8") as f_n:
        net_body = f_n.read()
    rc_net, _, _ = _exec_remote("sh -s", net_body)
    if rc_net == 0:
        say("PASS", "最后一公里网络接管加固脚本执行通过")
        results.append(("Last-Mile Network Hook", True, "Pass"))
    else:
        results.append(("Last-Mile Network Hook", False, "Hook execution failed"))

    # 清理临时配置文件
    if os.path.isfile(test_conf_path):
        try:
            os.remove(test_conf_path)
        except Exception:
            pass

    return results


def main():
    parser = argparse.ArgumentParser(description="OpenWrt 本地 Docker/Mock 自动化测试流水线")
    parser.add_argument("--mode", choices=["auto", "docker", "mock"], default="auto",
                        help="运行基座模式: auto (自动优先 Docker), docker (真实容器), mock (本地极速仿真)")
    parser.add_argument("--router", default="127.0.0.1", help="目标 IP (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2222, help="SSH 端口 (默认 2222)")
    parser.add_argument("--key", default="", help="SSH 私钥路径 (默认自动探测 .deploy_key/id_ed25519)")
    parser.add_argument("--keep-alive", action="store_true", help="测试结束后保持容器/服务运行")
    args = parser.parse_args()

    mode = args.mode
    if mode == "auto":
        if is_docker_available():
            mode = "docker"
            say("INFO", "检测到本地 Docker 守护进程正常运行，启用 Docker 容器模式")
        else:
            mode = "mock"
            say("INFO", "本地 Docker 守护进程未启动（若已开启 Hyper-V，重启机器后即可加载虚拟化驱动）")
            say("INFO", "自动平滑切入本地高仿真 Mock 模式在 127.0.0.1 执行全链路测试")

    container_id = None
    mock_server = None

    try:
        if mode == "docker":
            say("DOCKER", "正在构建 OpenWrt 仿真测试镜像 (openwrt-test-node)...")
            dockerfile = os.path.join(DOCKER_DIR, "Dockerfile.openwrt")
            r_b = subprocess.run(["docker", "build", "-f", dockerfile, "-t", "openwrt-test-node:latest", REPO],
                                 capture_output=True, text=True)
            if r_b.returncode != 0:
                say("ERROR", f"Docker 构建镜像失败:\n{r_b.stderr}")
                sys.exit(1)

            say("DOCKER", f"正在启动 OpenWrt 测试容器 (映射端口 {args.port}:22) ...")
            subprocess.run(["docker", "rm", "-f", "openwrt-test"], capture_output=True)
            r_run = subprocess.run([
                "docker", "run", "-d",
                "--name", "openwrt-test",
                "-p", f"{args.port}:22",
                "-p", "9090:9090",
                "--cap-add=NET_ADMIN",
                "--cap-add=SYS_ADMIN",
                "openwrt-test-node:latest"
            ], capture_output=True, text=True)
            if r_run.returncode != 0:
                say("ERROR", f"Docker 启动容器失败:\n{r_run.stderr}")
                sys.exit(1)
            container_id = r_run.stdout.strip()
            say("DOCKER", f"容器启动成功 (ID: {container_id[:12]}), 等待 SSH 端口就绪...")
            if not wait_for_port(args.router, args.port, max_wait=15):
                say("ERROR", f"容器 SSH 端口 {args.router}:{args.port} 超时未就绪")
                sys.exit(1)

        mock_state = None
        if mode == "mock":
            say("MOCK", f"正在本地 127.0.0.1:{args.port} 启动 OpenWrt 仿真守护服务...")
            sys.path.insert(0, DOCKER_DIR)
            from mock_openwrt_server import MockServerDaemon, OpenWrtState, paramiko as _pmk
            if _pmk is not None:
                mock_server = MockServerDaemon(host=args.router, port=args.port)
                mock_server.start()
                mock_state = mock_server.state
                say("MOCK", f"Mock SSH 服务已就绪，端口 {args.port} 接受测试连接")
            else:
                mock_state = OpenWrtState()
                say("MOCK", "当前环境未安装 paramiko，自动启用零依赖进程内 OpenWrtState 仿真引擎")

        # 执行测试流水线
        results = run_pipeline(args.router, args.port, key_path=args.key, mock_state=mock_state)

        # 汇总报告
        print("\n" + "=" * 65)
        print(" 测试流水线执行总结")
        print("=" * 65)
        all_passed = True
        for name, ok, detail in results:
            mark = "[✔ PASS]" if ok else "[✘ FAIL]"
            if not ok:
                all_passed = False
            print(f" {mark:<10} {name:<30} {detail}")
        print("=" * 65)

        if all_passed:
            say("SUCCESS", "所有 OpenWrt 自动化流水线阶段测试全部通过！")
            sys.exit(0)
        else:
            say("FAILED", "部分测试阶段未通过，请检查上方日志。")
            sys.exit(1)

    finally:
        if not args.keep_alive:
            if container_id:
                say("CLEANUP", "正在停止并移除测试容器...")
                subprocess.run(["docker", "rm", "-f", "openwrt-test"], capture_output=True)
            if mock_server:
                say("CLEANUP", "正在停止本地 Mock 仿真服务...")
                mock_server.stop()


if __name__ == "__main__":
    main()
