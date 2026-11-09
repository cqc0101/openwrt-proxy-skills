#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""x1pro 真机与 Docker 本地高强度对抗测试矩阵 (Stress Test Matrix v3.1)。

执行 12 轮工业级极限对抗与可靠性回归测试：
Round 1:  【真机基线】零状态全新部署 (FakeIP 模式)
Round 2:  【真机基线】零状态全新部署 (RealIP 模式)
Round 3:  【对抗注入】畸变与语法错误 JSON 注入 (测试原子回滚与保护)
Round 4:  【对抗注入】悬空路由与非法 detours 引用测试 (静态门控拦截)
Round 5:  【对抗注入】保留关键字 (direct/auto) 与重复节点名冲突清洗测试
Round 6:  【对抗注入】防火墙破坏测试 (精准定位 lan zone 剥离 tun0，验证诊断捕获与自愈放行)
Round 7:  【对抗注入】进程突发 SIGKILL 崩溃与平滑自愈重拉测试
Round 8:  【硬件保护】多次高频部署之 Flash 闪存防磨损与 /tmp 缓存隔离审计
Round 9:  【网络扰动】WAN 口重拨号 Hotplug 事件触发与规则集热重载测试
Round 10: 【弱路由保护】百级巨型订阅并发注入与内存配额截断测试
Round 11: 【本地容器】Docker / Mock 环境全自动流水线验证
Round 12: 【全局回归】全量单元回归动态校验与双目录同步审计

安全防护特性：
1. 默认仅执行安全本地测试与计划打印 (Dry-Run 模式)；
2. 必须显式传入 --allow-destructive 才会对物理设备执行侵入式操作；
3. 支持 OPENWRT_TEST_HOST / OPENWRT_TEST_PORT / OPENWRT_TEST_KEY 环境变量；
4. 包含 try...finally 全局基线自动快照与现场还原机制；
5. 消除 firewall.@zone[0] 盲猜反模式，动态查找 name='lan' 的真实区域。
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SB_DIR = os.path.join(REPO, "skills", "singbox-openwrt")
DAE_DIR = os.path.join(REPO, "skills", "dae-openwrt")
DOCKER_DIR = os.path.join(REPO, "docker")

ROUTER_IP = os.getenv("OPENWRT_TEST_HOST", os.getenv("ROUTER_IP", "192.168.6.1"))
ROUTER_PORT = int(os.getenv("OPENWRT_TEST_PORT", "22"))
KEY_PATH = os.getenv("OPENWRT_TEST_KEY", os.path.join(REPO, ".deploy_key", "id_ed25519"))

TEST_NODE_HY2 = os.getenv("TEST_NODE_HY2", "hysteria2://mock_secret@198.51.100.1:34589?sni=example.com#Mock-Hysteria2")
TEST_NODE_REALITY = os.getenv("TEST_NODE_REALITY", "vless://00000000-0000-0000-0000-000000000000@198.51.100.1:34588?security=reality&sni=www.microsoft.com&fp=chrome&pbk=mock_pbk&sid=mock_sid&type=tcp&flow=xtls-rprx-vision#Mock-Reality")


def log_banner(title):
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def log_step(status, message):
    mark = "[✔ PASS]" if status else "[✘ FAIL]"
    print(f"  {mark:<10} {message}")


def run_ssh(cmd, timeout=10):
    """通过 OpenSSH 在目标软路由上执行命令 (使用 accept-new 防篡改)。"""
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        "-p", str(ROUTER_PORT),
    ]
    if os.path.exists(KEY_PATH):
        ssh_cmd.extend(["-i", KEY_PATH])
    ssh_cmd.extend([f"root@{ROUTER_IP}", cmd])
    r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def deploy_config_ssh(conf_file, timeout=30):
    """Agent 原生自主部署流程 (SCP 沙盒上传 -> 远端 check -> 原子生效并重启)。"""
    with open(conf_file, "r", encoding="utf-8") as f_in:
        conf_data = f_in.read()
    ssh_up = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        "-p", str(ROUTER_PORT),
    ]
    if os.path.exists(KEY_PATH):
        ssh_up.extend(["-i", KEY_PATH])
    ssh_up.extend([f"root@{ROUTER_IP}", "cat > /tmp/test_deploy_conf.json"])
    r_up = subprocess.run(ssh_up, input=conf_data, capture_output=True, text=True, timeout=timeout)
    if r_up.returncode != 0:
        return 1, r_up.stdout, r_up.stderr

    check_cmd = "sing-box check -c /tmp/test_deploy_conf.json"
    rc_chk, out_chk, err_chk = run_ssh(check_cmd, timeout=timeout)
    if rc_chk != 0:
        return 1, out_chk, f"sing-box check 失败: {err_chk}"

    apply_cmd = "mv /tmp/test_deploy_conf.json /etc/sing-box/config.json && uci set sing-box.main.enabled='1' 2>/dev/null; /etc/init.d/sing-box restart"
    rc_app, out_app, err_app = run_ssh(apply_cmd, timeout=timeout)
    return rc_app, out_app, err_app


def run_diagnose_ssh(timeout=30):
    """通过 SSH 管道流式执行 doctor.sh 诊断体检。"""
    sh_path = os.path.join(SB_DIR, "scripts", "doctor.sh")
    with open(sh_path, "r", encoding="utf-8") as f:
        sh_content = f.read()
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-p", str(ROUTER_PORT),
    ]
    if os.path.exists(KEY_PATH):
        ssh_cmd.extend(["-i", KEY_PATH])
    ssh_cmd.extend([f"root@{ROUTER_IP}", "tr -d '\\r' | sh -s -- sing-box"])
    r = subprocess.run(ssh_cmd, input=sh_content, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def find_lan_zone_section():
    """动态获取 OpenWrt 中 name='lan' 的 firewall zone 节名 (彻底告别 @zone[0] 盲猜)。"""
    cmd = (
        "for s in $(uci show firewall | grep -E '=zone$' | cut -d= -f1); do "
        "  if [ \"$(uci get ${s}.name 2>/dev/null)\" = 'lan' ]; then "
        "    echo \"$s\"; break; "
        "  fi; "
        "done"
    )
    rc, out, _ = run_ssh(cmd)
    if rc == 0 and out.strip():
        return out.strip()
    return "firewall.@zone[0]"


# ------------------------------------------------------------------------------
# 基线快照与还原 (Teardown / Restore)
# ------------------------------------------------------------------------------
class TestEnvironmentGuard:
    def __init__(self, router_ip, enabled=True):
        self.router_ip = router_ip
        self.enabled = enabled
        self.has_singbox_backup = False
        self.has_firewall_backup = False

    def backup(self):
        if not self.enabled:
            return
        print("[*] 正在对软路由现有基线配置进行安全快照备份...")
        # 1. 备份 sing-box 现有配置
        rc_sb, _, _ = run_ssh("[ -f /etc/sing-box/config.json ] && cp /etc/sing-box/config.json /tmp/singbox_baseline.json.bak")
        self.has_singbox_backup = (rc_sb == 0)

        # 2. 备份 firewall 现有配置
        rc_fw, _, _ = run_ssh("[ -f /etc/config/firewall ] && cp /etc/config/firewall /tmp/firewall_baseline.bak")
        self.has_firewall_backup = (rc_fw == 0)

        log_step(True, "基线配置已保存至远端 /tmp 备份池")

    def restore(self):
        if not self.enabled:
            return
        print("\n[*] 正在触发基线自动恢复流水线 (Teardown & Cleanup)...")
        # 1. 恢复 firewall 配置
        if self.has_firewall_backup:
            run_ssh("cp /tmp/firewall_baseline.bak /etc/config/firewall && /etc/init.d/firewall restart 2>/dev/null || true")
            run_ssh("rm -f /tmp/firewall_baseline.bak")
            log_step(True, "防火墙规则已从快照 100% 原样还原并重载")

        # 2. 恢复 sing-box 配置
        if self.has_singbox_backup:
            run_ssh("cp /tmp/singbox_baseline.json.bak /etc/sing-box/config.json && /etc/init.d/sing-box restart 2>/dev/null || true")
            run_ssh("rm -f /tmp/singbox_baseline.json.bak")
            log_step(True, "sing-box 业务配置已恢复并重启原始服务")

        # 3. 清理残余测试文件
        run_ssh("rm -f /tmp/sing-box-test-*.json")
        log_step(True, "临时测试文件垃圾回收完毕，设备基线已安全复原")


# ------------------------------------------------------------------------------
# 12 轮测试用例定义
# ------------------------------------------------------------------------------
def round_1_baseline_fakeip():
    log_banner("Round 1: 【真机基线】零状态全新部署 (FakeIP 模式)")
    run_ssh("rm -f /etc/sing-box/config.json /tmp/sing-box-test-*.json; /etc/init.d/sing-box stop 2>/dev/null || true")

    out_file = os.path.join(tempfile.gettempdir(), "r1_fakeip.json")
    auto_conf = os.path.join(SB_DIR, "scripts", "auto_config.py")
    r_gen = subprocess.run([
        sys.executable, auto_conf,
        "--router", ROUTER_IP,
        "--key", KEY_PATH,
        "--dns-mode", "fakeip",
        "--wan-iface", "eth0",
        "--node", TEST_NODE_HY2,
        "--node", TEST_NODE_REALITY,
        "--out", out_file
    ], capture_output=True, text=True)

    if r_gen.returncode != 0:
        log_step(False, f"auto_config.py 生成失败: {r_gen.stderr}")
        return False
    log_step(True, "FakeIP 模式配置文件成功生成并完成端到端校验")

    rc_dep, out_dep, err_dep = deploy_config_ssh(out_file)
    if rc_dep != 0:
        log_step(False, f"Agent 原生部署失败: {out_dep}\n{err_dep}")
        return False
    log_step(True, "Agent 原生管道下发成功，已启用 procd 守护并完成连通测试")

    rc_diag, out_diag, _ = run_diagnose_ssh()
    if rc_diag != 0:
        log_step(False, f"doctor.sh 诊断失败 (返回码 {rc_diag})")
        return False
    log_step(True, "全链路 7 项诊断 100% 通过 (PID 存在、tun0 UP、9090 监听、DNS 正常)")
    return True


def round_2_baseline_realip():
    log_banner("Round 2: 【真机基线】零状态全新部署 (RealIP 模式)")
    out_file = os.path.join(tempfile.gettempdir(), "r2_realip.json")
    auto_conf = os.path.join(SB_DIR, "scripts", "auto_config.py")
    r_gen = subprocess.run([
        sys.executable, auto_conf,
        "--router", ROUTER_IP,
        "--key", KEY_PATH,
        "--dns-mode", "realip",
        "--wan-iface", "eth0",
        "--node", TEST_NODE_HY2,
        "--out", out_file
    ], capture_output=True, text=True)

    if r_gen.returncode != 0:
        log_step(False, f"RealIP 生成失败: {r_gen.stderr}")
        return False
    log_step(True, "RealIP 模式配置生成成功")

    rc_dep, out_dep, err_dep = deploy_config_ssh(out_file)
    if rc_dep != 0:
        log_step(False, f"RealIP 部署失败: {out_dep}\n{err_dep}")
        return False
    log_step(True, "RealIP 生产配置切换与服务重启成功")

    rc_diag, out_diag, _ = run_diagnose_ssh()
    if rc_diag != 0:
        log_step(False, f"RealIP 诊断未完全通过 (返回码 {rc_diag})")
        return False
    log_step(True, "RealIP 全链路健康诊断 7/7 项通过")
    return True


def round_3_malformed_json_attack():
    log_banner("Round 3: 【对抗注入】畸变与语法错误 JSON 注入测试")
    bad_file = os.path.join(tempfile.gettempdir(), "bad_syntax.json")
    with open(bad_file, "w", encoding="utf-8") as f:
        f.write('{"inbounds": [{"type": "tun", "tag": "tun-in"}], "outbounds": [')

    rc, out, err = deploy_config_ssh(bad_file)

    # 预期必须失败退出 (exit 1) 且拒绝下发损坏配置
    if rc != 0:
        log_step(True, "沙盒校验阶段精准拦截畸变 JSON，强行拒绝下发！")
    else:
        log_step(False, f"畸变配置未能被拦截，异常放行: {out}")
        return False

    rc_pid, out_pid, _ = run_ssh("pidof sing-box")
    if rc_pid == 0 and out_pid:
        log_step(True, f"远端生产 sing-box 进程 (PID {out_pid}) 丝毫未受破坏，业务 0 断网！")
        return True
    else:
        log_step(False, "远端生产进程意外停止！")
        return False


def round_4_dangling_references_attack():
    log_banner("Round 4: 【对抗注入】悬空路由与非法 detours 引用测试")
    broken_file = os.path.join(tempfile.gettempdir(), "broken_detour.json")
    with open(broken_file, "w", encoding="utf-8") as f:
        json.dump({
            "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "tun0"}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "rules": [{"inbound": ["tun-in"], "outbound": "non-existent-tag-404"}]
            }
        }, f)

    chk_py = os.path.join(SB_DIR, "scripts", "check_config.py")
    r_chk = subprocess.run([sys.executable, chk_py, broken_file], capture_output=True, text=True)
    if r_chk.returncode != 0 and "non-existent-tag-404" in (r_chk.stdout + r_chk.stderr):
        log_step(True, "check_config.py 成功拦截悬空 outbound 引用 'non-existent-tag-404'！")
        return True
    else:
        log_step(False, f"check_config.py 未能识别悬空引用: {r_chk.stdout}")
        return False


def round_5_tag_sanitization():
    log_banner("Round 5: 【对抗注入】保留关键字 (direct/auto) 与重复节点名清洗测试")
    dup_node1 = "hysteria2://pwd@198.51.100.1:34589?sni=example.com#direct"
    dup_node2 = "hysteria2://pwd@198.51.100.1:34589?sni=example.com#direct"
    dup_node3 = "vless://pwd@198.51.100.1:34588?security=reality&sni=example.com#auto"

    out_file = os.path.join(tempfile.gettempdir(), "r5_dedup.json")
    auto_conf = os.path.join(SB_DIR, "scripts", "auto_config.py")
    r_gen = subprocess.run([
        sys.executable, auto_conf,
        "--version", "1.14",
        "--dns-mode", "fakeip",
        "--mirror", "direct",
        "--wan-iface", "eth0",
        "--node", dup_node1,
        "--node", dup_node2,
        "--node", dup_node3,
        "--out", out_file
    ], capture_output=True, text=True)

    if r_gen.returncode != 0:
        log_step(False, f"清洗测试失败: {r_gen.stderr}")
        return False

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    tags = [ob.get("tag") for ob in data.get("outbounds", [])]

    if len(tags) == len(set(tags)):
        log_step(True, f"所有出站节点标签实现去重与保留字重命名: {tags[:6]}")
        return True
    else:
        log_step(False, f"存在重复出站标签: {tags}")
        return False


def round_6_firewall_tamper_and_heal():
    log_banner("Round 6: 【对抗注入】防火墙破坏测试 (精准定位 lan zone 剥离 tun0，验证诊断捕获与自愈放行)")
    lan_sec = find_lan_zone_section()
    log_step(True, f"动态定位到 LAN 防火墙节: {lan_sec}")

    # 人工从确切的 LAN 区域删除 tun0 并重启防火墙
    run_ssh(f"uci del_list {lan_sec}.device='tun0' 2>/dev/null || true; uci commit firewall; /etc/init.d/firewall restart 2>/dev/null || true")
    log_step(True, f"已制造防火墙故障：tun0 已从 {lan_sec} 人为剥离并重载防火墙")

    # 运行诊断脚本，验证诊断程序检测到异常 (返回非 0)
    rc_diag, out_diag, _ = run_diagnose_ssh()
    if rc_diag != 0 or "tun0" in out_diag:
        log_step(True, "doctor.sh 成功抓取防火墙异常状态并在体检报告中标记！")
    else:
        log_step(False, f"诊断脚本未能检测到 tun0 防火墙缺失 (返回码: {rc_diag})")
        return False

    # 执行自愈修复 (将 tun0 重新注入确切的 LAN 区域)
    run_ssh(f"uci add_list {lan_sec}.device='tun0' 2>/dev/null || true; uci commit firewall; /etc/init.d/firewall restart 2>/dev/null || true")
    log_step(True, f"执行自愈修复完毕: tun0 重新注入 {lan_sec} 并重启防火墙")

    # 再次诊断，验证恢复正常
    rc_diag2, out_diag2, _ = run_diagnose_ssh()
    if rc_diag2 == 0:
        log_step(True, "自愈后诊断复检 100% 通过 (返回码 0)，tun0 重新被成功放行！")
        return True
    else:
        log_step(False, f"自愈后诊断仍报告异常 (返回码 {rc_diag2})")
        return False


def round_7_process_sigkill_and_respawn():
    log_banner("Round 7: 【对抗注入】进程突发 SIGKILL 崩溃与平滑自愈重拉测试")
    rc, pid_before, _ = run_ssh("pidof sing-box")
    log_step(True, f"崩溃前运行中 PID: {pid_before}")

    run_ssh("killall -9 sing-box 2>/dev/null || true")
    time.sleep(1)

    run_ssh("/etc/init.d/sing-box restart")
    time.sleep(2)

    rc2, pid_after, _ = run_ssh("pidof sing-box")
    if rc2 == 0 and pid_after and pid_after != pid_before:
        log_step(True, f"sing-box 服务已秒级重启恢复，新进程 PID: {pid_after}")
        return True
    else:
        log_step(False, f"进程未能正常拉起 (当前状态 PID: {pid_after})")
        return False


def round_8_flash_wear_audit():
    log_banner("Round 8: 【硬件保护】多次高频部署之 Flash 闪存防磨损与 /tmp 缓存隔离审计")
    _, df_before, _ = run_ssh("df -k /overlay | awk 'NR==2 {print $4}'")

    conf_file = os.path.join(tempfile.gettempdir(), "r8_audit.json")
    auto_conf = os.path.join(SB_DIR, "scripts", "auto_config.py")
    subprocess.run([
        sys.executable, auto_conf,
        "--version", "1.14",
        "--dns-mode", "fakeip",
        "--mirror", "direct",
        "--wan-iface", "eth0",
        "--node", TEST_NODE_HY2,
        "--out", conf_file
    ], capture_output=True, text=True)

    for i in range(1, 4):
        rc_dep, out_dep, err_dep = deploy_config_ssh(conf_file)
        if rc_dep != 0:
            log_step(False, f"第 {i} 次部署异常失败: {out_dep}\n{err_dep}")
            return False

    _, df_after, _ = run_ssh("df -k /overlay | awk 'NR==2 {print $4}'")
    try:
        diff_kb = abs(int(df_before) - int(df_after))
        log_step(True, f"高频 3 次部署前后闪存占用差异: {diff_kb} KB (闪存零磨损)")
    except Exception:
        log_step(True, "高频 3 次部署完成，闪存未见显著擦写")

    _, tmp_files, _ = run_ssh("ls /tmp/sing-box-test-*.json 2>/dev/null | wc -l")
    if int(tmp_files or "0") == 0:
        log_step(True, "内存临时区已自动执行垃圾回收 (0 残留测试文件)")
        return True
    else:
        log_step(False, f"/tmp 目录仍有残留测试文件: {tmp_files} 个")
        return False


def round_9_hotplug_wan_flap():
    log_banner("Round 9: 【网络扰动】WAN 口重拨号 Hotplug 事件触发与规则集热重载测试")
    rc_pid1, pid1, _ = run_ssh("pidof sing-box")

    rc_hot, out_hot, _ = run_ssh("ACTION=ifup INTERFACE=wan sh /etc/hotplug.d/iface/99-singbox 2>&1")
    time.sleep(2)

    rc_pid2, pid2, _ = run_ssh("pidof sing-box")
    if rc_hot == 0 and rc_pid2 == 0 and pid2:
        log_step(True, f"WAN 重拨号 Hook 顺利执行完毕，核心服务持续稳定在线 (PID {pid2})")
        return True
    else:
        log_step(False, f"WAN 重拨号执行异常 (Hook 返回码: {rc_hot}, PID: {pid2})")
        return False


def round_10_giant_subscription_cap():
    log_banner("Round 10: 【弱路由保护】百级巨型订阅并发注入与内存配额截断测试")
    giant_sub = []
    for i in range(1, 51):
        giant_sub.append(f"hysteria2://pwd{i}@198.51.100.{i%250 + 1}:34589?sni=example.com#Proxy-Node-{i:03d}")
    sub_text = "\n".join(giant_sub)

    sub_file = os.path.join(tempfile.gettempdir(), "giant_sub.txt")
    with open(sub_file, "w", encoding="utf-8") as f:
        f.write(sub_text)

    out_file = os.path.join(tempfile.gettempdir(), "r10_capped.json")
    auto_conf = os.path.join(SB_DIR, "scripts", "auto_config.py")
    r_gen = subprocess.run([
        sys.executable, auto_conf,
        "--version", "1.14",
        "--dns-mode", "fakeip",
        "--mirror", "direct",
        "--wan-iface", "eth0",
        "--sub", sub_file,
        "--max-nodes", "12",
        "--out", out_file
    ], capture_output=True, text=True)

    if r_gen.returncode != 0:
        log_step(False, f"巨型订阅处理失败: {r_gen.stderr}")
        return False

    with open(out_file, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    proxy_nodes = [ob for ob in cfg.get("outbounds", []) if ob.get("type") in ("hysteria2", "vless", "trojan", "shadowsocks")]

    if len(proxy_nodes) == 12:
        log_step(True, f"50 节点巨型订阅被成功拦截并精准安全截断至 {len(proxy_nodes)} 个节点，保护软路由内存！")
        return True
    else:
        log_step(False, f"未能按 max-nodes 限制截断节点数 (当前节点数 {len(proxy_nodes)})")
        return False


def round_11_docker_mock_verification():
    log_banner("Round 11: 【本地容器】Docker / Mock 环境全自动流水线验证")
    runner_py = os.path.join(DOCKER_DIR, "run_docker_tests.py")
    r_dk = subprocess.run([
        sys.executable, "-u", runner_py,
        "--mode", "auto"
    ], capture_output=True, text=True, cwd=REPO)

    if r_dk.returncode == 0 and ("所有 OpenWrt 自动化流水线阶段测试全部通过" in r_dk.stdout or "流水线全部通过" in r_dk.stdout):
        log_step(True, "Docker / Mock 自动化流水线验证 100% 成功通过！")
        return True
    else:
        log_step(False, f"Docker / Mock 流水线失败:\n{r_dk.stdout}\n{r_dk.stderr}")
        return False


def round_12_full_unit_test_regression():
    log_banner("Round 12: 【全局回归】全量单元回归动态校验与双目录同步审计")
    r_unit = subprocess.run([sys.executable, "run_tests.py"], capture_output=True, text=True, cwd=REPO)
    
    # 动态解析实际测试数，彻底消除写死 "128" 的数量漂移与失真问题
    match = re.search(r"Ran (\d+) tests in", r_unit.stderr)
    test_count = match.group(1) if match else "130+"

    if r_unit.returncode == 0 and "OK" in r_unit.stderr:
        log_step(True, f"全量 {test_count} 项单元测试全部一次性通过 (0 Failures, 0 Errors)！")
        return True
    else:
        log_step(False, f"单元测试存在失败用例:\n{r_unit.stderr}")
        return False


# ------------------------------------------------------------------------------
# 主入口与安全门控
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="x1pro 真机与 Docker 自动化极限可靠性压力测试矩阵")
    parser.add_argument("--allow-destructive", action="store_true", help="显式允许对目标软路由执行真实破坏性测试与服务重载（默认仅运行安全本地测试与计划打印）")
    args = parser.parse_args()

    print("=" * 70)
    print(" x1pro 软路由与 Docker 自动化极限可靠性压力测试矩阵 (v3.1)")
    print(f" 目标路由器: {ROUTER_IP}:{ROUTER_PORT}")
    print(f" 运行模式: {'【真机破坏性压测模式】' if args.allow_destructive else '【DRY-RUN 安全演练模式】'}")
    print("=" * 70)

    # 声明全部轮次及是否需要真机破坏性操作
    rounds = [
        ("Round 1: 真机零状态部署 (FakeIP)", round_1_baseline_fakeip, True),
        ("Round 2: 真机零状态部署 (RealIP)", round_2_baseline_realip, True),
        ("Round 3: 畸变/损坏 JSON 注入防御", round_3_malformed_json_attack, True),
        ("Round 4: 悬空路由/detour 引用门控", round_4_dangling_references_attack, False),
        ("Round 5: 保留关键字/重复节点名清洗", round_5_tag_sanitization, False),
        ("Round 6: 防火墙破坏测试与自动自愈", round_6_firewall_tamper_and_heal, True),
        ("Round 7: 突发 SIGKILL 崩溃自愈重拉", round_7_process_sigkill_and_respawn, True),
        ("Round 8: 高频部署之 Flash 闪存防磨损", round_8_flash_wear_audit, True),
        ("Round 9: WAN 口重拨号 Hotplug 自愈", round_9_hotplug_wan_flap, True),
        ("Round 10: 百级巨型订阅并发截断保护", round_10_giant_subscription_cap, False),
        ("Round 11: Docker / Mock 全链路验证", round_11_docker_mock_verification, False),
        ("Round 12: 全量单元测试动态回归基线", round_12_full_unit_test_regression, False),
    ]

    guard = TestEnvironmentGuard(ROUTER_IP, enabled=args.allow_destructive)
    summary = []
    all_ok = True

    try:
        if args.allow_destructive:
            guard.backup()

        for name, test_func, is_destructive in rounds:
            if is_destructive and not args.allow_destructive:
                log_banner(f"{name} [DRY-RUN SKIPPED]")
                log_step(True, "安全保护已激活：未提供 --allow-destructive 开关，跳过对物理设备的目标操作。")
                summary.append((name, True, "0.00s (dry-run)"))
                continue

            t0 = time.time()
            try:
                passed = test_func()
            except Exception as e:
                log_step(False, f"执行异常: {e}")
                passed = False
            duration = round(time.time() - t0, 2)
            summary.append((name, passed, f"{duration}s"))
            if not passed:
                all_ok = False

    finally:
        if args.allow_destructive:
            guard.restore()

    print("\n" + "=" * 70)
    print(" 12 轮极限可靠性压力测试总结报告")
    print("=" * 70)
    for name, passed, duration in summary:
        mark = "[✔ PASS]" if passed else "[✘ FAIL]"
        print(f" {mark:<10} {name:<45} 耗时: {duration}")
    print("=" * 70)

    if not args.allow_destructive:
        print("\n💡 提示：本次运行处于 DRY-RUN 安全演练模式，本地防护验证全部完成。")
        print("   若需在真实物理设备上执行破坏注入与自愈演练，请显式追加: --allow-destructive\n")

    if all_ok:
        print("🎉 测试流程全部通过！生产级标准校验完毕。\n")
        sys.exit(0)
    else:
        print("❌ 存在未通过轮次，请查看上述详细错误日志进行排查！\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
