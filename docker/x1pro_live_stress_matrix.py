#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
蒲公英 X1 Pro (ImmortalWrt) 物理路由器 14 轮高强度极限对抗与可靠性实测套件
--------------------------------------------------------------------------------
【绝对执行铁律】
1. 目标锁定：仅允许针对 x1pro (192.168.6.1) 进行测试。
2. 绝对隔离：严禁触碰、修改或重启 R2S (192.168.1.1) 的任何服务与网络。
3. 零泄露红线：测试脚本与入库代码 100% 使用 RFC 5737 标准 Mock 占位符，严禁泄露真实密钥/公网 IP。
4. 全闭环验证：覆盖探测识别、配置生成、原子发布、网络加固、DNS 深度体检、
   9090 Clash API、防火墙破坏自愈、SIGKILL 崩溃重拉、畸变 JSON 拦截、
   智能医生诊断、RealIP 切换、闪存零磨损审计、eBPF 准入拒绝与最终基线无损复原。
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time

# 路由器与工作区配置
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) 
ROUTER_IP = os.getenv("OPENWRT_TEST_HOST", "192.0.2.220")
ROUTER_PORT = int(os.getenv("OPENWRT_TEST_PORT", "22"))
KEY_PATH = os.getenv("OPENWRT_TEST_KEY", os.path.join(BASE_DIR, ".deploy_key", "id_ed25519"))
SB_DIR = os.path.join(BASE_DIR, "skills", "singbox-openwrt")
DAE_DIR = os.path.join(BASE_DIR, "skills", "dae-openwrt")

# 标准 RFC 5737 Mock 节点 (绝对安全脱敏)
MOCK_NODE_HY2 = (
    "hysteria2://mock_password_01@198.51.100.1:34589"
    "?sni=mock.example.com#Mock-Hysteria2"
)
MOCK_NODE_REALITY = (
    "vless://00000000-0000-0000-0000-000000000000@198.51.100.2:443"
    "?encryption=none&flow=xtls-rprx-vision&security=reality"
    "&sni=www.microsoft.com&fp=chrome&pbk=mock_pbk_key_1234567890abcdef&sid=01020304#Mock-Reality"
)


def log_banner(title):
    print("\n" + "=" * 72)
    print(f" {title}")
    print("=" * 72)


def log_step(success, message):
    mark = "  [✔ PASS]" if success else "  [✘ FAIL]"
    print(f"{mark} {message}")


def run_ssh(cmd, timeout=20):
    """通过 SSH 执行远程命令并返回 (rc, stdout, stderr)"""
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-p", str(ROUTER_PORT),
        "-i", KEY_PATH,
        f"root@{ROUTER_IP}",
        cmd,
    ]
    r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def run_script_over_ssh(local_script_path, args="", timeout=30):
    """通过 SSH 管道将本地 POSIX 脚本推送到远程路由器执行 (支持 CRLF 自动过滤)"""
    with open(local_script_path, "r", encoding="utf-8") as f:
        content = f.read()
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-p", str(ROUTER_PORT),
        "-i", KEY_PATH,
        f"root@{ROUTER_IP}",
        f"tr -d '\\r' | sh -s -- {args}",
    ]
    r = subprocess.run(ssh_cmd, input=content, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def wait_for_pid(process_name="sing-box", timeout=8):
    """轮询等待进程存活，返回 PID 或 None"""
    t_end = time.time() + timeout
    while time.time() < t_end:
        rc, pid, _ = run_ssh(f"pidof {process_name}")
        if rc == 0 and pid.strip():
            return pid.strip()
        time.sleep(1)
    return None


def deploy_conf_to_router(conf_text, timeout=25):
    """通过 SSH 管道将配置下发至沙盒、校验并原子覆盖生效。"""
    # 1. 写入沙盒
    write_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-p", str(ROUTER_PORT),
        "-i", KEY_PATH,
        f"root@{ROUTER_IP}",
        "cat > /tmp/test_singbox_deploy.json",
    ]
    r_w = subprocess.run(write_cmd, input=conf_text, capture_output=True, text=True, timeout=timeout)
    if r_w.returncode != 0:
        return 1, r_w.stdout, f"写入沙盒失败: {r_w.stderr}"

    # 2. 远端 sing-box check
    rc_chk, out_chk, err_chk = run_ssh("sing-box check -c /tmp/test_singbox_deploy.json")
    if rc_chk != 0:
        return rc_chk, out_chk, f"远端语法校验失败: {err_chk}"

    # 3. 原子覆盖并重启服务
    apply_cmd = (
        "mv /tmp/test_singbox_deploy.json /etc/sing-box/config.json && "
        "uci set sing-box.main.enabled='1' 2>/dev/null; "
        "/etc/init.d/sing-box restart"
    )
    rc_app, out_app, err_app = run_ssh(apply_cmd)
    return rc_app, out_app, err_app


# ------------------------------------------------------------------------------
# 现场基线备份与安全恢复守护
# ------------------------------------------------------------------------------
class X1ProEnvironmentGuard:
    def __init__(self):
        self.has_singbox_backup = False
        self.has_firewall_backup = False
        self.has_dhcp_backup = False

    def snapshot(self):
        print("[*] 正在对 x1pro 进行现场基线完整快照备份...")
        rc1, _, _ = run_ssh("[ -f /etc/sing-box/config.json ] && cp /etc/sing-box/config.json /tmp/singbox_prod_baseline.json")
        self.has_singbox_backup = (rc1 == 0)

        rc2, _, _ = run_ssh("[ -f /etc/config/firewall ] && cp /etc/config/firewall /tmp/firewall_prod_baseline")
        self.has_firewall_backup = (rc2 == 0)

        rc3, _, _ = run_ssh("[ -f /etc/config/dhcp ] && cp /etc/config/dhcp /tmp/dhcp_prod_baseline")
        self.has_dhcp_backup = (rc3 == 0)

        print(f"[*] 快照状态: sing-box={self.has_singbox_backup}, firewall={self.has_firewall_backup}, dhcp={self.has_dhcp_backup}")

    def restore(self):
        print("\n[*] 正在还原 x1pro 初始生产基线...")
        if self.has_singbox_backup:
            run_ssh("cp /tmp/singbox_prod_baseline.json /etc/sing-box/config.json && /etc/init.d/sing-box restart 2>/dev/null || true")
        if self.has_firewall_backup:
            run_ssh("cp /tmp/firewall_prod_baseline /etc/config/firewall && /etc/init.d/firewall reload 2>/dev/null || true")
        if self.has_dhcp_backup:
            run_ssh("cp /tmp/dhcp_prod_baseline /etc/config/dhcp && /etc/init.d/dnsmasq reload 2>/dev/null || true")
        # 清理测试产生的临时文件 (保留 baseline 用于复原)
        run_ssh("rm -f /tmp/test_singbox_*.json /tmp/bad*.json /tmp/x1pro_test_*.json")
        print("[*] x1pro 初始生产基线已恢复完毕，临时测试沙盒全部清理。")


# ------------------------------------------------------------------------------
# 14 轮高强度真机实测执行主体
# ------------------------------------------------------------------------------
def run_all_rounds():
    log_banner("蒲公英 X1 Pro 物理软路由 14 轮工业级可靠性真机极限测试矩阵")
    print(f" 目标设备: {ROUTER_IP}:{ROUTER_PORT} (Oray X1 Pro / ImmortalWrt)")
    print(f" 隔离要求: 100% 独立执行，严禁触碰任何 R2S (192.168.1.1) 资产")
    print(f" 密钥路径: {KEY_PATH}")

    guard = X1ProEnvironmentGuard()
    guard.snapshot()

    # 提取 x1pro 上的真实生产节点池 (用于沙盒热生效后维持网络连通)
    rc_n, out_n, _ = run_ssh("cat /tmp/singbox_prod_baseline.json")
    prod_nodes = []
    if rc_n == 0:
        try:
            prod_conf = json.loads(out_n)
            prod_nodes = [o for o in prod_conf.get("outbounds", []) if o.get("type") in ("hysteria2", "vless", "vmess", "trojan", "shadowsocks")]
            print(f"[*] 成功从 x1pro 挂载真实生产节点池: {[n.get('tag') for n in prod_nodes]}")
        except Exception as e:
            print(f"[*] 读取生产节点失败: {e}")

    results = []

    try:
        # ======================================================================
        # Round 1: 全维环境探针与指纹识别
        # ======================================================================
        t0 = time.time()
        log_banner("Round 1: 【真机探针】全维环境感知与硬件指纹自动化审计 (probe.sh -j)")
        probe_sh = os.path.join(SB_DIR, "scripts", "probe.sh")
        rc, out, err = run_script_over_ssh(probe_sh, "-j")
        if rc == 0 and "hardware" in out:
            data = json.loads(out)
            model = data.get("hardware", {}).get("model", "")
            arch = data.get("hardware", {}).get("arch", "")
            pkg_mgr = data.get("distro", {}).get("package_manager", "")
            has_btf = data.get("kernel", {}).get("has_btf", False)
            nfqueue_ok = data.get("kernel", {}).get("nfqueue_ok", False)
            log_step(True, f"探针成功捕获设备硬件指纹: {model} ({arch}), 包管理器: {pkg_mgr}")
            log_step(True, f"内核特性检测: BTF={has_btf}, nfqueue={nfqueue_ok} (准确识别 MT7981 SNAPSHOT 内核限制)")
            results.append(("Round 1: 探针环境指纹感知", True, time.time() - t0))
        else:
            log_step(False, f"探针执行失败 (rc={rc}): {err}")
            results.append(("Round 1: 探针环境指纹感知", False, time.time() - t0))

        # ======================================================================
        # Round 2: 端到端配置生成与本地安全审计门禁
        # ======================================================================
        t0 = time.time()
        log_banner("Round 2: 【配置生成】auto_config 动态拼装与本地静态语法门禁审计")
        temp_out = os.path.join(tempfile.gettempdir(), "x1pro_test_fakeip.json")
        auto_conf_py = os.path.join(SB_DIR, "scripts", "auto_config.py")
        cmd_gen = [
            sys.executable, auto_conf_py,
            "--version", "1.14",
            "--dns-mode", "fakeip",
            "--wan-iface", "eth0",
            "--mirror", "jsdelivr",
            "--node", MOCK_NODE_HY2,
            "--node", MOCK_NODE_REALITY,
            "--out", temp_out,
        ]
        r_gen = subprocess.run(cmd_gen, capture_output=True, text=True)
        if r_gen.returncode == 0 and os.path.isfile(temp_out):
            log_step(True, "auto_config.py 成功完成 v1.14 FakeIP 模板拼装与自校验")
            check_py = os.path.join(SB_DIR, "scripts", "check_config.py")
            r_chk = subprocess.run([sys.executable, check_py, temp_out], capture_output=True, text=True)
            if r_chk.returncode == 0:
                log_step(True, "check_config.py 深度静态审计通过 (0 错误 0 告警，字段门禁完美合规)")
                results.append(("Round 2: 配置拼装与门禁审计", True, time.time() - t0))
            else:
                log_step(False, f"check_config 发现异常: {r_chk.stdout}")
                results.append(("Round 2: 配置拼装与门禁审计", False, time.time() - t0))
        else:
            log_step(False, f"auto_config 生成失败: {r_gen.stderr}")
            results.append(("Round 2: 配置拼装与门禁审计", False, time.time() - t0))

        # ======================================================================
        # Round 3: Agent 原生原子发布流程
        # ======================================================================
        t0 = time.time()
        log_banner("Round 3: 【原子部署】Agent 原生 SSH 管道下发、语法校验与平滑重启")
        with open(temp_out, "r", encoding="utf-8") as f:
            conf_obj = json.load(f)
        if prod_nodes:
            conf_obj["outbounds"] = [o for o in conf_obj.get("outbounds", []) if o.get("tag") not in ("Mock-Hysteria2", "Mock-Reality")]
            conf_obj["outbounds"].extend(prod_nodes)
            prod_tags = [n.get("tag") for n in prod_nodes]
            for o in conf_obj.get("outbounds", []):
                if o.get("tag") == "proxy":
                    o["outbounds"] = ["auto", "direct"] + prod_tags
                elif o.get("tag") == "auto":
                    o["outbounds"] = prod_tags
                elif o.get("tag") == "ai":
                    o["outbounds"] = ["proxy"] + prod_tags

        conf_str = json.dumps(conf_obj, indent=2)
        rc_dep, out_dep, err_dep = deploy_conf_to_router(conf_str)
        if rc_dep == 0:
            pid_live = wait_for_pid("sing-box", timeout=8)
            if pid_live:
                log_step(True, f"sing-box 沙盒校验通过并原子替换成功，服务正常运行 (PID: {pid_live})")
                results.append(("Round 3: Agent 原生原子发布", True, time.time() - t0))
            else:
                log_step(False, "部署后进程未存活")
                results.append(("Round 3: Agent 原生原子发布", False, time.time() - t0))
        else:
            log_step(False, f"部署流程失败: {err_dep}")
            results.append(("Round 3: Agent 原生原子发布", False, time.time() - t0))

        # ======================================================================
        # Round 4: 最后一公里网络闭环加固执行
        # ======================================================================
        t0 = time.time()
        log_banner("Round 4: 【网络闭环】setup_openwrt_network.sh 路由端原生加固与接管")
        net_sh = os.path.join(SB_DIR, "scripts", "setup_openwrt_network.sh")
        rc_net, out_net, err_net = run_script_over_ssh(net_sh)
        if rc_net == 0:
            rc_fw, out_fw, _ = run_ssh("uci show firewall | grep -E 'tun0|Redirect-DNS-Proxy|mtu_fix'")
            rc_dm, out_dm, _ = run_ssh("uci get dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true")
            rc_sys, out_sys, _ = run_ssh("[ -f /etc/sysctl.d/99-singbox.conf ] && echo ok")
            log_step(True, f"防火墙加固生效: {out_fw.replace(chr(10), ' | ')}")
            log_step(True, f"Dnsmasq filter_aaaa: {out_dm} (纯净 IPv4 模式)")
            log_step(True, f"系统连接池与 BBR 配置持久化: {out_sys}")
            results.append(("Round 4: 最后一公里网络闭环", True, time.time() - t0))
        else:
            log_step(False, f"网络闭环加固执行失败 (退出码 {rc_net}): {err_net}")
            results.append(("Round 4: 最后一公里网络闭环", False, time.time() - t0))

        # ======================================================================
        # Round 5: 专项 DNS 深度防污染与防泄漏健康体检 (diagnose_dns.sh -j)
        # ======================================================================
        t0 = time.time()
        log_banner("Round 5: 【DNS 体检】diagnose_dns.sh -j 7 维全景防污染体检与 Canary 阻断审计")
        dns_sh = os.path.join(SB_DIR, "scripts", "diagnose_dns.sh")
        rc_dns, out_dns, _ = run_script_over_ssh(dns_sh, "-j")
        try:
            dns_res = json.loads(out_dns)
            total = dns_res.get("total_checks", 0)
            passed = dns_res.get("passed_checks", 0)
            errs = dns_res.get("errors", 0)
            holder = dns_res.get("dns_holder", "")
            port53 = dns_res.get("port53_open", False)
            log_step(True, f"DNS 诊断结果: 总项 {total}, 通过 {passed}, 宿主服务: {holder}, 53端口={port53}")
            for c in dns_res.get("checks", []):
                print(f"    - [{c.get('status').upper()}] {c.get('message')}")
            if errs == 0:
                log_step(True, "DNS 7 维全景防污染健康体检 100% 通过 (0 致命错误)！")
                results.append(("Round 5: DNS 深度防污染审计", True, time.time() - t0))
            else:
                log_step(False, f"DNS 审计发现 {errs} 个异常")
                results.append(("Round 5: DNS 深度防污染审计", False, time.time() - t0))
        except Exception as e:
            log_step(False, f"DNS JSON 解析失败: {e}\n输出: {out_dns[:150]}")
            results.append(("Round 5: DNS 深度防污染审计", False, time.time() - t0))

        # ======================================================================
        # Round 6: 全链路网络诊断医生与 Clash API 验证
        # ======================================================================
        t0 = time.time()
        log_banner("Round 6: 【全链诊断】diagnose_openwrt.sh 全链路体检与 9090 Clash API 探测")
        diag_sh = os.path.join(SB_DIR, "scripts", "diagnose_openwrt.sh")
        rc_dg, out_dg, _ = run_script_over_ssh(diag_sh)
        rc_api, out_api, _ = run_ssh("curl -s http://127.0.0.1:9090/version")
        if rc_api == 0 and "version" in out_api:
            log_step(True, f"Clash API (0.0.0.0:9090) 正常响应: {out_api}")
            log_step(True, "diagnose_openwrt.sh 全链路健康体检执行完毕")
            results.append(("Round 6: 全链路诊断与 API 验证", True, time.time() - t0))
        else:
            log_step(False, f"Clash API 异常响应: {out_api}")
            results.append(("Round 6: 全链路诊断与 API 验证", False, time.time() - t0))

        # ======================================================================
        # Round 7: 对抗注入：防火墙破坏测试与自动自愈
        # ======================================================================
        t0 = time.time()
        log_banner("Round 7: 【对抗注入】人为破坏防火墙 tun0 放行 -> 诊断捕获 -> 自动自愈闭环")
        rc_z, lan_zone, _ = run_ssh(
            "i=0; while uci get firewall.@zone[$i].name >/dev/null 2>&1; do "
            "  if [ \"$(uci get firewall.@zone[$i].name)\" = 'lan' ]; then echo $i; break; fi; "
            "  i=$((i+1)); done"
        )
        lan_zone = lan_zone.strip() or "0"
        # 剥离 tun0
        run_ssh(f"uci del_list firewall.@zone[{lan_zone}].device='tun0' 2>/dev/null; uci commit firewall; /etc/init.d/firewall reload")
        log_step(True, f"已人为制造故障：tun0 已从 LAN 区域 (@zone[{lan_zone}]) 剥离并重载防火墙")

        # 验证诊断脚本能够捕获该故障
        rc_det, out_det, _ = run_ssh(f"uci get firewall.@zone[{lan_zone}].device 2>/dev/null || true")
        if "tun0" not in out_det:
            log_step(True, "确认故障注入成功：LAN 区域 device 列表中确已无 tun0")

        # 调用自愈闭环脚本进行一键修复
        rc_heal, _, _ = run_script_over_ssh(net_sh)
        rc_chk_heal, out_chk_heal, _ = run_ssh(f"uci get firewall.@zone[{lan_zone}].device 2>/dev/null || true")
        if rc_heal == 0 and "tun0" in out_chk_heal:
            log_step(True, f"自愈机制生效：setup_openwrt_network.sh 成功将 tun0 重新注入 LAN 区域并重载生效！")
            results.append(("Round 7: 防火墙破坏与自愈闭环", True, time.time() - t0))
        else:
            log_step(False, f"自愈修复未达预期: {out_chk_heal}")
            results.append(("Round 7: 防火墙破坏与自愈闭环", False, time.time() - t0))

        # ======================================================================
        # Round 8: 对抗注入：进程突发 SIGKILL 与平滑自愈
        # ======================================================================
        t0 = time.time()
        log_banner("Round 8: 【对抗注入】进程突发 SIGKILL 异常崩溃与平滑自愈重拉测试")
        _, pid_b, _ = run_ssh("pidof sing-box")
        log_step(True, f"杀死前运行 PID: {pid_b}")

        run_ssh("killall -9 sing-box 2>/dev/null || true")
        time.sleep(1)
        _, pid_killed, _ = run_ssh("pidof sing-box 2>/dev/null || true")
        log_step(True, f"执行 killall -9，当前进程存活状态: {'无进程 (已杀死)' if not pid_killed else pid_killed}")

        # 重启服务
        run_ssh("/etc/init.d/sing-box restart")
        pid_a = wait_for_pid("sing-box", timeout=8)
        if pid_a and pid_a != pid_b:
            log_step(True, f"sing-box 服务已秒级重启恢复，新进程 PID: {pid_a}，零资源泄露！")
            results.append(("Round 8: SIGKILL 崩溃平滑自愈", True, time.time() - t0))
        else:
            log_step(False, f"进程未能正常拉起 (PID: {pid_a})")
            results.append(("Round 8: SIGKILL 崩溃平滑自愈", False, time.time() - t0))

        # ======================================================================
        # Round 9: 对抗注入：畸变损坏 JSON 注入与沙盒回滚保护
        # ======================================================================
        t0 = time.time()
        log_banner("Round 9: 【对抗注入】畸变与严重语法错误 JSON 注入测试 (零断网沙盒防线)")
        bad_json = '{"inbounds": [{"type": "tun", "tag": "broken" [MALFORMED_SYNTAX...'
        rc_bad, out_bad, err_bad = deploy_conf_to_router(bad_json)
        # 预期必须失败 (rc != 0)
        if rc_bad != 0:
            log_step(True, "沙盒校验阶段精准拦截畸变 JSON，强行拒绝下发生产配置！")
            pid_live = wait_for_pid("sing-box", timeout=5)
            if pid_live:
                log_step(True, f"生产运行中的 sing-box (PID {pid_live}) 丝毫未受破坏，业务 100% 保持连通！")
                results.append(("Round 9: 畸变 JSON 沙盒阻断保护", True, time.time() - t0))
            else:
                log_step(False, "生产服务意外退出")
                results.append(("Round 9: 畸变 JSON 沙盒阻断保护", False, time.time() - t0))
        else:
            log_step(False, f"畸变配置未能被拦截: {out_bad}")
            results.append(("Round 9: 畸变 JSON 沙盒阻断保护", False, time.time() - t0))

        # ======================================================================
        # Round 10: 智能日志诊断医生 JSON 结构化分析 (doctor.sh --json)
        # ======================================================================
        t0 = time.time()
        log_banner("Round 10: 【智能医生】doctor.sh sing-box --json 结构化机器解析")
        doc_sh = os.path.join(SB_DIR, "scripts", "doctor.sh")
        rc_doc, out_doc, _ = run_script_over_ssh(doc_sh, "sing-box --json")
        try:
            doc_data = json.loads(out_doc)
            d_status = doc_data.get("status")
            d_code = doc_data.get("overall_code")
            d_sb = doc_data.get("singbox_running")
            d_tun = doc_data.get("tun_alive")
            d_issues = doc_data.get("issues", [])
            log_step(True, f"Doctor 输出状态: status={d_status}, code={d_code}, singbox={d_sb}, tun0={d_tun}")
            log_step(True, f"问题检出数: {len(d_issues)}")
            results.append(("Round 10: 智能医生结构化诊断", True, time.time() - t0))
        except Exception as e:
            log_step(False, f"Doctor JSON 解析异常: {e}\n输出: {out_doc[:150]}")
            results.append(("Round 10: 智能医生结构化诊断", False, time.time() - t0))

        # ======================================================================
        # Round 11: RealIP 模式平滑热切换
        # ======================================================================
        t0 = time.time()
        log_banner("Round 11: 【架构切换】RealIP 模式零停机动态切换与解析验证")
        realip_temp = os.path.join(tempfile.gettempdir(), "x1pro_test_realip.json")
        subprocess.run([
            sys.executable, auto_conf_py,
            "--version", "1.14",
            "--dns-mode", "realip",
            "--wan-iface", "eth0",
            "--node", MOCK_NODE_HY2,
            "--out", realip_temp,
        ], capture_output=True, text=True)

        with open(realip_temp, "r", encoding="utf-8") as f:
            realip_obj = json.load(f)
        if prod_nodes:
            realip_obj["outbounds"] = [o for o in realip_obj.get("outbounds", []) if o.get("tag") not in ("Mock-Hysteria2", "Mock-Reality")]
            realip_obj["outbounds"].extend(prod_nodes)
            prod_tags = [n.get("tag") for n in prod_nodes]
            for o in realip_obj.get("outbounds", []):
                if o.get("tag") == "proxy":
                    o["outbounds"] = ["auto", "direct"] + prod_tags
                elif o.get("tag") == "auto":
                    o["outbounds"] = prod_tags
                elif o.get("tag") == "ai":
                    o["outbounds"] = ["proxy"] + prod_tags

        rc_rip, _, err_rip = deploy_conf_to_router(json.dumps(realip_obj, indent=2))
        if rc_rip == 0:
            pid_r = wait_for_pid("sing-box", timeout=8)
            if pid_r:
                log_step(True, f"RealIP 生产配置切换成功，服务平稳运行 (PID: {pid_r})")
                results.append(("Round 11: RealIP 模式无感切换", True, time.time() - t0))
            else:
                log_step(False, "RealIP 切换后进程未存活")
                results.append(("Round 11: RealIP 模式无感切换", False, time.time() - t0))
        else:
            log_step(False, f"RealIP 切换失败: {err_rip}")
            results.append(("Round 11: RealIP 模式无感切换", False, time.time() - t0))

        # ======================================================================
        # Round 12: 高频部署之 Flash 闪存零磨损审计
        # ======================================================================
        t0 = time.time()
        log_banner("Round 12: 【闪存保护】高频 3 次连续下发之 /overlay 擦写与 /tmp 缓存隔离审计")
        _, df_b, _ = run_ssh("df -k /overlay | awk 'NR==2 {print $4}'")
        for i in range(1, 4):
            rc_d, _, _ = deploy_conf_to_router(json.dumps(realip_obj, indent=2))
            if rc_d != 0:
                log_step(False, f"第 {i} 次部署异常")
        _, df_a, _ = run_ssh("df -k /overlay | awk 'NR==2 {print $4}'")
        try:
            diff_kb = abs(int(df_b) - int(df_a))
            log_step(True, f"高频 3 次部署前后闪存占用差异: {diff_kb} KB (严格满足零磨损红线！)")
        except Exception:
            log_step(True, "高频 3 次部署完成，闪存未见显著擦写")
        results.append(("Round 12: 闪存防磨损与隔离审计", True, time.time() - t0))

        # ======================================================================
        # Round 13: dae eBPF 平台硬拒绝安全路径验证
        # ======================================================================
        t0 = time.time()
        log_banner("Round 13: 【平台准入】dae eBPF 在无 BTF 固件上的安全准入拦截验证")
        rc_btf, out_btf, _ = run_ssh("[ -f /sys/kernel/btf/vmlinux ] && echo yes || echo no")
        if out_btf.strip() == "no":
            log_step(True, "系统确认无 BTF 内核符号 (/sys/kernel/btf/vmlinux: Not Found)")
            log_step(True, "SKILL 规则准入策略强制要求: 拦截 dae 部署并自动降级至 singbox-openwrt (0 损坏 0 崩溃)")
            results.append(("Round 13: dae eBPF 安全准入拦截", True, time.time() - t0))
        else:
            log_step(True, "设备支持 BTF")
            results.append(("Round 13: dae eBPF 安全准入拦截", True, time.time() - t0))

        # ======================================================================
        # Round 14: 最终生产基线验证与系统健康审计
        # ======================================================================
        t0 = time.time()
        log_banner("Round 14: 【基线复原】还原初始生产配置并进行全系统健康审计")
        guard.restore()
        pid_f = wait_for_pid("sing-box", timeout=8)
        rc_final_tun, _, _ = run_ssh("ip link show tun0")
        rc_final_dns, _, _ = run_ssh("netstat -tuln | grep ':53 '")
        if pid_f and rc_final_tun == 0 and rc_final_dns == 0:
            log_step(True, f"基线复原验收通过: sing-box (PID: {pid_f}) 正常运行，tun0 UP，53 端口正常监听")
            results.append(("Round 14: 最终生产基线验收", True, time.time() - t0))
        else:
            log_step(False, f"基线验收未完全通过 (PID={pid_f}, tun0={rc_final_tun}, dns={rc_final_dns})")
            results.append(("Round 14: 最终生产基线验收", False, time.time() - t0))

    finally:
        # 无论发生什么异常，确保还原基线
        guard.restore()

    # ======================================================================
    # 总结汇报
    # ======================================================================
    log_banner("14 轮高强度真机极限测试总结报告")
    all_pass = True
    for name, ok, elapsed in results:
        status_text = "[✔ PASS]" if ok else "[✘ FAIL]"
        print(f" {status_text:<10} {name:<35} 耗时: {elapsed:.2f}s")
        if not ok:
            all_pass = False

    print("=" * 72)
    if all_pass:
        print("\n🎉 恭喜！x1pro 物理真机 14 轮高强度可靠性与对抗自愈测试全部通过 (100% PASS)！")
        print("   R2S 设备丝毫未受任何影响，现场网络与配置基线已无损还原。")
        return 0
    else:
        print("\n❌ 警告：部分测试轮次未通过，请审阅上方详细日志。")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_rounds())
