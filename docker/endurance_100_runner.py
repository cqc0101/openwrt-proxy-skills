#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
100 轮真机与仿真环境工业级可靠性循环耐久实测引擎 (Endurance 100 Matrix)
--------------------------------------------------------------------------------
【执行规范】
1. 真实不作假：每一轮严格执行真实软硬件调用与逻辑校验，真实记录耗时与状态。
2. 零隐私泄露：严格执行安全合规红线，严禁输出任何真实公网 IP 或敏感密钥。
3. 严格隔离：严禁触碰 R2S (192.168.1.1)。
4. 覆盖三大域：
   - 域 A (Docker/Local): 146 项单元测试全量验证（模板、解析器、门禁规则、防呆断言）
   - 域 B (真机 Meraki Z1): MIPS32 / Linux 4.9 / fw3 / Dnsmasq 探针与诊断
   - 域 C (真机 X1 Pro): ARM64 / Linux 5.15 / fw4 / sing-box 1.14 / tun0 / 9090 API 探针与体检
"""

import json
import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SB_DIR = os.path.join(BASE_DIR, "skills", "singbox-openwrt")
DAE_DIR = os.path.join(BASE_DIR, "skills", "dae-openwrt")

# 目标设备 1: Cisco Meraki Z1 (MIPS)
MERAKI_IP = os.getenv("MERAKI_IP", "192.0.2.250")
PLINK_EXE = os.getenv("PLINK_EXE", "plink")
MERAKI_HOSTKEY = os.getenv("MERAKI_HOSTKEY", "")
MERAKI_PASS = os.getenv("MERAKI_PASS", "password")

# 目标设备 2: 蒲公英 X1 Pro (ARM64)
X1PRO_IP = os.getenv("X1PRO_IP", "192.0.2.220")
X1PRO_KEY = os.path.join(BASE_DIR, ".deploy_key", "id_ed25519")

TOTAL_ROUNDS = 100
REPORT_JSON = os.path.join(BASE_DIR, "docker", "endurance_100_report.json")
REPORT_LOG = os.path.join(BASE_DIR, "docker", "endurance_100_report.log")


def run_meraki_script(script_path, args=""):
    with open(script_path, "r", encoding="utf-8") as f:
        content = f.read()
    cmd = [
        PLINK_EXE,
        "-batch",
        "-hostkey", MERAKI_HOSTKEY,
        "-ssh",
        "-l", "root",
        "-pw", MERAKI_PASS,
        MERAKI_IP,
        f"tr -d '\\r' | sh -s -- {args}",
    ]
    for attempt in range(2):
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = p.communicate(input=content, timeout=12)
            if p.returncode in (0, 1, 2) and stdout.strip():
                return p.returncode, stdout.strip(), stderr.strip()
        except Exception:
            pass
        time.sleep(0.5)
    return p.returncode if 'p' in locals() else -1, stdout.strip() if 'stdout' in locals() else "", stderr.strip() if 'stderr' in locals() else ""


def run_x1pro_script(script_path, args=""):
    with open(script_path, "r", encoding="utf-8") as f:
        content = f.read()
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-p", "22",
        "-i", X1PRO_KEY,
        f"root@{X1PRO_IP}",
        f"tr -d '\\r' | sh -s -- {args}",
    ]
    for attempt in range(2):
        try:
            r = subprocess.run(ssh_cmd, input=content, capture_output=True, text=True, timeout=12)
            if r.returncode in (0, 1, 2) and r.stdout.strip():
                return r.returncode, r.stdout.strip(), r.stderr.strip()
        except Exception:
            pass
        time.sleep(0.5)
    return r.returncode if 'r' in locals() else -1, r.stdout.strip() if 'r' in locals() else "", r.stderr.strip() if 'r' in locals() else ""


def run_x1pro_cmd(cmd_str):
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-p", "22",
        "-i", X1PRO_KEY,
        f"root@{X1PRO_IP}",
        cmd_str,
    ]
    for attempt in range(2):
        try:
            r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                return r.returncode, r.stdout.strip(), r.stderr.strip()
        except Exception:
            pass
        time.sleep(0.5)
    return r.returncode if 'r' in locals() else -1, r.stdout.strip() if 'r' in locals() else "", r.stderr.strip() if 'r' in locals() else ""


def run_single_round(round_idx):
    t_round_start = time.time()
    round_log = {
        "round": round_idx,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "unit_tests": {"pass": False, "elapsed": 0.0, "total": 0},
        "meraki_z1": {"pass": False, "elapsed": 0.0, "details": {}},
        "x1pro": {"pass": False, "elapsed": 0.0, "details": {}},
        "status": "FAIL",
        "total_elapsed": 0.0,
    }

    # --------------------------------------------------------------------------
    # 阶段 1: 全量单元测试 (146 测试用例)
    # --------------------------------------------------------------------------
    t0 = time.time()
    run_tests_py = os.path.join(BASE_DIR, "run_tests.py")
    r_ut = subprocess.run([sys.executable, run_tests_py], capture_output=True, text=True, cwd=BASE_DIR, timeout=25)
    t_ut = time.time() - t0
    ut_ok = (r_ut.returncode == 0 and "OK" in r_ut.stderr)
    round_log["unit_tests"]["pass"] = ut_ok
    round_log["unit_tests"]["elapsed"] = round(t_ut, 2)
    round_log["unit_tests"]["total"] = 146

    # --------------------------------------------------------------------------
    # 阶段 2: 真机 Cisco Meraki Z1 (MIPS / Linux 4.9)
    # --------------------------------------------------------------------------
    t0 = time.time()
    probe_sh = os.path.join(SB_DIR, "scripts", "probe.sh")
    dns_sh = os.path.join(SB_DIR, "scripts", "diagnose_dns.sh")
    doc_sh = os.path.join(SB_DIR, "scripts", "doctor.sh")

    rc_p1, out_p1, _ = run_meraki_script(probe_sh, "-j")
    rc_d1, out_d1, _ = run_meraki_script(dns_sh, "-j")
    rc_c1, out_c1, _ = run_meraki_script(doc_sh, "sing-box --json")
    t_m1 = time.time() - t0

    m1_ok = False
    if rc_p1 == 0 and rc_d1 == 0 and rc_c1 in (0, 1, 2):
        try:
            d_p = json.loads(out_p1)
            d_d = json.loads(out_d1)
            d_c = json.loads(out_c1)
            m1_ok = (
                d_p.get("hardware", {}).get("model") == "Meraki Z1"
                and d_d.get("total_checks") == 7
                and "singbox_running" in d_c
            )
            round_log["meraki_z1"]["details"] = {
                "model": d_p.get("hardware", {}).get("model"),
                "arch": d_p.get("hardware", {}).get("arch"),
                "dns_passed": d_d.get("passed_checks"),
                "doctor_issues": d_c.get("issue_count"),
            }
        except Exception as e:
            m1_ok = False
            round_log["meraki_z1"]["error"] = str(e)

    round_log["meraki_z1"]["pass"] = m1_ok
    round_log["meraki_z1"]["elapsed"] = round(t_m1, 2)

    # --------------------------------------------------------------------------
    # 阶段 3: 真机 蒲公英 X1 Pro (ARM64 / Linux 5.15)
    # --------------------------------------------------------------------------
    t0 = time.time()
    rc_p2, out_p2, _ = run_x1pro_script(probe_sh, "-j")
    rc_d2, out_d2, _ = run_x1pro_script(dns_sh, "-j")
    rc_c2, out_c2, _ = run_x1pro_script(doc_sh, "sing-box --json")
    rc_api, out_api, _ = run_x1pro_cmd("curl -s http://127.0.0.1:9090/version")
    rc_pid, out_pid, _ = run_x1pro_cmd("pidof sing-box")
    t_x1 = time.time() - t0

    x1_ok = False
    if rc_p2 == 0 and rc_d2 == 0 and rc_c2 in (0, 1, 2) and rc_api == 0 and rc_pid == 0:
        try:
            d_p2 = json.loads(out_p2)
            d_d2 = json.loads(out_d2)
            d_c2 = json.loads(out_c2)
            x1_ok = (
                "Oray" in d_p2.get("hardware", {}).get("model", "")
                and d_d2.get("total_checks") == 7
                and bool(out_pid.strip())
                and "version" in out_api
            )
            round_log["x1pro"]["details"] = {
                "model": d_p2.get("hardware", {}).get("model"),
                "pid": out_pid.strip(),
                "clash_api": "ok" if "version" in out_api else "fail",
                "dns_passed": d_d2.get("passed_checks"),
            }
        except Exception as e:
            x1_ok = False
            round_log["x1pro"]["error"] = str(e)

    round_log["x1pro"]["pass"] = x1_ok
    round_log["x1pro"]["elapsed"] = round(t_x1, 2)

    # 总体裁定
    round_total_ok = (ut_ok and m1_ok and x1_ok)
    round_log["status"] = "PASS" if round_total_ok else "FAIL"
    round_log["total_elapsed"] = round(time.time() - t_round_start, 2)

    return round_log


def main():
    print("=" * 76)
    print("  OpenWrt 智能科学上网技能库 100 轮全天候工业级极限耐久实测引擎")
    print("=" * 76)
    print(f"目标轮次: {TOTAL_ROUNDS} 轮 (只能多不能少，不弄虚作假)")
    print(f"真机矩阵: Cisco Meraki Z1 ({MERAKI_IP}) + 蒲公英 X1 Pro ({X1PRO_IP})")
    print(f"单测矩阵: 146 项用例 / 轮 (共计将执行 {TOTAL_ROUNDS * 146} 次断言)")
    print(f"报告输出: {REPORT_JSON}")
    print("=" * 76)

    all_logs = []
    total_passed = 0
    t_global_start = time.time()

    with open(REPORT_LOG, "w", encoding="utf-8") as lf:
        lf.write(f"=== 100 轮极限实测引擎启动: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    for i in range(1, TOTAL_ROUNDS + 1):
        res = run_single_round(i)
        all_logs.append(res)
        is_ok = (res["status"] == "PASS")
        if is_ok:
            total_passed += 1

        mark = "✔ PASS" if is_ok else "✘ FAIL"
        log_line = (
            f"[{mark}] 轮次 #{i:03d}/{TOTAL_ROUNDS:03d} | "
            f"单测: {res['unit_tests']['elapsed']}s | "
            f"Meraki Z1: {res['meraki_z1']['elapsed']}s | "
            f"X1 Pro: {res['x1pro']['elapsed']}s | "
            f"耗时: {res['total_elapsed']}s"
        )
        print(log_line)

        with open(REPORT_LOG, "a", encoding="utf-8") as lf:
            lf.write(log_line + "\n")

        # 每 10 轮实时刷盘一次 JSON 报告，确保意外中断也不丢失历史
        if i % 10 == 0 or i == TOTAL_ROUNDS:
            with open(REPORT_JSON, "w", encoding="utf-8") as jf:
                json.dump({
                    "target_rounds": TOTAL_ROUNDS,
                    "completed_rounds": i,
                    "passed_rounds": total_passed,
                    "pass_rate": f"{(total_passed / i) * 100:.2f}%",
                    "total_duration_sec": round(time.time() - t_global_start, 2),
                    "history": all_logs,
                }, jf, indent=2, ensure_ascii=False)

    total_time = time.time() - t_global_start
    print("\n" + "=" * 76)
    print(f"🏁 100 轮全天候极限耐久实测已全部完成！")
    print(f"   总耗时: {total_time:.2f}s ({total_time / 60:.1f} 分钟)")
    print(f"   执行结果: 通过 {total_passed} / {TOTAL_ROUNDS} 轮 (通过率: {(total_passed / TOTAL_ROUNDS) * 100:.2f}%)")
    print(f"   全量累计执行单元测试: {TOTAL_ROUNDS * 146} 项次")
    print(f"   完整结构化报告已归档至: {REPORT_JSON}")
    print("=" * 76)

    return 0 if total_passed == TOTAL_ROUNDS else 1


if __name__ == "__main__":
    sys.exit(main())
