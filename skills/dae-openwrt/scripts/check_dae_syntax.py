#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae 配置文件 5 条铁律静态合规检测工具（启发式检查）
注意：本工具只做静态模式匹配，最终结论必须由远端 `dae validate <file>` 确认（注意：dae 不支持 -c 参数，直接传文件路径）。
"""

import sys
import os
import re

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _strip_comments(line: str) -> str:
    """感知单双引号边界剥离行首与行尾 # 注释，防止误截断节点 URI 中的 #fragment。"""
    s = line.strip()
    if s.startswith("#"):
        return ""
    in_single = False
    in_double = False
    out = []
    for ch in s:
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
        elif ch == "#" and not in_single and not in_double:
            break
        else:
            out.append(ch)
    return "".join(out).strip()


def check_dae_syntax(filepath):
    errors = []
    warnings = []

    with open(filepath, 'r', encoding='utf-8') as f:
        raw_lines = f.readlines()

    lines = [_strip_comments(l) for l in raw_lines]
    content = "\n".join(lines)

    # 1. 检查双引号 (单引号词法铁律；ext:"xxx" 除外)
    for idx, line in enumerate(lines, 1):
        if not line:
            continue
        matches = re.findall(r'([\w\'\-]+:\s*"[^"]*"|->\s*"[^"]*")', line)
        for m in matches:
            if not m.startswith('ext:'):
                errors.append(f"第 {idx} 行疑似违反单引号规范: {m}。建议统一使用单引号 '...'（ext:\"file.dat:tag\" 除外）。")

    # 2. 检查 lan_interface 与 wan_interface 绑定
    if "lan_interface" not in content:
        warnings.append("[网卡绑定提醒] global 块中未显式声明 'lan_interface'。软路由代理局域网流量建议绑定 'lan_interface: br-lan'。")
    if "wan_interface" not in content:
        warnings.append("[网卡绑定提醒] global 块中未声明 'wan_interface: auto'。")

    # 3. 检查 must_direct 防环（宿主机 DNS 组件保护）
    #    允许 pname(...) 与 -> must_direct 跨行书写或存在 && 条件
    has_dnsmasq_protect = re.search(r'pname\([^)]*dnsmasq[^)]*\)[^->\}]*->\s*must_direct', content, re.DOTALL)
    if not has_dnsmasq_protect:
        errors.append("[DNS 死循环高危] routing 规则中未发现针对 dnsmasq 的 'must_direct' 放行规则！"
                      "在 OpenWrt 上，宿主机 DNS 组件的 53 端口流量必须于规则顶部放行，否则极易形成 DNS 回环死锁。")

    # 4. 检查布尔取反 (!) 合并
    neg_rule_count = len(re.findall(r'(?m)^\s*!domain\(', content))
    if neg_rule_count > 1:
        warnings.append("[取反合并建议] 发现多条独立的 '!domain(...)' 规则。"
                        "在 dae 语义中，'既不属于 A 也不属于 B' 必须合并写在同一行内"
                        "（如 '!domain(geosite:a, geosite:b) -> proxy'），拆成两行会变成 OR 逻辑，大量流量被误送代理。")

    # 5. 检查 DNS 污染重查闭环
    if "ip(geoip:private)" in content:
        resp_blocks = re.findall(r'response\s*\{([^}]*)\}', content, flags=re.S)
        for block in resp_blocks:
            m_relookup = re.search(r'ip\(geoip:private\)[^->\n]*->\s*(?!accept\b|reject\b)\w+', block)
            if m_relookup:
                m_accept = re.search(r'upstream\([^)]*\)\s*->\s*accept', block)
                if not m_accept or m_accept.start() >= m_relookup.start():
                    errors.append("[DNS 投毒死循环高危] 配置了私网 IP 污染重查，但 response 块中缺少位于其前的"
                                  "可信上游白名单放行（'upstream(...) -> accept'），会导致无限递归重查！")
                    break

    return errors, warnings


def main():
    if len(sys.argv) < 2:
        print("用法: python check_dae_syntax.py <dae配置文件路径>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"错误: 文件不存在: {filepath}")
        sys.exit(1)

    print(f"[*] 正在审计 dae 配置文件: {filepath}")
    errors, warnings = check_dae_syntax(filepath)

    if errors:
        print(f"\n[!] 发现 {len(errors)} 个严重阻断问题:")
        for e in errors:
            print(f"  - [ERROR] {e}")

    if warnings:
        print(f"\n[!] 发现 {len(warnings)} 个优化建议:")
        for w in warnings:
            print(f"  - [WARN] {w}")

    if not errors and not warnings:
        print("\n[+] 静态启发式检查通过，未发现明显违规。")
    elif not errors:
        print("\n[+] 无致命问题，请评估上方建议。")
    else:
        print("\n[x] 检查未通过，请修复后重试。")
        sys.exit(1)

    print("[i] 提示：本工具仅做静态检查，部署前请务必以远端 'dae validate <file>' 的结论为准（dae 不接受 -c 参数）。")
    return 0


if __name__ == "__main__":
    main()
