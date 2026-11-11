#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae 节点与完整配置生成器 (支持输出 node 语法块，或注入 openwrt.dae 模板生成完整配置并自动静态审计)
自包含：本技能自带 sub_parser.py / parse_node.py / check_dae_syntax.py。
"""

import ipaddress
import os
import re
import sys
import tempfile

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "assets", "templates", "openwrt.dae"))
CANDIDATES = [
    SCRIPT_DIR,
    os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "singbox-openwrt", "scripts")),
]

SUB_PARSER_DIR = next((p for p in CANDIDATES if os.path.isfile(os.path.join(p, "sub_parser.py"))), None)
if SUB_PARSER_DIR is None:
    print("[-] 找不到 sub_parser.py！", file=sys.stderr)
    sys.exit(1)

if SUB_PARSER_DIR not in sys.path:
    sys.path.insert(0, SUB_PARSER_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from sub_parser import parse_source, to_dae_nodes
from check_dae_syntax import check_dae_syntax


def build_full_dae_config(nodes, lan_iface="br-lan", wan_iface="auto", topology="main", main_router_ip=None, ram_mb=None, template_path=None):
    """读取 openwrt.dae 基准模板，注入清洗后的 node 块、接口与旁路由主网关直连规则，返回完整配置文本。"""
    tpl_file = template_path or TEMPLATE_PATH
    if not os.path.isfile(tpl_file):
        raise FileNotFoundError(f"找不到 dae 模板文件: {tpl_file}")
    with open(tpl_file, "r", encoding="utf-8-sig") as f:
        tpl_text = f.read()

    node_block = to_dae_nodes(nodes)
    # 替换模板中的 node { ... } 块（锚定行首闭括号，防止注释或密码中的 } 提前截断）
    merged = re.sub(r"(?ms)^node\s*\{.*?^\}", lambda _: node_block, tpl_text, count=1)
    for _if_label, _if_val in (("lan_interface", lan_iface), ("wan_interface", wan_iface)):
        if _if_val is not None:
            _if_s = str(_if_val).strip()
            if not _if_s or _if_s.startswith("-") or not re.match(r"^[a-zA-Z0-9_.\-@:,]+$", _if_s):
                raise ValueError(f"非法的网卡接口名 ({_if_label}={_if_val!r})")
    if lan_iface and lan_iface != "br-lan":
        merged = re.sub(r"(?m)^(\s*lan_interface:\s*)\S+", lambda m: f"{m.group(1)}{lan_iface.strip()}", merged)
    if wan_iface and wan_iface != "auto":
        merged = re.sub(r"(?m)^(\s*wan_interface:\s*)\S+", lambda m: f"{m.group(1)}{wan_iface.strip()}", merged)
    if topology == "bypass":
        if not main_router_ip:
            print("[!] 提示: 旁路由模式 (--topology bypass) 未指定 --main-router-ip，建议指定主路由 IP 以配置直接放行规则。", file=sys.stderr)
        else:
            raw_gw = str(main_router_ip).strip()
            try:
                gw_if = ipaddress.ip_interface(raw_gw)
                gw_ip = str(gw_if.ip) if "/" not in raw_gw else str(gw_if)
            except ValueError as e:
                raise ValueError(f"非法的旁路由主网关 IP (--main-router-ip={main_router_ip!r}): {e}")
            gw_expr = f"'{gw_ip}'" if (":" in gw_ip or "/" in gw_ip) else gw_ip
            merged = re.sub(
                r"(?m)^(\s*pname\([^)]*dnsmasq[^)]*\)[^\n]*->\s*must_direct\s*)$",
                lambda m: f"{m.group(1)}\n    dip({gw_expr}) -> direct",
                merged,
                count=1,
            )
    if ram_mb is not None:
        if isinstance(ram_mb, bool) or int(ram_mb) <= 0:
            raise ValueError(f"--ram-mb 必须为正整数 (> 0)，当前值: {ram_mb!r}")
        r_mb = int(ram_mb)
        map_sz = 32768 if r_mb < 256 else (65536 if r_mb < 512 else 131072)
        merged = re.sub(
            r"(?m)^(\s*bpf_conn_state_map_size:\s*)\d+",
            lambda m: f"{m.group(1)}{map_sz}",
            merged,
        )
    return merged


def main():
    if len(sys.argv) < 2:
        print("用法: python sub_to_dae.py <机场订阅URL / Base64文件 / Clash配置> [--max 15] [--include 正则] [--full] [-o /tmp/config.dae]")
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description="dae 订阅转换与完整配置生成工具")
    parser.add_argument("source", help="订阅来源 (URL/文件/Base64/单节点URI)")
    parser.add_argument("--max", type=int, default=15, help="保留最大节点数 (默认 15)")
    parser.add_argument("--include", help="包含节点匹配正则")
    parser.add_argument("--exclude", help="排除节点匹配正则")
    parser.add_argument("--full", action="store_true", help="注入 openwrt.dae 模板生成完整配置文件并执行内置 5 条铁律静态审计")
    parser.add_argument("--lan-iface", default="br-lan", help="完整配置模式下的局域网接口 (默认: br-lan)")
    parser.add_argument("--wan-iface", default="auto", help="完整配置模式下的外网接口 (默认: auto)")
    parser.add_argument("--topology", choices=["main", "bypass"], default="main", help="网络拓扑模式 (默认: main，旁路由请指定 bypass)")
    parser.add_argument("--main-router-ip", default=None, help="旁路由模式下的主路由 IP (如 192.168.1.1)")
    parser.add_argument("--ram-mb", type=int, default=None, help="目标路由器物理内存 MB (低于 512MB 时自动调小 bpf_conn_state_map_size 防 OOM)")
    parser.add_argument("-o", "--out", help="输出文件路径 (不指定则输出到标准输出)")

    args = parser.parse_args()

    try:
        nodes = parse_source(args.source, include=args.include, exclude=args.exclude, max_nodes=args.max)
    except Exception as e:
        print(f"[-] 解析订阅失败: {e}", file=sys.stderr)
        sys.exit(1)
    if not nodes:
        print("[-] 未能解析出有效节点", file=sys.stderr)
        sys.exit(1)

    if args.full:
        try:
            out_text = build_full_dae_config(
                nodes,
                lan_iface=args.lan_iface,
                wan_iface=args.wan_iface,
                topology=args.topology,
                main_router_ip=args.main_router_ip,
                ram_mb=args.ram_mb,
            )
        except ValueError as e:
            print(f"[FATAL] 参数校验失败: {e}", file=sys.stderr)
            sys.exit(1)
        with tempfile.NamedTemporaryFile("w", suffix=".dae", delete=False, encoding="utf-8") as tf:
            tf.write(out_text)
            tmp_dae = tf.name
        try:
            errors, warnings = check_dae_syntax(tmp_dae)
        finally:
            if os.path.exists(tmp_dae):
                os.remove(tmp_dae)
        for w in warnings:
            print(f"[!] {w}", file=sys.stderr)
        if errors:
            print(f"[FATAL] 生成的 dae 配置未通过静态审计（共 {len(errors)} 个阻断错误）：", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            sys.exit(3)
    else:
        out_text = to_dae_nodes(nodes)

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(out_text if out_text.endswith("\n") else out_text + "\n")
        print(f"[+] 成功转换 {len(nodes)} 个节点并写入: {args.out}", file=sys.stderr)
    else:
        print(out_text)
        print(f"[+] 成功转换 {len(nodes)} 个节点到 dae 语法格式", file=sys.stderr)


if __name__ == "__main__":
    main()
