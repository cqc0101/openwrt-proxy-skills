#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae 节点与完整配置生成器 (支持输出 node 语法块，或注入 openwrt.dae 模板生成完整配置并自动静态审计)
自包含：本技能自带 sub_parser.py / parse_node.py / check_dae_syntax.py。
"""

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


def build_full_dae_config(nodes, lan_iface="br-lan", wan_iface="auto", template_path=None):
    """读取 openwrt.dae 基准模板，注入清洗后的 node 块与接口设置，返回完整配置文本。"""
    tpl_file = template_path or TEMPLATE_PATH
    if not os.path.isfile(tpl_file):
        raise FileNotFoundError(f"找不到 dae 模板文件: {tpl_file}")
    with open(tpl_file, "r", encoding="utf-8") as f:
        tpl_text = f.read()

    node_block = to_dae_nodes(nodes)
    # 替换模板中的 node { ... } 块
    merged = re.sub(r"(?m)^node\s*\{[^}]*\}", lambda _: node_block, tpl_text, count=1)
    if lan_iface and lan_iface != "br-lan":
        merged = re.sub(r"(?m)^(\s*lan_interface:\s*)\S+", f"\\g<1>{lan_iface}", merged)
    if wan_iface and wan_iface != "auto":
        merged = re.sub(r"(?m)^(\s*wan_interface:\s*)\S+", f"\\g<1>{wan_iface}", merged)
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
        out_text = build_full_dae_config(nodes, lan_iface=args.lan_iface, wan_iface=args.wan_iface)
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
